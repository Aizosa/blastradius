"""Extended detectors — higher-coverage vectors surfaced by the threat catalog.

These are lower-frequency but genuinely dangerous auto-execution points that a
comprehensive scanner must not miss (git config command hijacks, gyp native
builds, IDE run configs, test-runner configs, package-index redirects).
"""
from __future__ import annotations

import os
import re
from typing import Iterator

from ..models import Finding
from . import FileIndex, Vector, build_finding, detector, find_line, snippet_of


def _git_config_files(idx: FileIndex) -> list[str]:
    return [r for r in idx.by_name("config", ".gitconfig") if r.startswith(".git") or r == ".gitconfig"]


@detector
def git_config_command_hijacks(idx: FileIndex) -> Iterator[Finding]:
    """credential.helper, aliases with '!', include/includeIf, fsmonitor, pager/editor."""
    checks = [
        (r"(?im)^\s*helper\s*=\s*(!.*|/.*|.*\.sh.*)$",
         Vector("git-credential-helper", "Git credential.helper runs a command", "git",
                "git fetch / push / clone (any auth operation)",
                "credential.helper set to a shell command executes on every authenticated git "
                "operation and can capture or exfiltrate credentials.",
                "Ensure credential.helper is a known helper (store/cache/manager), not a script.",
                "high")),
        (r"(?im)^\s*\w+\s*=\s*!.+$",
         Vector("git-alias-shell", "Git alias shells out", "git",
                "running the aliased git subcommand",
                "A git alias beginning with '!' runs an arbitrary shell command; a repo-local "
                "config can define one that looks like a normal git subcommand.",
                "Review alias.* entries with a leading '!'.",
                "high")),
        (r"(?im)^\s*(path|hooksPath)\s*=\s*.+$|^\s*\[includeIf",
         Vector("git-config-include", "Git config includes external config", "git",
                "any git command",
                "include/includeIf pulls in another config file that can set hooksPath, aliases "
                "or command hijacks — indirection that hides the real setting.",
                "Trace every include/includeIf path and audit the included file.",
                "medium")),
        (r"(?im)^\s*fsmonitor\s*=\s*(?!true|false).+$",
         Vector("git-fsmonitor", "core.fsmonitor runs on git status", "git",
                "git status / most git commands",
                "core.fsmonitor set to a program runs it on routine git operations.",
                "Verify core.fsmonitor points to a trusted binary.",
                "high")),
        (r"(?im)^\s*sshCommand\s*=\s*.+$",
         Vector("git-ssh-command", "core.sshCommand overrides the ssh binary", "git",
                "git fetch / push / clone over ssh",
                "core.sshCommand replaces the ssh command git uses; a repo-local config can "
                "point it at an arbitrary script that runs on every ssh transport operation.",
                "Ensure core.sshCommand is unset or a trusted ssh invocation.",
                "high")),
        (r"(?im)^\s*(pager|editor)\s*=\s*.*(?:\||;|&|\bsh\b|\bbash\b|curl|wget).*$",
         Vector("git-pager-editor", "core.pager / editor runs a shell pipeline", "git",
                "git log / diff / commit (pager or editor invocation)",
                "A pager or editor configured as a shell pipeline executes when git pages output "
                "or opens an editor.",
                "Set core.pager/editor to a plain binary.",
                "medium")),
    ]
    for rel in _git_config_files(idx):
        code = idx.read(rel)
        for pat, vec in checks:
            m = re.search(pat, code)
            if m:
                yield build_finding(vec, rel, code, snippet=m.group(0).strip(),
                                    line=find_line(code, m.group(0)), scan_text=m.group(0))


@detector
def gitattributes_drivers(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "gitattributes-driver", "Git diff/merge driver runs on diff/merge", "git",
        "git diff / log / merge on matching paths",
        "A custom diff= (textconv) or merge= driver in .gitattributes runs the configured "
        "external command during ordinary diff/log/merge.",
        "Check .gitattributes for diff=/merge= and the git config defining the driver command.",
        "medium",
    )
    for rel in idx.by_name(".gitattributes"):
        code = idx.read(rel)
        m = re.search(r"(?im)\b(diff|merge)=(\S+)", code)
        if m:
            yield build_finding(vec, rel, code, snippet=m.group(0),
                                line=find_line(code, m.group(0)))


@detector
def node_gyp_build(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "node-gyp-build", "Native build (binding.gyp) runs during install", "node",
        "npm install of a package with native addons",
        "binding.gyp drives node-gyp to compile native code, executing gyp actions/rules and a "
        "build toolchain during install — arbitrary command execution.",
        "Audit binding.gyp 'actions'/'rules' commands; prefer prebuilt binaries you trust.",
        "medium",
    )
    for rel in idx.by_name("binding.gyp"):
        code = idx.read(rel)
        yield build_finding(vec, rel, code, snippet=snippet_of(code, 8),
                            scan_text=code if re.search(r"(?i)(action|rule|'action'|command)", code) else "")


@detector
def vscode_launch(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "vscode-launch", "VSCode launch.json runs a task/program on debug", "editor",
        "starting a debug session (F5) in VS Code",
        "launch.json preLaunchTask and program/runtimeExecutable run when a debug session "
        "starts; a repo can point them at a malicious command.",
        "Review preLaunchTask and program/runtimeExecutable entries.",
        "low",
    )
    for rel in idx.by_name("launch.json"):
        if os.path.dirname(rel).split(os.sep)[-1] != ".vscode":
            continue
        code = idx.read(rel)
        if re.search(r'"(preLaunchTask|runtimeExecutable|program)"\s*:', code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 10), scan_text=code)


@detector
def jetbrains_run_configs(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "jetbrains-runconfig", "JetBrains run config / external tool runs command", "editor",
        "opening the project or running the configuration in a JetBrains IDE",
        ".idea run configurations, external tools and before-launch steps can execute shell "
        "commands, some on project open.",
        "Audit .idea/runConfigurations/*.xml and workspace.xml for shell/exec entries.",
        "medium",
    )
    rels = [r for r in idx.under(".idea") if r.endswith(".xml")]
    for rel in rels:
        code = idx.read(rel)
        if re.search(r"(?i)(ShConfigurationType|option name=\"SCRIPT_TEXT\"|<EXTENSION|"
                     r"ExternalTool|command=\"|PROGRAM_PARAMS|runic|BUILD_SCRIPT)", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)


@detector
def python_test_runner_configs(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "python-runner-config", "tox / nox config runs shell commands", "python",
        "running tox or nox in the project",
        "tox.ini [testenv] commands and noxfile.py sessions run arbitrary shell/Python when "
        "the runner is invoked.",
        "Review commands in tox.ini and sessions in noxfile.py.",
        "low",
    )
    for rel in idx.by_name("tox.ini"):
        code = idx.read(rel)
        if re.search(r"(?im)^\s*commands\s*=", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)
    for rel in idx.by_name("noxfile.py"):
        code = idx.read(rel)
        if re.search(r"(?i)session\.run|subprocess|os\.system", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)


@detector
def package_index_redirect(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "package-index-redirect", "Package index / registry redirected", "supply-chain",
        "installing dependencies (pip / cargo / gem / etc.)",
        "pip.conf/pip.ini, cargo config or bundler config pointing index-url/registry at a "
        "non-official host silently sources packages from an attacker-controlled mirror.",
        "Confirm index-url/registry hosts are the official ones.",
        "medium",
    )
    for rel in idx.by_name("pip.conf", "pip.ini"):
        code = idx.read(rel)
        m = re.search(r"(?im)^\s*(index-url|extra-index-url)\s*=\s*(\S+)", code)
        if m and "pypi.org" not in m.group(2):
            yield build_finding(vec, rel, code, snippet=m.group(0), line=find_line(code, m.group(0)))
    for rel in idx.by_suffix(os.path.join(".cargo", "config.toml"), os.path.join(".cargo", "config")):
        code = idx.read(rel)
        if re.search(r"(?im)\[source\.|replace-with", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8))
