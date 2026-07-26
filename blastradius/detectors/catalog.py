"""Catalog detectors — high-value vectors surfaced by the threat-catalog critic.

These close the gaps the completeness pass flagged: git submodule transport RCE,
config-as-code (JS toolchain, Ruby/PHP/Go build files), SSH config command exec,
debugger init files, and Bun/Deno runtime hooks.
"""
from __future__ import annotations

import os
import re
from typing import Iterator

from ..models import Finding
from . import FileIndex, Vector, build_finding, detector, find_line, snippet_of


@detector
def git_submodule_transport(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "git-submodule-transport", "Submodule uses a command-executing transport", "git",
        "git submodule update / clone --recurse-submodules",
        "A .gitmodules url using the ext:: or fd:: transport runs an arbitrary command when "
        "the submodule is fetched — RCE from simply recursing submodules.",
        "Reject ext::/fd:: submodule URLs; fetch submodules only from trusted https/ssh hosts.",
        "high",
    )
    for rel in idx.by_name(".gitmodules"):
        code = idx.read(rel)
        m = re.search(r"(?im)url\s*=\s*((?:ext|fd)::\S+)", code)
        if m:
            yield build_finding(vec, rel, code, snippet=m.group(0).strip(),
                                line=find_line(code, m.group(0)), scan_text=m.group(1))


@detector
def js_toolchain_config_as_code(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "js-config-as-code", "JS toolchain config executes code", "node",
        "running the tool (vite/webpack/jest/eslint/babel/postcss/next…) or an IDE loading it",
        "*.config.js/.cjs/.mjs and .eslintrc.js etc. are executed as code when the tool runs; "
        "an agent running a build/lint/test triggers them, and they can spawn processes or fetch.",
        "Treat tooling configs as executable; review require()/import of remote or child_process use.",
        "low",
    )
    name_rx = re.compile(
        r"(?i)(?:^|/)("
        r"(?:vite|vitest|webpack|rollup|rspack|esbuild|next|nuxt|svelte|astro|remix|"
        r"jest|babel|postcss|tailwind|playwright|cypress|karma|gatsby|metro|"
        r"eslint|prettier|stylelint|commitlint|lint-staged|drizzle|prisma)\.config\.[cm]?[jt]s"
        r"|\.(?:eslintrc|prettierrc|babelrc|stylelintrc)\.[cm]?js)$"
    )
    risky_rx = re.compile(r"(?i)(child_process|execSync|spawnSync|require\(['\"]node:|"
                          r"\bfetch\(|https?://|\beval\(|process\.env\b.*(?:TOKEN|KEY|SECRET))")
    for rel in idx.rel_paths:
        if not name_rx.search(rel.replace(os.sep, "/")):
            continue
        code = idx.read(rel)
        if risky_rx.search(code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)


@detector
def bun_deno_runtime(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "bun-deno-runtime", "Bun/Deno runtime auto-loads code", "node",
        "bun install / bun run / deno task",
        "bunfig.toml `preload`, package.json `trustedDependencies` (re-enables Bun install "
        "scripts), and deno.json `tasks` run code automatically on install/run.",
        "Review bunfig preload, trustedDependencies, and deno.json tasks.",
        "medium",
    )
    for rel in idx.by_name("bunfig.toml"):
        code = idx.read(rel)
        if re.search(r"(?im)^\s*preload\s*=", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6), scan_text=code)
    for rel in idx.by_name("deno.json", "deno.jsonc"):
        code = idx.read(rel)
        if '"tasks"' in code:
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)


@detector
def composer_scripts(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "composer-scripts", "PHP Composer lifecycle script", "lang",
        "composer install / update",
        "composer.json scripts (post-install-cmd, post-update-cmd, post-autoload-dump) run "
        "shell/PHP automatically during dependency install.",
        "Install with --no-scripts; audit the scripts block.",
        "medium",
    )
    for rel in idx.by_name("composer.json"):
        code = idx.read(rel)
        m = re.search(r'"(post-install-cmd|post-update-cmd|post-autoload-dump|pre-install-cmd|'
                      r'post-root-package-install|post-create-project-cmd)"', code)
        if m:
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 10),
                                line=find_line(code, m.group(0)), scan_text=code)


@detector
def go_generate(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "go-generate", "go:generate directive runs a command", "lang",
        "running `go generate ./...`",
        "//go:generate lines run arbitrary commands when `go generate` is invoked; agents run "
        "it as a routine codegen step.",
        "Review every //go:generate command before running go generate.",
        "low",
    )
    for rel in idx.by_suffix(".go"):
        code = idx.read(rel)
        m = re.search(r"(?m)^//go:generate\s+(.+)$", code)
        if m:
            yield build_finding(vec, rel, code, snippet=m.group(0),
                                line=find_line(code, m.group(0)), scan_text=m.group(1))


@detector
def ssh_config_exec(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "ssh-config-exec", "SSH config runs a command", "shell",
        "any ssh/git-over-ssh connection using this config",
        "ProxyCommand / LocalCommand / Match exec in an SSH config execute a shell command on "
        "connect; a repo-supplied ssh config (or one an install step copies) yields execution.",
        "Never point ssh -F at a repo-provided config; review ProxyCommand/LocalCommand/Match exec.",
        "high",
    )
    for rel in idx.rel_paths:
        base = os.path.basename(rel).lower()
        low = rel.replace(os.sep, "/").lower()
        is_ssh_cfg = base == "ssh_config" or (base == "config" and "/.ssh/" in "/" + low)
        if not is_ssh_cfg:
            continue
        code = idx.read(rel)
        if re.search(r"(?im)^\s*(ProxyCommand|LocalCommand|Match\s+exec)\b", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8), scan_text=code)


@detector
def dotenv_code_loader(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "dotenv-code-loader", "Dotenv file sets a code-loading env var", "shell",
        "any tool that auto-loads .env (dotenv, direnv, docker compose, an agent shell)",
        "A .env file that sets NODE_OPTIONS=--require, BASH_ENV, LD_PRELOAD, PYTHONSTARTUP or "
        "GIT_SSH_COMMAND turns 'loading environment variables' into arbitrary code execution.",
        "Never auto-load untrusted .env files; strip code-loading vars before sourcing.",
        "medium",
    )
    loader_rx = re.compile(
        r"(?im)^\s*(?:export\s+)?(NODE_OPTIONS|BASH_ENV|ENV|LD_PRELOAD|LD_LIBRARY_PATH|"
        r"PYTHONSTARTUP|GIT_SSH_COMMAND|RUBYOPT|PERL5OPT|DYLD_INSERT_LIBRARIES)\s*=")
    for rel in idx.rel_paths:
        base = os.path.basename(rel)
        if base != ".env" and not base.startswith(".env."):
            continue
        code = idx.read(rel)
        m = loader_rx.search(code)
        if m:
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8, around=m.group(0)),
                                line=find_line(code, m.group(0)), scan_text=code)


@detector
def debugger_init(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "debugger-init", "Debugger auto-load script", "editor",
        "starting gdb/lldb in the project directory",
        ".gdbinit / .lldbinit in the working directory are auto-sourced by the debugger and can "
        "run shell (via `!`, `shell`, or python) on startup.",
        "Set safe-path / disable local init (gdb: add-auto-load-safe-path); review the file.",
        "medium",
    )
    for rel in idx.by_name(".gdbinit", ".lldbinit"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6), scan_text=code)
