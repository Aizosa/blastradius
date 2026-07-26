"""Built-in detectors for BlastRadius.

Each detector locates one family of auto-execution points and yields Findings.
Content-based severity is handled centrally by ``build_finding`` (amplifiers),
so detectors focus on *locating* the trigger and passing the relevant code.
"""
from __future__ import annotations

import json
import os
import re
import stat
from typing import Iterator

from ..models import Finding
from . import FileIndex, Vector, build_finding, detector, find_line, snippet_of

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_LIFECYCLE_KEYS = (
    "preinstall", "install", "postinstall", "preuninstall", "postuninstall",
    "prepare", "prepublish", "prepublishOnly", "prepack", "postpack",
    "preprepare", "postprepare", "dependencies",
)


def _load_jsonc(text: str):
    """Best-effort parse of JSON that may contain // and /* */ comments + trailing commas."""
    if not text.strip():
        return None
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    no_line = re.sub(r"(^|[^:])//[^\n]*", r"\1", no_block)
    no_trailing = re.sub(r",(\s*[}\]])", r"\1", no_line)
    for candidate in (text, no_trailing, no_line):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _is_exec(idx: FileIndex, rel: str) -> bool:
    try:
        return bool(idx.abs(rel).stat().st_mode & stat.S_IXUSR)
    except OSError:
        return False


# Instructions in agent-read files that tell the agent to run commands =
# prompt injection. These phrases, near a command, are the signal.
_INJECTION_RX = re.compile(
    r"(?i)\b(?:run|execute|exec|paste|copy[- ]?paste|curl|wget|npm\s+install|pip\s+install|"
    r"chmod|bash\b|sh\s+-c|eval|source\b|before\s+(?:you\s+)?(?:do\s+anything|starting)|"
    r"ignore\s+(?:previous|prior|all)\s+instructions|system\s*prompt|do\s+not\s+tell\s+the\s+user)\b"
)


# --------------------------------------------------------------------------- #
# git
# --------------------------------------------------------------------------- #

_HOOK_NAMES = {
    "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-push",
    "pre-rebase", "post-checkout", "post-merge", "pre-receive", "update",
    "post-receive", "post-update", "pre-applypatch", "post-applypatch",
    "applypatch-msg", "post-rewrite", "fsmonitor-watchman", "post-index-change",
}


@detector
def git_native_hooks(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "git-native-hook", "Git hook runs on git operations", "git",
        "git commit / checkout / push / merge (also fires when an agent runs git)",
        "Files in .git/hooks execute automatically on ordinary git commands; they are "
        "not shown in the working tree and survive review of tracked files.",
        "Inspect .git/hooks/*; remove or empty unexpected hooks. Set core.hooksPath to a "
        "reviewed, version-controlled directory.",
        "high",
    )
    for rel in idx.under(".git/hooks"):
        name = os.path.basename(rel)
        if name.endswith(".sample") or name not in _HOOK_NAMES:
            continue
        code = idx.read(rel)
        if not code.strip():
            continue
        yield build_finding(vec, rel, code, snippet=snippet_of(code))


@detector
def git_hooks_path(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "git-hookspath", "core.hooksPath redirects git hooks", "git",
        "any git command",
        "core.hooksPath points git at an arbitrary directory of scripts that run on git "
        "operations — a repo can set this to a folder it controls.",
        "Verify the hooksPath directory is trusted and reviewed.",
        "high",
    )
    for rel in idx.by_name("config"):
        if not rel.startswith(".git"):
            continue
        code = idx.read(rel)
        m = re.search(r"(?im)^\s*hooksPath\s*=\s*(.+)$", code)
        if m:
            yield build_finding(vec, rel, code, snippet=m.group(0).strip(),
                                line=find_line(code, m.group(0)), scan_text=m.group(1))


@detector
def husky_hooks(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "husky-hook", "Husky git hook", "git",
        "git commit / push",
        "Husky installs git hooks from the .husky/ directory that run on git operations.",
        "Review .husky/* scripts; they run shell on commit/push.",
        "medium",
    )
    for rel in idx.under(".husky"):
        name = os.path.basename(rel)
        if name.startswith("_") or name in {"husky.sh"}:
            continue
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code))


@detector
def pre_commit_lefthook(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "precommit-config", "pre-commit / lefthook config runs hooks", "git",
        "git commit (once hooks installed)",
        "Config declares commands and remote hook repos that run on commit; a "
        "'repo: local' entry can run any shell.",
        "Audit entry point commands and pinned hook repo revisions.",
        "medium",
    )
    for rel in idx.by_name(".pre-commit-config.yaml", ".pre-commit-config.yml",
                           "lefthook.yml", "lefthook.yaml", ".lefthook.yml"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 10))


@detector
def gitattributes_filter(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "gitattributes-filter", "Git filter driver runs on checkout/commit", "git",
        "git checkout / add / status (clean & smudge filters)",
        "A filter= driver in .gitattributes runs the configured clean/smudge command on "
        "matching files during normal git operations.",
        "Check .gitattributes for filter= and the git config that defines the driver command.",
        "medium",
    )
    for rel in idx.by_name(".gitattributes"):
        code = idx.read(rel)
        m = re.search(r"(?im)filter=(\S+)", code)
        if m:
            yield build_finding(vec, rel, code, snippet=m.group(0),
                                line=find_line(code, m.group(0)))


# --------------------------------------------------------------------------- #
# node / js
# --------------------------------------------------------------------------- #

@detector
def npm_lifecycle(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "npm-lifecycle-script", "npm/pnpm/yarn lifecycle script", "node",
        "npm install / pnpm install / yarn (preinstall, install, postinstall, prepare)",
        "Lifecycle scripts run automatically during dependency install — the #1 "
        "supply-chain execution vector. An agent running `npm install` triggers them.",
        "Install with --ignore-scripts; audit these scripts; pin & vet dependencies.",
        "medium",
    )
    for rel in idx.by_name("package.json"):
        # skip nested dependency manifests inside vendored trees (already pruned, but be safe)
        data = _load_jsonc(idx.read(rel))
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for key, cmd in scripts.items():
            if key in _LIFECYCLE_KEYS and isinstance(cmd, str) and cmd.strip():
                code = idx.read(rel)
                yield build_finding(
                    vec, rel, code, snippet=f'"{key}": "{cmd}"',
                    line=find_line(code, f'"{key}"'), scan_text=cmd,
                )


@detector
def pnpmfile(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "pnpmfile", ".pnpmfile.cjs runs during install", "node",
        "pnpm install",
        ".pnpmfile.cjs executes arbitrary Node during dependency resolution/install.",
        "Review or remove .pnpmfile.cjs.",
        "high",
    )
    for rel in idx.by_name(".pnpmfile.cjs", ".pnpmfile.js"):
        code = idx.read(rel)
        yield build_finding(vec, rel, code, snippet=snippet_of(code))


@detector
def npmrc(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "npmrc", ".npmrc alters install behaviour / leaks tokens", "node",
        "npm/yarn install",
        ".npmrc can disable script sandboxing, repoint the registry to a malicious mirror, "
        "or embed auth tokens that leak with the repo.",
        "Check registry overrides and remove committed _authToken values.",
        "medium",
    )
    for rel in idx.by_name(".npmrc", ".yarnrc", ".yarnrc.yml"):
        code = idx.read(rel)
        if re.search(r"(?i)(_authToken|_auth\b|registry\s*=|ignore-scripts\s*=\s*false|enable-pre-post-scripts)", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8))


# --------------------------------------------------------------------------- #
# python
# --------------------------------------------------------------------------- #

@detector
def python_setup_py(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "python-setup-py", "setup.py executes on build/install", "python",
        "pip install / python setup.py / build",
        "setup.py is arbitrary Python run at install time; a common sdist supply-chain vector.",
        "Prefer declarative pyproject metadata; audit any code beyond setup()/find_packages.",
        "low",
    )
    for rel in idx.by_name("setup.py"):
        code = idx.read(rel)
        # benign setups are basically just setup(...); flag ones that do more.
        interesting = re.search(
            r"(?im)(os\.system|subprocess|Popen|urllib|requests\.|socket|exec\(|eval\(|__import__|"
            r"cmdclass|install_requires\s*=\s*\[[^\]]*(?:git\+|http))", code)
        yield build_finding(vec, rel, code, snippet=snippet_of(code, 8),
                            scan_text=code if interesting else "")


@detector
def python_import_hooks(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "python-import-hook", "Python auto-imported module with side effects", "python",
        "importing the package / running pytest / starting the interpreter",
        "conftest.py, sitecustomize.py, usercustomize.py and .pth files run automatically "
        "(pytest collection, interpreter startup, or site initialisation) with no explicit call.",
        "Ensure these contain no network/exec side effects; .pth files must not start with 'import'.",
        "medium",
    )
    for rel in idx.by_name("conftest.py", "sitecustomize.py", "usercustomize.py"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8))
    for rel in idx.by_suffix(".pth"):
        code = idx.read(rel)
        # executable .pth lines begin with `import`
        if re.search(r"(?m)^\s*import\s", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 4))


# --------------------------------------------------------------------------- #
# editors / IDE
# --------------------------------------------------------------------------- #

@detector
def vscode_tasks(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "vscode-autotask", "VSCode task runs on folder open", "editor",
        "opening the folder in VS Code",
        'A task with "runOn": "folderOpen" executes the moment the workspace is opened — '
        "no command needed.",
        'Remove runOptions.runOn=folderOpen; review the task command.',
        "high",
    )
    for rel in idx.by_name("tasks.json"):
        if os.path.dirname(rel).split(os.sep)[-1] != ".vscode":
            continue
        code = idx.read(rel)
        if re.search(r'"runOn"\s*:\s*"folderOpen"', code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 12),
                                line=find_line(code, "folderOpen"))


@detector
def vscode_settings(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "vscode-settings", "VSCode settings inject env / auto-run", "editor",
        "opening the folder / running any task in VS Code",
        "Workspace settings can set terminal.integrated.env, override the automation shell, "
        "or configure code-runner to execute code, all scoped to this repo.",
        "Review .vscode/settings.json for terminal env, shell overrides, code-runner commands.",
        "medium",
    )
    for rel in idx.by_name("settings.json"):
        if os.path.dirname(rel).split(os.sep)[-1] != ".vscode":
            continue
        code = idx.read(rel)
        if re.search(r"(?i)(terminal\.integrated\.(env|automation|profiles)|code-runner|python\.testing|"
                     r"\.autoActivate|runner\.executorMap)", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 10))


@detector
def devcontainer(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "devcontainer-lifecycle", "Dev Container lifecycle command", "editor",
        "opening the repo in a Dev Container / Codespace",
        "initializeCommand/onCreateCommand/postCreateCommand/postStartCommand run shell "
        "automatically when the container is built or started.",
        "Audit each *Command in devcontainer.json.",
        "medium",
    )
    for rel in idx.by_name("devcontainer.json"):
        data = _load_jsonc(idx.read(rel))
        code = idx.read(rel)
        if not isinstance(data, dict):
            continue
        for key in ("initializeCommand", "onCreateCommand", "updateContentCommand",
                    "postCreateCommand", "postStartCommand", "postAttachCommand"):
            if key in data and data[key]:
                cmd = data[key]
                cmd_s = cmd if isinstance(cmd, str) else json.dumps(cmd)
                yield build_finding(vec, rel, code, snippet=f'"{key}": {json.dumps(cmd)[:200]}',
                                    line=find_line(code, key), scan_text=cmd_s)


@detector
def editor_dir_locals(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "editor-dir-locals", "Per-directory editor config with code", "editor",
        "opening a file in Emacs (.dir-locals.el) / Vim (exrc, modelines)",
        "Emacs .dir-locals.el and Vim project rc files can evaluate code (eval, :autocmd, "
        "shell) when a file in the directory is opened.",
        "Set enable-local-eval=nil (Emacs) / disable exrc & modelines (Vim); review the file.",
        "medium",
    )
    for rel in idx.by_name(".dir-locals.el", ".exrc", ".nvimrc", ".vimrc", ".nvim.lua", ".lvimrc"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6))


# --------------------------------------------------------------------------- #
# AI agent configuration
# --------------------------------------------------------------------------- #

@detector
def claude_permissions(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "claude-autoapprove", "Claude Code pre-approves tools / runs hooks", "agent",
        "the agent reads .claude/settings*.json",
        "permissions.allow can pre-authorise dangerous tools (Bash, arbitrary commands) so "
        "the agent runs them without prompting; hooks run shell on tool events.",
        "Review permissions.allow for broad Bash/command entries; audit hooks[*].command.",
        "high",
    )
    for rel in idx.by_name("settings.json", "settings.local.json"):
        if os.path.dirname(rel).split(os.sep)[-1] != ".claude":
            continue
        data = _load_jsonc(idx.read(rel))
        code = idx.read(rel)
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions", {})
        allow = perms.get("allow", []) if isinstance(perms, dict) else []
        broad = [a for a in allow if isinstance(a, str) and re.search(r"(?i)bash|^\*$|\(\*\)|run|exec", a)]
        hooks = data.get("hooks")
        if broad or hooks:
            snip = json.dumps({k: data[k] for k in ("permissions", "hooks") if k in data}, indent=1)[:400]
            yield build_finding(vec, rel, code, snippet=snip, scan_text=json.dumps(data))


@detector
def mcp_servers(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "mcp-server", "MCP server auto-launched by agent", "agent",
        "the agent/IDE loads .mcp.json / mcpServers config",
        "An MCP server entry specifies a command+args that the agent launches automatically; "
        "a repo-local .mcp.json can start any local process.",
        "Verify each mcpServers[*].command is a trusted binary, not a repo-local script.",
        "high",
    )
    for rel in idx.by_name(".mcp.json", "mcp.json"):
        data = _load_jsonc(idx.read(rel))
        code = idx.read(rel)
        if isinstance(data, dict) and data.get("mcpServers"):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 12),
                                scan_text=json.dumps(data))


@detector
def agent_instruction_injection(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "agent-instruction-injection", "Agent-read file contains command instructions", "agent",
        "the coding agent reads project instructions",
        "Files agents auto-read (CLAUDE.md, .cursorrules, copilot-instructions, aider conf) "
        "can carry prompt-injection telling the agent to run commands or exfiltrate data.",
        "Read these files as untrusted input; never let an agent act on embedded shell commands.",
        "medium",
    )
    names = ("CLAUDE.md", ".cursorrules", "copilot-instructions.md", ".windsurfrules",
             ".aider.conf.yml", ".clinerules", "AGENTS.md", "GEMINI.md")
    rels = list(idx.by_name(*names)) + [r for r in idx.under(".cursor/rules")]
    for rel in rels:
        code = idx.read(rel)
        hits = _INJECTION_RX.findall(code)
        if len(hits) >= 2 or re.search(r"(?i)ignore\s+(previous|all)\s+instructions", code):
            m = _INJECTION_RX.search(code)
            yield build_finding(vec, rel, code,
                                snippet=snippet_of(code, 6, around=m.group(0) if m else ""),
                                line=find_line(code, m.group(0)) if m else None,
                                scan_text=code)


# --------------------------------------------------------------------------- #
# shell / env
# --------------------------------------------------------------------------- #

@detector
def direnv_envrc(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "direnv-envrc", ".envrc runs on cd into the directory", "shell",
        "changing into the directory with direnv installed",
        ".envrc is sourced by direnv the moment you cd into the repo; it runs arbitrary shell.",
        "Inspect before `direnv allow`; never allow an unreviewed .envrc.",
        "high",
    )
    for rel in idx.by_name(".envrc"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8))


@detector
def dropped_secrets_persistence(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "repo-dropped-unit", "Repo ships a shell rc / service / cron fragment", "shell",
        "if sourced or installed into the user environment",
        "A repo carrying .bashrc/.zshrc/.profile, systemd units, or crontab fragments can "
        "establish persistence if a setup step installs them.",
        "Do not source repo-provided rc files; inspect any install step that copies them.",
        "medium",
    )
    for rel in idx.by_name(".bashrc", ".zshrc", ".bash_profile", ".profile", ".zprofile",
                           "crontab", ".netrc"):
        # only if at repo root-ish (dotfile repos are a legit case but still worth flagging low)
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6))


# --------------------------------------------------------------------------- #
# CI / task runners
# --------------------------------------------------------------------------- #

@detector
def github_actions(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "gha-pull-request-target", "GitHub Actions runs untrusted code with secrets", "ci",
        "a pull request against the repo",
        "pull_request_target / workflow_run run with repo secrets while able to check out "
        "untrusted PR code; ${{ github.event.* }} interpolated into run: is a script-injection sink.",
        "Avoid pull_request_target with PR checkout; never interpolate event data into run:; pin actions by SHA.",
        "high",
    )
    for rel in idx.rel_paths:
        if not (rel.startswith(".github/workflows") and rel.endswith((".yml", ".yaml"))):
            continue
        code = idx.read(rel)
        risky = (
            "pull_request_target" in code
            or "workflow_run" in code
            or re.search(r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)[.\[]", code)
        )
        if risky:
            m = re.search(r"(pull_request_target|workflow_run|\$\{\{\s*github\.event\.[^}]+\}\})", code)
            yield build_finding(vec, rel, code,
                                snippet=snippet_of(code, 10, around=m.group(0) if m else ""),
                                line=find_line(code, m.group(0)) if m else None,
                                scan_text=code)


@detector
def task_runners(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "task-runner-default", "Task runner default target runs shell", "ci",
        "running `make`, `just`, or `task` with no argument",
        "Makefile/justfile/Taskfile recipes run shell; a default target or an include of a "
        "remote/generated file executes when the tool is run in the repo.",
        "Read the default target and any include/remote directives before running.",
        "low",
    )
    for rel in idx.by_name("Makefile", "makefile", "GNUmakefile", "justfile", ".justfile",
                           "Taskfile.yml", "Taskfile.yaml"):
        code = idx.read(rel)
        # only surface if it fetches network or does more than trivial build
        if re.search(r"(?i)(curl|wget|\|\s*sh|\|\s*bash|include\s+http|-include\s+\S)", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8))


# --------------------------------------------------------------------------- #
# other languages
# --------------------------------------------------------------------------- #

@detector
def rust_build_rs(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "rust-build-rs", "Rust build.rs runs at compile time", "lang",
        "cargo build / cargo test",
        "build.rs is arbitrary Rust executed during compilation; a dependency's build script "
        "runs on your machine when you build.",
        "Audit build.rs, especially network access or Command spawns.",
        "medium",
    )
    for rel in idx.by_name("build.rs"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 8),
                                scan_text=code if re.search(r"(?i)(Command|process|reqwest|std::net|curl)", code) else "")


@detector
def ruby_rakefile(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "ruby-rakefile", "Ruby Rakefile / Gemfile runs code", "lang",
        "bundle install / rake",
        "Gemfile is evaluated as Ruby during bundle; Rakefile runs on `rake`. Both can shell out.",
        "Review Gemfile for arbitrary code and Rakefile default tasks.",
        "low",
    )
    for rel in idx.by_name("Gemfile", "Rakefile"):
        code = idx.read(rel)
        if re.search(r"(?i)(system\(|`[^`]+`|%x\{|IO\.popen|Net::HTTP|open\(|eval)", code):
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6), scan_text=code)


@detector
def r_profile(idx: FileIndex) -> Iterator[Finding]:
    vec = Vector(
        "r-profile", ".Rprofile runs on R startup", "lang",
        "starting R in the project directory",
        ".Rprofile in the working directory is sourced automatically when R starts.",
        "Inspect .Rprofile; disable with R_PROFILE_USER= or --no-init-file.",
        "medium",
    )
    for rel in idx.by_name(".Rprofile", ".Renviron"):
        code = idx.read(rel)
        if code.strip():
            yield build_finding(vec, rel, code, snippet=snippet_of(code, 6))
