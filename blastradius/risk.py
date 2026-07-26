"""Cross-cutting risk amplifiers.

A vector (e.g. a postinstall script) has a *base* severity just for existing.
What makes it actually dangerous is what the code inside *does*. These
amplifiers grep the referenced content and escalate severity accordingly.
This is the "blast radius" engine: a benign postinstall stays LOW, one that
pipes curl to bash and reads ~/.ssh becomes CRITICAL.
"""
from __future__ import annotations

import re

from .models import Amplifier, Severity

# (id, name, weight, why, pattern)
# weight 5 == on its own strong evidence of malice / full RCE with side effects.
_SPECS: list[tuple[str, str, int, str, str]] = [
    (
        "pipe-to-shell",
        "Pipe network download straight into a shell",
        5,
        "Downloads code from the internet and executes it unseen — classic drive-by RCE.",
        r"(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|d|k|fi)?sh\b",
    ),
    (
        "iwr-iex",
        "PowerShell download-and-execute (IWR|IEX)",
        5,
        "Windows equivalent of curl|bash — fetches and runs remote code in memory.",
        r"(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString)[^\n]*(?:\|\s*)?(?:Invoke-Expression|iex)\b",
    ),
    (
        "base64-decode-exec",
        "Base64/hex decode then execute",
        5,
        "Obfuscated payload decoded and run — deliberate attempt to hide intent from review.",
        r"(?:base64\s+(?:-d|--decode)|b64decode|FromBase64String|atob)\b[^\n]{0,80}(?:\|\s*(?:ba|z)?sh|eval|exec|Invoke-Expression|iex)",
    ),
    (
        "reverse-shell",
        "Reverse / bind shell",
        5,
        "Opens an interactive shell back to an attacker — full remote control.",
        r"(?:/dev/tcp/|bash\s+-i\b|nc\s+(?:-[a-z]*e|.*-e\b)|ncat\s+.*-e|socket\.socket\([^\n]*connect|pty\.spawn)",
    ),
    (
        "credential-access",
        "Reads credentials / secrets",
        4,
        "Touches SSH keys, cloud creds, tokens or dotfiles that hold secrets — exfil precursor.",
        r"(?:\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.netrc|\.docker/config|"
        r"GITHUB_TOKEN|AWS_SECRET|_TOKEN\b|_API_KEY\b|\.env\b|keychain|secretsmanager|"
        r"\benv\b\s*(?:\||>)|printenv)",
    ),
    (
        "persistence",
        "Installs persistence",
        4,
        "Writes to crontab, authorized_keys, shell rc files or services so code re-runs later.",
        r"(?:crontab|authorized_keys|>>\s*~?/?\.(?:bashrc|zshrc|profile|bash_profile)|"
        r"systemctl\s+--user|launchctl\s+load|/etc/cron|schtasks\s+/create|reg\s+add)",
    ),
    (
        "data-exfil",
        "Exfiltrates data over the network",
        4,
        "POSTs local files/output to a remote host — data theft.",
        r"(?:curl|wget|nc|http)[^\n]*(?:--data|-d\b|-F\b|--upload-file|-T\b|POST)[^\n]*(?:https?://|\d+\.\d+\.\d+\.\d+)",
    ),
    (
        "destructive",
        "Destructive filesystem/device operation",
        4,
        "Mass delete or raw device write — data loss / sabotage.",
        r"(?:rm\s+-[rfRF]{1,3}\s+(?:/|~|\$HOME|\*)|mkfs|dd\s+[^\n]*of=/dev/|:\(\)\{|shred\s)",
    ),
    (
        "eval-dynamic",
        "Evaluates a dynamically built string",
        3,
        "Runs code assembled at runtime — hides the real command from static review.",
        r"\b(?:eval|exec)\s*\(?[\"'`]?\$|Function\(|new\s+Function|child_process|os\.system|subprocess\.(?:call|run|Popen)\s*\([^\n]*shell\s*=\s*True",
    ),
    (
        "obfuscation",
        "Obfuscated payload",
        3,
        "Long encoded blobs or char-code assembly — legitimate build steps don't need this.",
        r"(?:[A-Za-z0-9+/]{120,}={0,2}|(?:\\x[0-9a-fA-F]{2}){12,}|String\.fromCharCode\((?:\d+,\s*){8,})",
    ),
    (
        "disable-security",
        "Disables logging or security controls",
        3,
        "Clears history, disables AV/firewall, or removes audit trails to evade detection.",
        r"(?:history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|set\s+MpPreference|"
        r"Defender|ufw\s+disable|iptables\s+-F|chattr\s+[+-]i|setenforce\s+0)",
    ),
    (
        "env-code-loader",
        "Sets an environment variable that auto-loads code",
        4,
        "NODE_OPTIONS/BASH_ENV/LD_PRELOAD/PYTHONSTARTUP/GIT_SSH_COMMAND & friends make an "
        "interpreter or git load attacker-controlled code on the next run.",
        r"(?:NODE_OPTIONS\s*=[^\n]*(?:--(?:require|import|loader)|(?:^|\s)-r\b)|BASH_ENV\s*=|"
        r"LD_PRELOAD\s*=|LD_LIBRARY_PATH\s*=|PYTHONSTARTUP\s*=|PYTHONPATH\s*=[^\n]*\.pth|"
        r"GIT_SSH_COMMAND\s*=|RUBYOPT\s*=|PERL5OPT\s*=|DYLD_INSERT_LIBRARIES\s*=)",
    ),
    (
        "hidden-unicode",
        "Invisible / bidirectional Unicode (Trojan Source)",
        3,
        "Zero-width, bidi-override or line-separator characters can hide or visually reorder "
        "code from a human reviewer while the machine runs something else.",
        "[‪-‮⁦-⁩​‌‍‎‏﻿  ]",
    ),
    (
        "network-egress",
        "Contacts the network",
        2,
        "Makes an outbound connection — benign alone, but amplifies anything alongside it.",
        r"(?:curl|wget|nc\b|ncat|Invoke-WebRequest|Invoke-RestMethod|https?://|ftp://|\d{1,3}(?:\.\d{1,3}){3})",
    ),
    (
        "privilege",
        "Escalates privileges / weakens permissions",
        2,
        "sudo, chmod 777 or setuid — widens what the payload can reach.",
        r"(?:\bsudo\b|chmod\s+(?:-R\s+)?[0-7]*777|chmod\s+[+]s|setcap|doas\b)",
    ),
    (
        "self-conceal",
        "Hides or unstages itself",
        3,
        "Deletes itself, hides from git, or suppresses output so the change goes unnoticed.",
        r"(?:rm\s+-f?\s*[\"']?\$?0|git\s+update-index\s+--assume-unchanged|"
        r"\.gitignore|>\s*/dev/null\s+2>&1\s*&\s*$|nohup|disown)",
    ),
]

_COMPILED = [
    (aid, name, weight, why, re.compile(pat, re.IGNORECASE | re.MULTILINE))
    for aid, name, weight, why, pat in _SPECS
]


def scan_amplifiers(text: str) -> list[Amplifier]:
    """Return the amplifiers present in ``text`` (deduped by id)."""
    if not text:
        return []
    out: list[Amplifier] = []
    for aid, name, weight, why, rx in _COMPILED:
        m = rx.search(text)
        if m:
            evidence = m.group(0).strip()
            if len(evidence) > 160:
                evidence = evidence[:157] + "..."
            out.append(Amplifier(id=aid, name=name, weight=weight, why=why, evidence=evidence))
    return out


def escalate(base: Severity, amps: list[Amplifier]) -> Severity:
    """Combine a base severity with amplifier weights into an effective severity."""
    if not amps:
        return base
    total = sum(a.weight for a in amps)
    strongest = max(a.weight for a in amps)
    score = int(base)
    # A single weight-5 signal is standalone evidence of RCE-with-intent.
    if strongest >= 5:
        score = max(score, int(Severity.CRITICAL))
    if total >= 6:
        score += 2
    elif total >= 3:
        score += 1
    return Severity(min(int(Severity.CRITICAL), max(int(Severity.INFO), score)))
