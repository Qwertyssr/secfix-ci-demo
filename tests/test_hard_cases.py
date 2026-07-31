"""Hard / complex scan stress test.

Runs the full agent against fixtures that deliberately include vulnerability
classes the deterministic engine cannot safely auto-fix (XXE, SSRF, pickle,
eval, path traversal, hardcoded secret, f-string SQLi) plus tricky SCA cases
(multi-CVE component, transitive dep, no-fix-available). Asserts secfix fixes
only what it can verify and safely escalates the rest.

Run:  py -m unittest tests.test_hard_cases -v
"""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import secfix.cli as cli  # noqa: E402


class HardCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        shutil.copy(os.path.join(ROOT, "hard_demo", "app.py"), self.tmp)
        shutil.copy(os.path.join(ROOT, "hard_demo", "requirements.txt"), self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fixes_verifiable_escalates_hard(self):
        rc = cli.run([
            "--root", self.tmp,
            "--blackduck", os.path.join(ROOT, "hard_demo", "reports", "blackduck.json"),
            "--fortify", os.path.join(ROOT, "hard_demo", "reports", "fortify.json"),
            "--req", "requirements.txt",
            "--severities", "critical,high,medium",
        ])
        self.assertEqual(rc, 0)

        with open(os.path.join(self.tmp, "requirements.txt")) as fh:
            req = fh.read()
        self.assertIn("PyYAML==5.4", req)       # highest of two CVE fixes (5.3.1 vs 5.4)
        self.assertIn("requests==2.20.0", req)

        with open(os.path.join(self.tmp, "app.py")) as fh:
            code = fh.read()
        # verifiable fixes applied
        self.assertIn("hashlib.sha256", code)
        self.assertNotIn("shell=True", code)
        # hard cases safely left untouched (escalated, not guessed)
        for residue in ("pickle.loads(", "eval(", "fromstring(", "AKIA1234567890EXAMPLE"):
            self.assertIn(residue, code, f"{residue} should remain (escalated)")
        # f-string SQLi must not be mangled into a broken parameterized query
        self.assertIn('f"SELECT * FROM users WHERE name', code)


if __name__ == "__main__":
    unittest.main()
