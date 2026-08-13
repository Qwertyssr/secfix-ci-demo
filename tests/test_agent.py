"""Unit tests for the secfix agent: adapters + fixers, run offline."""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secfix.normalize import normalize_blackduck, normalize_fortify  # noqa: E402
from secfix.fixers.deps import apply_dependency_fixes, bump_requirements  # noqa: E402
from secfix.fixers import rules  # noqa: E402
from secfix.fixers.code import fix_code_finding  # noqa: E402
from secfix.models import Finding  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_blackduck_parses_fixed_version(self):
        report = {"items": [{
            "componentName": "PyYAML", "componentVersionName": "5.3",
            "componentVersionOriginId": "pypi:PyYAML:5.3",
            "vulnerabilityWithRemediation": {
                "vulnerabilityName": "CVE-2020-14343", "severity": "CRITICAL",
                "solution": "Upgrade to 5.4 or later"}}]}
        f = normalize_blackduck(report)[0]
        self.assertEqual(f.component, "PyYAML")
        self.assertEqual(f.fixed_version, "5.4")
        self.assertEqual(f.type, "dependency_vuln")

    def test_fortify_maps_category(self):
        report = {"data": [{
            "issueInstanceId": "X", "category": "SQL Injection", "friority": "Critical",
            "fullFileName": "sample_app/db.py", "lineNumber": 13}]}
        f = normalize_fortify(report)[0]
        self.assertEqual(f.category, "SQL Injection")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.type, "code_vuln")


class DepsFixerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "requirements.txt"), "w") as fh:
            fh.write("PyYAML==5.3\nrequests==2.19.1\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_bump(self):
        findings = [Finding("blackduck", "dependency_vuln", "critical", "x",
                            cve="CVE-1", component="PyYAML", current_version="5.3", fixed_version="5.4")]
        patch = bump_requirements(self.d, findings)
        self.assertIsNotNone(patch)
        self.assertIn("PyYAML==5.4", patch.files["requirements.txt"])
        self.assertIn("requests==2.19.1", patch.files["requirements.txt"])  # untouched

    def test_blackduck_current_version_must_match_manifest(self):
        findings = [Finding("blackduck", "dependency_vuln", "critical", "x",
                            cve="CVE-1", component="PyYAML", current_version="5.2", fixed_version="5.4")]
        patch = apply_dependency_fixes(self.d, findings)
        self.assertIsNone(patch)


class SastRuleTests(unittest.TestCase):
    def _fix(self, filename, src, category):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, filename), "w") as fh:
                fh.write(src)
            f = Finding("fortify", "code_vuln", "high", category, category=category, file=filename, line=1)
            patch = fix_code_finding(d, f)
            self.assertIsNotNone(patch, f"no patch for {category}")
            content = patch.files[filename]
            self.assertFalse(rules.residue_present(content, f), f"residue remained for {category}")
            return content
        finally:
            shutil.rmtree(d)

    def test_weak_hash(self):
        out = self._fix("a.py", "import hashlib\nx = hashlib.md5(b'a')\n", "Weak Cryptographic Hash")
        self.assertIn("sha256", out)

    def test_yaml(self):
        out = self._fix("c.py", "import yaml\nd = yaml.load(s, Loader=yaml.Loader)\n", "Insecure Deserialization")
        self.assertIn("yaml.safe_load(s)", out)

    def test_command_injection(self):
        src = 'import subprocess\ncmd = "python r.py --name " + name\nsubprocess.call(cmd, shell=True)\n'
        out = self._fix("t.py", src, "Command Injection")
        self.assertIn('["python", "r.py", "--name", name]', out)
        self.assertNotIn("shell=True", out)

    def test_sql_injection(self):
        src = 'cur.execute("SELECT * FROM u WHERE n = \'" + username + "\'")\n'
        out = self._fix("db.py", src, "SQL Injection")
        self.assertIn('execute("SELECT * FROM u WHERE n = ?", (username,))', out)


if __name__ == "__main__":
    unittest.main()
