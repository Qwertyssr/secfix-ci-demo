"""LLM (Vertex AI) fix-flow test — exercised with a STUB provider, no credentials.

Proves the orchestrator's decision logic in secfix/fixers/code.py:
  1. an AI patch that clears the residue check is USED (provider = 'vertex');
  2. an AI patch that does NOT clear the residue check is REJECTED and the
     deterministic rule engine takes over (provider = 'rule');
  3. when the AI provider is unavailable, rules are used.

No Google credentials are involved — sast.fix_code is monkeypatched. This is how
we validate the LLM flow without sending any secret to a model or to Vertex AI.

Run:  py -m unittest tests.test_llm_flow -v
"""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secfix.fixers import code as code_mod        # noqa: E402
from secfix.fixers import sast as sast_mod        # noqa: E402
from secfix.fixers import Patch                   # noqa: E402
from secfix.models import Finding                 # noqa: E402


class LlmFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = sast_mod.fix_code

    def tearDown(self):
        sast_mod.fix_code = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as fh:
            fh.write(content)
        return name

    def test_ai_patch_used_when_verified(self):
        rel = self._write("m.py", "def f(x):\n    return eval(x)\n")
        finding = Finding("fortify", "code_vuln", "critical", "Dynamic Code Evaluation",
                          category="Dynamic Code Evaluation", file=rel, line=2)
        fixed = "import ast\n\n\ndef f(x):\n    return ast.literal_eval(x)\n"
        sast_mod.fix_code = lambda app_dir, f: Patch(
            finding=f, summary="ai", files={f.file: fixed}, provider="vertex")

        patch = code_mod.fix_code_finding(self.tmp, finding)
        self.assertIsNotNone(patch)
        self.assertEqual(patch.provider, "vertex")           # AI patch accepted
        self.assertIn("literal_eval", patch.files[rel])

    def test_ai_patch_rejected_falls_back_to_rule(self):
        rel = self._write("h.py", "import hashlib\nx = hashlib.md5(b'a')\n")
        finding = Finding("fortify", "code_vuln", "high", "Weak Cryptographic Hash",
                          category="Weak Cryptographic Hash", file=rel, line=2)
        # AI returns content that STILL contains md5 -> residue present -> rejected
        sast_mod.fix_code = lambda app_dir, f: Patch(
            finding=f, summary="ai-bad",
            files={f.file: "import hashlib\nx = hashlib.md5(b'a')  # not actually fixed\n"},
            provider="vertex")

        patch = code_mod.fix_code_finding(self.tmp, finding)
        self.assertIsNotNone(patch)
        self.assertEqual(patch.provider, "rule")             # fell back to rules
        self.assertIn("sha256", patch.files[rel])

    def test_ai_unavailable_uses_rule(self):
        rel = self._write("h2.py", "import hashlib\nx = hashlib.md5(b'a')\n")
        finding = Finding("fortify", "code_vuln", "high", "Weak Cryptographic Hash",
                          category="Weak Cryptographic Hash", file=rel, line=2)
        sast_mod.fix_code = lambda app_dir, f: None            # provider not available

        patch = code_mod.fix_code_finding(self.tmp, finding)
        self.assertEqual(patch.provider, "rule")

    def test_context_window_limits_llm_input(self):
        content = "".join(f"line {i}\n" for i in range(1, 101))
        start, end, snippet = sast_mod._context_window(content, 50)

        self.assertEqual((start, end), (30, 70))
        self.assertIn("line 50\n", snippet)
        self.assertNotIn("line 29\n", snippet)
        self.assertNotIn("line 71\n", snippet)

    def test_replace_window_keeps_content_outside_llm_context(self):
        content = "".join(f"line {i}\n" for i in range(1, 8))
        updated = sast_mod._replace_window(content, 3, 5, "fixed 3\nfixed 4\n")

        self.assertTrue(updated.startswith("line 1\nline 2\n"))
        self.assertIn("fixed 3\nfixed 4\n", updated)
        self.assertTrue(updated.endswith("line 6\nline 7\n"))


if __name__ == "__main__":
    unittest.main()
