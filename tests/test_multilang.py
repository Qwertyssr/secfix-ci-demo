"""Multi-language coverage test.

Runs the full agent against a polyglot project (npm, Maven, Go manifests + JS,
Java, Go source) and asserts secfix bumps every ecosystem's dependencies and
applies the cross-language weak-hash fix — leaving unrelated entries untouched.

Run:  py -m unittest tests.test_multilang -v
"""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import secfix.cli as cli  # noqa: E402

SRC = os.path.join(ROOT, "multilang_demo")


class MultiLanguage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for name in ("crypto_util.js", "package.json", "Hasher.java", "pom.xml", "hash.go", "go.mod"):
            shutil.copy(os.path.join(SRC, name), self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _read(self, name):
        with open(os.path.join(self.tmp, name), encoding="utf-8") as fh:
            return fh.read()

    def test_polyglot_fix(self):
        rc = cli.run([
            "--root", self.tmp,
            "--blackduck", os.path.join(SRC, "reports", "blackduck.json"),
            "--fortify", os.path.join(SRC, "reports", "fortify.json"),
            "--severities", "critical,high,medium",
        ])
        self.assertEqual(rc, 0)

        # npm
        pkg = self._read("package.json")
        self.assertIn('"lodash": "4.17.21"', pkg)
        self.assertIn('"minimist": "1.2.6"', pkg)
        # maven — vulnerable deps bumped, project version untouched
        pom = self._read("pom.xml")
        self.assertIn("<version>2.17.1</version>", pom)   # log4j-core
        self.assertIn("<version>3.2.2</version>", pom)    # commons-collections
        self.assertIn("<version>1.0.0</version>", pom)    # project version preserved
        # go — flagged module bumped, other left alone
        gomod = self._read("go.mod")
        self.assertIn("gopkg.in/yaml.v2 v2.2.8", gomod)
        self.assertIn("github.com/dgrijalva/jwt-go v3.2.0+incompatible", gomod)

        # cross-language SAST weak-hash fixes
        self.assertIn("createHash('sha256')", self._read("crypto_util.js"))
        self.assertIn('getInstance("SHA-256")', self._read("Hasher.java"))
        go = self._read("hash.go")
        self.assertIn('"crypto/sha256"', go)
        self.assertIn("sha256.Sum256(", go)
        self.assertNotIn("md5", go)


if __name__ == "__main__":
    unittest.main()
