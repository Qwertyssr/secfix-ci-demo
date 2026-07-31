"""Integration tests for the live scanner API clients.

Stands up mock HTTP servers that replicate the *real* Black Duck and Fortify SSC
API contracts (auth handshakes, media types, href navigation, endpoint shapes),
then asserts the clients authenticate, paginate the resource graph, and return
reports that normalize into correct Findings. This exercises the real-API code
path without needing the licensed commercial servers.

Run:  py -m unittest tests.test_scanner_clients -v
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secfix.scanners.blackduck_client import BlackDuckClient  # noqa: E402
from secfix.scanners.fortify_client import FortifyClient  # noqa: E402
from secfix.normalize import normalize_blackduck, normalize_fortify  # noqa: E402


# --------------------------------------------------------------------------
# Mock Black Duck Hub
# --------------------------------------------------------------------------
def _blackduck_handler(base_holder):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path == "/api/tokens/authenticate":
                # real BD requires 'Authorization: token <api-token>'
                assert self.headers.get("Authorization") == "token BD-API-TOKEN"
                self._json(200, {"bearerToken": "BEARER-XYZ", "expiresInMilliseconds": 7200000})
            else:
                self._json(404, {})

        def do_GET(self):
            base = base_holder["base"]
            assert self.headers.get("Authorization") == "Bearer BEARER-XYZ"
            parsed = urllib.parse.urlparse(self.path)
            path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
            if path == "/api/projects":
                self.assertq(query, "name:secfix-ci-demo")
                self._json(200, {"items": [{
                    "name": "secfix-ci-demo",
                    "_meta": {"href": f"{base}/api/projects/PID"},
                }]})
            elif path == "/api/projects/PID/versions":
                self.assertq(query, "versionName:main")
                self._json(200, {"items": [{
                    "versionName": "main",
                    "_meta": {"href": f"{base}/api/projects/PID/versions/VID"},
                }]})
            elif path == "/api/projects/PID/versions/VID/vulnerable-bom-components":
                self._json(200, {"totalCount": 1, "items": [{
                    "componentName": "PyYAML",
                    "componentVersionName": "5.3",
                    "componentVersionOriginId": "pypi:PyYAML:5.3",
                    "vulnerabilityWithRemediation": {
                        "vulnerabilityName": "CVE-2020-14343",
                        "severity": "CRITICAL",
                        "overallScore": 9.8,
                        "solution": "Upgrade to 5.4 or later",
                    },
                }]})
            else:
                self._json(404, {})

        def assertq(self, query, expected):
            assert query.get("q", [""])[0] == expected, (query, expected)
    return H


# --------------------------------------------------------------------------
# Mock Fortify SSC
# --------------------------------------------------------------------------
def _fortify_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            assert self.headers.get("Authorization") == "FortifyToken FORTIFY-TOKEN"
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if path == "/api/v1/projectVersions":
                self._json(200, {"data": [{
                    "id": 42, "name": "main",
                    "project": {"name": "secfix-ci-demo"},
                }]})
            elif path == "/api/v1/projectVersions/42/issues":
                self._json(200, {"count": 1, "data": [{
                    "id": 100204,
                    "issueInstanceId": "F0RT1FY-SQLI",
                    "category": "SQL Injection",
                    "friority": "Critical",
                    "fullFileName": "sample_app/db.py",
                    "lineNumber": 13,
                }]})
            else:
                self._json(404, {})
    return H


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class BlackDuckClientTests(unittest.TestCase):
    def setUp(self):
        self.holder = {"base": ""}
        self.srv = _serve(_blackduck_handler(self.holder))
        self.holder["base"] = f"http://127.0.0.1:{self.srv.server_port}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_live_fetch_and_normalize(self):
        client = BlackDuckClient(self.holder["base"], "BD-API-TOKEN")
        report = client.fetch("secfix-ci-demo", "main")
        findings = normalize_blackduck(report)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.scanner, "blackduck")
        self.assertEqual(f.component, "PyYAML")
        self.assertEqual(f.cve, "CVE-2020-14343")
        self.assertEqual(f.fixed_version, "5.4")


class FortifyClientTests(unittest.TestCase):
    def setUp(self):
        self.srv = _serve(_fortify_handler())
        self.base = f"http://127.0.0.1:{self.srv.server_port}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_live_fetch_and_normalize(self):
        client = FortifyClient(self.base, "FORTIFY-TOKEN")
        report = client.fetch("secfix-ci-demo", "main")
        findings = normalize_fortify(report)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.scanner, "fortify")
        self.assertEqual(f.category, "SQL Injection")
        self.assertEqual(f.file, "sample_app/db.py")
        self.assertEqual(f.severity, "critical")


class LiveModeCliTests(unittest.TestCase):
    """Full CLI in LIVE mode: fetch from both mock APIs, fix, validate — no PR."""

    def setUp(self):
        self.holder = {"base": ""}
        self.bd = _serve(_blackduck_handler(self.holder))
        self.holder["base"] = f"http://127.0.0.1:{self.bd.server_port}"
        self.ft = _serve(_fortify_handler())
        self.ft_base = f"http://127.0.0.1:{self.ft.server_port}"
        self.tmp = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, "sample_app"),
                        os.path.join(self.tmp, "sample_app"))

    def tearDown(self):
        for s in (self.bd, self.ft):
            s.shutdown(); s.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_live_pipeline_applies_fixes(self):
        import secfix.cli as cli
        env_backup = dict(os.environ)
        os.environ["BD_API_TOKEN"] = "BD-API-TOKEN"
        os.environ["FORTIFY_TOKEN"] = "FORTIFY-TOKEN"
        try:
            rc = cli.run([
                "--root", self.tmp,
                "--blackduck-url", self.holder["base"],
                "--blackduck-project", "secfix-ci-demo",
                "--blackduck-version", "main",
                "--fortify-url", self.ft_base,
                "--fortify-app", "secfix-ci-demo",
                "--fortify-version", "main",
                "--req", "sample_app/requirements.txt",
                "--severities", "critical,high",
            ])
        finally:
            os.environ.clear(); os.environ.update(env_backup)

        self.assertEqual(rc, 0)
        with open(os.path.join(self.tmp, "sample_app/requirements.txt")) as fh:
            self.assertIn("PyYAML==5.4", fh.read())          # SCA fix from live Black Duck
        with open(os.path.join(self.tmp, "sample_app/db.py")) as fh:
            self.assertIn("?", fh.read())                    # SAST fix from live Fortify


if __name__ == "__main__":
    unittest.main()
