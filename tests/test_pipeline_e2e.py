"""End-to-end pipeline simulation.

Reproduces what .github/workflows/security-fix.yml does on a runner, but locally:
  1. build a git repo with the demo files + a bare 'origin' remote
  2. stand up a mock GitHub REST API (honours GITHUB_API_URL)
  3. run `python -m secfix --open-pr` exactly as the workflow does
  4. assert: fixes applied, branch pushed to origin, PR POSTed with correct body

This proves the whole CI mechanism works without a real GitHub Actions runner.
Run:  py -m unittest tests.test_pipeline_e2e -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable if " " not in sys.executable else "python"


class _Captured:
    pulls = []
    labels = []
    mrs = []


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path.endswith("/merge_requests"):
                _Captured.mrs.append({"path": self.path, "body": body,
                                      "token": self.headers.get("PRIVATE-TOKEN")})
                self._send(201, {"iid": 1, "web_url": "https://gitlab.test/group/name/-/merge_requests/1"})
            elif self.path.endswith("/pulls"):
                _Captured.pulls.append({"path": self.path, "body": body,
                                        "auth": self.headers.get("Authorization")})
                resp = {"number": 1, "html_url": "https://github.test/owner/name/pull/1"}
                self._send(201, resp)
            elif self.path.endswith("/labels"):
                _Captured.labels.append(body)
                self._send(200, {})
            else:
                self._send(404, {})

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return Handler


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


class PipelineE2E(unittest.TestCase):
    def setUp(self):
        _Captured.pulls.clear()
        _Captured.labels.clear()
        _Captured.mrs.clear()
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        # copy the demo files a real checkout would contain
        for item in ("sample_app", "secfix", "scan_reports"):
            shutil.copytree(os.path.join(ROOT, item), os.path.join(self.repo, item))

        # init git repo + baseline commit on main
        _git(self.repo, "-c", "init.defaultBranch=main", "init")
        _git(self.repo, "config", "user.name", "tester")
        _git(self.repo, "config", "user.email", "tester@example.com")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-m", "baseline")

        # bare 'origin' the agent will push to
        self.origin = os.path.join(self.tmp, "origin.git")
        _git(self.tmp, "init", "--bare", self.origin)
        _git(self.repo, "remote", "add", "origin", self.origin)
        _git(self.repo, "push", "-u", "origin", "main")

        # mock GitHub API
        self.server = HTTPServer(("127.0.0.1", 0), _make_handler())
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_pipeline_opens_pr(self):
        env = dict(os.environ)
        env["GITHUB_TOKEN"] = "fake-token"
        env["GITHUB_API_URL"] = f"http://127.0.0.1:{self.port}"
        env["PYTHONPATH"] = self.repo

        proc = subprocess.run(
            [PY, "-m", "secfix",
             "--root", ".",
             "--blackduck", "scan_reports/blackduck.json",
             "--fortify", "scan_reports/fortify.json",
             "--req", "sample_app/requirements.txt",
             "--severities", "critical,high",
             "--test-cmd", f"{PY} -m unittest discover -s sample_app/tests",
             "--base", "main",
             "--repo", "owner/name",
             "--pr-body-out", "pr-body.md",
             "--open-pr"],
            cwd=self.repo, env=env, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("Opened PR #1", proc.stdout)

        # 1) fixes were applied in the working tree
        with open(os.path.join(self.repo, "sample_app/requirements.txt")) as fh:
            self.assertIn("PyYAML==5.4", fh.read())
        with open(os.path.join(self.repo, "sample_app/auth.py")) as fh:
            self.assertIn("hashlib.sha256", fh.read())

        # 2) a secfix/* branch was pushed to origin
        refs = subprocess.run(["git", "ls-remote", "--heads", self.origin],
                              capture_output=True, text=True).stdout
        self.assertIn("refs/heads/secfix/auto-", refs)

        # 3) the PR was POSTed with the right base/head + auth + body
        self.assertEqual(len(_Captured.pulls), 1)
        pr = _Captured.pulls[0]
        self.assertEqual(pr["path"], "/repos/owner/name/pulls")
        self.assertEqual(pr["body"]["base"], "main")
        self.assertTrue(pr["body"]["head"].startswith("secfix/auto-"))
        self.assertIn("Automated security fixes", pr["body"]["body"])
        self.assertEqual(pr["auth"], "Bearer fake-token")

        # 4) labels applied
        self.assertIn("security", _Captured.labels[0]["labels"])

    def test_full_pipeline_opens_merge_request(self):
        env = dict(os.environ)
        env["GITLAB_TOKEN"] = "glpat-fake"
        env["PYTHONPATH"] = self.repo

        proc = subprocess.run(
            [PY, "-m", "secfix",
             "--root", ".",
             "--blackduck", "scan_reports/blackduck.json",
             "--fortify", "scan_reports/fortify.json",
             "--req", "sample_app/requirements.txt",
             "--severities", "critical,high",
             "--test-cmd", f"{PY} -m unittest discover -s sample_app/tests",
             "--base", "main",
             "--provider", "gitlab",
             "--project", "group/name",
             "--gitlab-url", f"http://127.0.0.1:{self.port}",
             "--open-pr"],
            cwd=self.repo, env=env, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("Opened MR !1", proc.stdout)

        # branch pushed to origin
        refs = subprocess.run(["git", "ls-remote", "--heads", self.origin],
                              capture_output=True, text=True).stdout
        self.assertIn("refs/heads/secfix/auto-", refs)

        # MR POSTed to the GitLab API with the right project/branches/token
        self.assertEqual(len(_Captured.mrs), 1)
        mr = _Captured.mrs[0]
        self.assertEqual(mr["path"], "/api/v4/projects/group%2Fname/merge_requests")
        self.assertEqual(mr["body"]["target_branch"], "main")
        self.assertTrue(mr["body"]["source_branch"].startswith("secfix/auto-"))
        self.assertIn("security", mr["body"]["labels"])
        self.assertEqual(mr["token"], "glpat-fake")


if __name__ == "__main__":
    unittest.main()
