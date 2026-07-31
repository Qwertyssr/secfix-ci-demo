"""GitHub Pull Request publishing (zero third-party deps; uses urllib).

Git branch/commit/push live in secfix.git_ops (shared with the GitLab publisher).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List, Optional


def open_pull_request(
    repo: str,
    base: str,
    head: str,
    title: str,
    body: str,
    token: str,
    labels: Optional[List[str]] = None,
    api_url: str = "https://api.github.com",
) -> dict:
    """Create a PR via the GitHub REST API. `repo` is 'owner/name'."""
    payload = json.dumps({"title": title, "head": head, "base": base, "body": body}).encode()
    req = urllib.request.Request(
        f"{api_url}/repos/{repo}/pulls",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "secfix-agent",
        },
    )
    with urllib.request.urlopen(req) as resp:
        pr = json.loads(resp.read().decode())

    if labels:
        lbl = json.dumps({"labels": labels}).encode()
        lreq = urllib.request.Request(
            f"{api_url}/repos/{repo}/issues/{pr['number']}/labels",
            data=lbl,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "secfix-agent",
            },
        )
        try:
            urllib.request.urlopen(lreq).close()
        except urllib.error.HTTPError:
            pass  # labels are best-effort
    return pr
