"""GitLab Merge Request publishing (zero third-party deps; git CLI + urllib).

Mirrors github_pr.open_pull_request but targets the GitLab REST API:
  POST {api}/projects/{id}/merge_requests
See https://docs.gitlab.com/api/merge_requests/#create-a-merge-request
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import List, Optional


def open_merge_request(
    project: str,
    source_branch: str,
    target_branch: str,
    title: str,
    body: str,
    token: str,
    labels: Optional[List[str]] = None,
    api_url: str = "https://gitlab.com/api/v4",
) -> dict:
    """Create a merge request. `project` is a numeric id or 'group/name' path."""
    pid = urllib.parse.quote(str(project), safe="")
    payload = {
        "source_branch": source_branch,
        "target_branch": target_branch,
        "title": title,
        "description": body,
        "remove_source_branch": True,
    }
    if labels:
        payload["labels"] = ",".join(labels)

    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/projects/{pid}/merge_requests",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
            "User-Agent": "secfix-agent",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())
