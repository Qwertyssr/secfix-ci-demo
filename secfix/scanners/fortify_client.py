"""Fortify Software Security Center (SSC) REST client (SAST).

Follows the real SSC API:
  Authorization: FortifyToken <token>
  1. GET /api/v1/projectVersions?q=name:<version>   -> match project+version -> id
  2. GET /api/v1/projectVersions/<id>/issues         -> {"data": [...]}

The returned dict matches scan_reports/fortify.json, so normalize_fortify
consumes it unchanged.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request


class FortifyClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            f"{self.base}{path}",
            method="GET",
            headers={
                "Authorization": f"FortifyToken {self.token}",
                "Accept": "application/json",
                "User-Agent": "secfix-agent",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode()
        return json.loads(body) if body else {}

    def _resolve_version_id(self, app: str, version: str) -> int | None:
        q = urllib.parse.quote(f"name:{version}")
        data = self._get(f"/api/v1/projectVersions?q={q}&limit=200").get("data", [])
        for pv in data:
            proj_name = (pv.get("project") or {}).get("name")
            if proj_name == app and pv.get("name") == version:
                return pv.get("id")
        # fall back to a version-name match if the project name differs
        for pv in data:
            if pv.get("name") == version:
                return pv.get("id")
        return data[0]["id"] if data else None

    def fetch(self, app: str, version: str, limit: int = 200) -> dict:
        """Return {"data": [...]} of issues for the application version."""
        pvid = self._resolve_version_id(app, version)
        if pvid is None:
            return {"data": []}
        return self._get(
            f"/api/v1/projectVersions/{pvid}/issues?limit={limit}&showhidden=false"
        )
