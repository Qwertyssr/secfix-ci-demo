"""Black Duck REST client (Software Composition Analysis).

Auth + navigation follow the real Black Duck (Hub) API:
  1. POST /api/tokens/authenticate      (Authorization: token <api-token>)  -> bearerToken
  2. GET  /api/projects?q=name:<p>      -> project, follow _meta.href
  3. GET  <projectHref>/versions?q=versionName:<v>  -> version, follow _meta.href
  4. GET  <versionHref>/vulnerable-bom-components   -> {"items": [...]}

The returned dict matches scan_reports/blackduck.json, so normalize_blackduck
consumes it unchanged.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Optional

_USER_MEDIA = "application/vnd.blackducksoftware.user-4+json"
_PROJECT_MEDIA = "application/vnd.blackducksoftware.project-detail-5+json"
_BOM_MEDIA = "application/vnd.blackducksoftware.bill-of-materials-6+json"


class BlackDuckClient:
    def __init__(self, base_url: str, api_token: str, timeout: int = 30):
        self.base = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self._bearer: Optional[str] = None

    # -- low level ---------------------------------------------------------
    def _request(self, method: str, url: str, accept: str, auth: str) -> dict:
        full = url if url.startswith("http") else f"{self.base}{url}"
        req = urllib.request.Request(full, method=method, headers={
            "Authorization": auth,
            "Accept": accept,
            "User-Agent": "secfix-agent",
        })
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode()
        return json.loads(body) if body else {}

    def authenticate(self) -> str:
        data = self._request(
            "POST", "/api/tokens/authenticate", _USER_MEDIA, f"token {self.api_token}"
        )
        self._bearer = data["bearerToken"]
        return self._bearer

    def _get(self, url: str, accept: str) -> dict:
        if not self._bearer:
            self.authenticate()
        return self._request("GET", url, accept, f"Bearer {self._bearer}")

    @staticmethod
    def _href(item: dict) -> str:
        return item.get("_meta", {}).get("href", "")

    def _find(self, items: list, key: str, value: str) -> dict:
        for it in items:
            if it.get(key) == value:
                return it
        return items[0] if items else {}

    # -- high level --------------------------------------------------------
    def fetch(self, project: str, version: str, limit: int = 500) -> dict:
        """Return {"items": [...]} of vulnerable BOM components."""
        q = urllib.parse.quote(f"name:{project}")
        projects = self._get(f"/api/projects?q={q}", _PROJECT_MEDIA).get("items", [])
        proj = self._find(projects, "name", project)
        if not proj:
            return {"items": []}

        qv = urllib.parse.quote(f"versionName:{version}")
        versions = self._get(f"{self._href(proj)}/versions?q={qv}", _PROJECT_MEDIA).get("items", [])
        ver = self._find(versions, "versionName", version)
        if not ver:
            return {"items": []}

        return self._get(
            f"{self._href(ver)}/vulnerable-bom-components?limit={limit}", _BOM_MEDIA
        )
