"""Collect findings from either the live scanner APIs or committed JSON files.

Live mode is selected per-scanner when a base URL is provided (flag or env):
  Black Duck: --blackduck-url / $BD_URL      + token $BD_API_TOKEN
  Fortify:    --fortify-url   / $SSC_URL      + token $FORTIFY_TOKEN
Otherwise the corresponding --blackduck / --fortify JSON file is read.
"""
from __future__ import annotations

import json
import os
from typing import List

from ..models import Finding
from ..normalize import normalize_blackduck, normalize_fortify
from .blackduck_client import BlackDuckClient
from .fortify_client import FortifyClient


def collect_findings(args) -> List[Finding]:
    findings: List[Finding] = []

    # --- Black Duck ---
    bd_url = getattr(args, "blackduck_url", "") or os.getenv("BD_URL", "")
    if bd_url:
        token = os.environ["BD_API_TOKEN"]
        client = BlackDuckClient(bd_url, token)
        report = client.fetch(args.blackduck_project, args.blackduck_version)
        findings += normalize_blackduck(report)
        print(f"  [blackduck] live fetch: {bd_url} "
              f"({args.blackduck_project}/{args.blackduck_version}) -> {len(report.get('items', []))} components")
    elif getattr(args, "blackduck", None):
        with open(args.blackduck, encoding="utf-8") as fh:
            findings += normalize_blackduck(json.load(fh))

    # --- Fortify ---
    ssc_url = getattr(args, "fortify_url", "") or os.getenv("SSC_URL", "")
    if ssc_url:
        token = os.environ["FORTIFY_TOKEN"]
        client = FortifyClient(ssc_url, token)
        report = client.fetch(args.fortify_app, args.fortify_version)
        findings += normalize_fortify(report)
        print(f"  [fortify] live fetch: {ssc_url} "
              f"({args.fortify_app}/{args.fortify_version}) -> {len(report.get('data', []))} issues")
    elif getattr(args, "fortify", None):
        with open(args.fortify, encoding="utf-8") as fh:
            findings += normalize_fortify(json.load(fh))

    return findings
