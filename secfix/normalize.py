"""Scanner adapters: convert raw scanner JSON into the common Finding model.

Each adapter isolates the scanner-specific shape so everything downstream is
scanner-agnostic. To wire a *real* scanner, keep the function signature and map
the live API response here (see docs/REUSE.md).
"""
from __future__ import annotations

import json
import re
from typing import List

from .models import Finding

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:[.-]?[a-zA-Z0-9]+)?)")


def _parse_fixed_version(solution: str | None) -> str | None:
    """Pull the first version-looking token out of a remediation string."""
    if not solution:
        return None
    m = _VERSION_RE.search(solution)
    return m.group(1) if m else None


def normalize_blackduck(report: dict) -> List[Finding]:
    findings: List[Finding] = []
    for item in report.get("items", []):
        vr = item.get("vulnerabilityWithRemediation", {})
        findings.append(
            Finding(
                scanner="blackduck",
                type="dependency_vuln",
                severity=vr.get("severity", "unknown").lower(),
                title=f'{item.get("componentName")} {vr.get("vulnerabilityName")}',
                cve=vr.get("vulnerabilityName"),
                component=item.get("componentName"),
                current_version=item.get("componentVersionName"),
                fixed_version=_parse_fixed_version(vr.get("solution")),
                raw_ref=item.get("componentVersionOriginId"),
                extra={"cvss": vr.get("overallScore")},
            )
        )
    return findings


def normalize_fortify(report: dict) -> List[Finding]:
    findings: List[Finding] = []
    for issue in report.get("data", []):
        findings.append(
            Finding(
                scanner="fortify",
                type="code_vuln",
                severity=str(issue.get("friority", "unknown")).lower(),
                title=issue.get("category", "Unknown issue"),
                category=issue.get("category"),
                file=issue.get("fullFileName"),
                line=issue.get("lineNumber"),
                raw_ref=str(issue.get("issueInstanceId")),
            )
        )
    return findings


def load_reports(blackduck_path: str | None, fortify_path: str | None) -> List[Finding]:
    findings: List[Finding] = []
    if blackduck_path:
        with open(blackduck_path, "r", encoding="utf-8") as fh:
            findings += normalize_blackduck(json.load(fh))
    if fortify_path:
        with open(fortify_path, "r", encoding="utf-8") as fh:
            findings += normalize_fortify(json.load(fh))
    return findings
