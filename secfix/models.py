"""Common finding model shared by all scanner adapters."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass
class Finding:
    scanner: str                       # blackduck | fortify
    type: str                          # dependency_vuln | code_vuln
    severity: str                      # critical | high | medium | low
    title: str
    cve: Optional[str] = None
    category: Optional[str] = None     # SAST category, e.g. "SQL Injection"
    file: Optional[str] = None
    line: Optional[int] = None
    component: Optional[str] = None     # e.g. "PyYAML"
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    raw_ref: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.lower(), 4)

    def fingerprint(self) -> str:
        key = "|".join([
            self.scanner,
            self.type,
            (self.cve or ""),
            (self.category or ""),
            (self.component or ""),
            (self.file or ""),
        ])
        return "sha256:" + hashlib.sha256(key.encode()).hexdigest()[:16]

    def label(self) -> str:
        if self.type == "dependency_vuln":
            return f"{self.component} {self.cve}"
        return f"{self.category} ({self.file}:{self.line})"
