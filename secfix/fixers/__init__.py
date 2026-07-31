"""Fix strategy engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..models import Finding


@dataclass
class Patch:
    """A concrete change proposal for a single finding."""
    finding: Finding
    summary: str
    files: Dict[str, str] = field(default_factory=dict)  # path -> new full content
    provider: str = "rule"                               # rule | vertex | deps

    def touched(self) -> List[str]:
        return sorted(self.files.keys())
