"""Code-fix orchestrator: choose AI provider or deterministic rules, then verify.

Order of preference per finding:
  1. Vertex AI provider (if enabled) — for complex/unknown cases.
  2. Deterministic rule engine — trusted templates.
The chosen patch must clear the vulnerability's residue pattern; otherwise we
fall back to the rule engine, and if that also fails we return None (escalate).
"""
from __future__ import annotations

from typing import Optional

from ..models import Finding
from . import Patch
from . import rules, sast


def fix_code_finding(app_dir: str, finding: Finding) -> Optional[Patch]:
    # 1. Try the AI provider first (only active when configured).
    ai_patch = sast.fix_code(app_dir, finding)
    if ai_patch:
        content = ai_patch.files[finding.file]
        if not rules.residue_present(content, finding):
            return ai_patch  # verified

    # 2. Deterministic templates.
    rule_patch = rules.fix_code(app_dir, finding)
    if rule_patch:
        content = rule_patch.files[finding.file]
        if not rules.residue_present(content, finding):
            return rule_patch

    return None  # escalate to a human
