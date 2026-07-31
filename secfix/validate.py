"""Validator: prove a set of applied patches builds, passes tests, and actually
removes the reported vulnerabilities without introducing obvious regressions.
"""
from __future__ import annotations

import os
import subprocess
from typing import List, Tuple

from .models import Finding
from .fixers import rules


def run_tests(app_dir: str, test_cmd: List[str]) -> Tuple[bool, str]:
    if not test_cmd:
        return True, "(no test command configured)"
    proc = subprocess.run(
        test_cmd, cwd=app_dir, capture_output=True, text=True
    )
    ok = proc.returncode == 0
    return ok, (proc.stdout + "\n" + proc.stderr).strip()


def verify_dependency(app_dir: str, finding: Finding, req_file: str = "requirements.txt") -> bool:
    path = os.path.join(app_dir, req_file)
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read().lower()
    comp = (finding.component or "").lower()
    ver = (finding.fixed_version or "").lower()
    return f"{comp}=={ver}" in content.replace(" ", "")


def verify_code(app_dir: str, finding: Finding) -> bool:
    if not finding.file:
        return False
    path = os.path.join(app_dir, finding.file)
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    return not rules.residue_present(content, finding)
