"""Validator: prove a set of applied patches builds, passes tests, and actually
removes the reported vulnerabilities without introducing obvious regressions.
"""
from __future__ import annotations

import os
import re
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


def _read(app_dir: str, rel: str) -> str | None:
    path = os.path.join(app_dir, rel)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def verify_dependency(app_dir: str, finding: Finding, req_file: str = "requirements.txt") -> bool:
    """Confirm the fixed version is now pinned in the correct manifest."""
    comp = (finding.component or "").strip()
    ver = (finding.fixed_version or "").strip()
    if not comp or not ver:
        return False
    eco = finding.ecosystem or "python"

    if eco == "python":
        content = _read(app_dir, req_file)
        return bool(content) and f"{comp}=={ver}".lower().replace(" ", "") in content.lower().replace(" ", "")
    if eco == "npm":
        content = _read(app_dir, "package.json")
        return bool(content) and re.search(rf'"{re.escape(comp)}"\s*:\s*"[\^~]?{re.escape(ver)}"', content) is not None
    if eco == "maven":
        content = _read(app_dir, "pom.xml")
        return bool(content) and re.search(
            rf"<artifactId>\s*{re.escape(comp)}\s*</artifactId>\s*<version>\s*{re.escape(ver)}\s*</version>", content
        ) is not None
    if eco == "go":
        content = _read(app_dir, "go.mod")
        return bool(content) and re.search(rf"{re.escape(comp)}\s+v?{re.escape(ver)}\b", content) is not None
    return False


def verify_code(app_dir: str, finding: Finding) -> bool:
    if not finding.file:
        return False
    content = _read(app_dir, finding.file)
    if content is None:
        return False
    return not rules.residue_present(content, finding)
