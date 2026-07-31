"""Dependency (SCA) fixer: bump vulnerable versions in requirements.txt."""
from __future__ import annotations

import os
import re
from typing import List, Optional

from ..models import Finding
from . import Patch

# Matches: name==version  (optionally with extras / spaces)
_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[^\s;#]+)(?P<rest>.*)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _ver_key(v: str) -> tuple:
    """Coarse version sort key: numeric groups only (e.g. '2.10.1' -> (2,10,1))."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def bump_requirements(app_dir: str, findings: List[Finding], req_file: str = "requirements.txt") -> Optional[Patch]:
    """Return a single Patch bumping every fixable dependency finding.

    All dependency findings are grouped into one requirements.txt patch so the
    reviewer sees one coherent change.
    """
    path = os.path.join(app_dir, req_file)
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()

    wanted = {}
    for f in findings:
        if f.type == "dependency_vuln" and f.component and f.fixed_version:
            key = _normalize(f.component)
            prev = wanted.get(key)
            # when a component has multiple CVEs, target the highest fixed version
            if prev is None or _ver_key(f.fixed_version) > _ver_key(prev.fixed_version):
                wanted[key] = f

    if not wanted:
        return None

    changed: List[Finding] = []
    out_lines: List[str] = []
    for line in original.splitlines():
        m = _REQ_RE.match(line.strip())
        if m and _normalize(m.group("name")) in wanted:
            f = wanted[_normalize(m.group("name"))]
            new_line = f"{m.group('name')}=={f.fixed_version}{m.group('rest')}"
            out_lines.append(new_line)
            changed.append(f)
        else:
            out_lines.append(line)

    if not changed:
        return None

    new_content = "\n".join(out_lines)
    if original.endswith("\n"):
        new_content += "\n"

    bumps = ", ".join(f"{f.component} {f.current_version}->{f.fixed_version} ({f.cve})" for f in changed)
    rel = os.path.relpath(path, app_dir).replace(os.sep, "/")
    patch = Patch(
        finding=changed[0],
        summary=f"bump {len(changed)} vulnerable dependencies: {bumps}",
        files={rel: new_content},
        provider="deps",
    )
    patch.extra_findings = changed  # type: ignore[attr-defined]
    return patch
