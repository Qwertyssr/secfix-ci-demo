"""Dependency (SCA) fixer: bump vulnerable versions across ecosystems.

Supported manifests: requirements.txt (python), package.json (npm),
pom.xml (maven), go.mod (go). Routing is driven by Finding.ecosystem (from the
Black Duck origin id); the requirements bumper also matches ecosystem-less
findings for backward compatibility.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from ..models import Finding
from . import Patch

# Matches: name==version  (optionally with extras / spaces)
_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[^\s;#]+)(?P<rest>.*)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _ver_key(v: str) -> tuple:
    """Coarse version sort key: numeric groups only (e.g. '2.10.1' -> (2,10,1))."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _same_version(actual: str | None, reported: str | None) -> bool:
    if not actual or not reported:
        return False
    actual = actual.strip()
    if actual[:1] in "^~":
        actual = actual[1:]
    actual = actual[1:] if actual.startswith("v") else actual
    reported = reported.strip()
    reported = reported[1:] if reported.startswith("v") else reported
    return actual == reported


def _highest(findings: List[Finding]) -> List[Finding]:
    """De-duplicate by component, keeping the highest fixed version."""
    best: Dict[str, Finding] = {}
    for f in findings:
        if not (f.component and f.fixed_version):
            continue
        k = f.component
        if k not in best or _ver_key(f.fixed_version) > _ver_key(best[k].fixed_version):
            best[k] = f
    return list(best.values())


# --- per-ecosystem content bumpers: (content, findings) -> (new_content, changed) ---

def _bump_requirements_content(content: str, findings: List[Finding]) -> Tuple[str, List[Finding]]:
    wanted = {_normalize(f.component): f for f in _highest(findings)}
    changed: List[Finding] = []
    out_lines: List[str] = []
    for line in content.splitlines():
        m = _REQ_RE.match(line.strip())
        f = wanted.get(_normalize(m.group("name"))) if m else None
        if f and _same_version(m.group("version"), f.current_version):
            out_lines.append(f"{m.group('name')}=={f.fixed_version}{m.group('rest')}")
            changed.append(f)
        else:
            out_lines.append(line)
    new_content = "\n".join(out_lines)
    if content.endswith("\n"):
        new_content += "\n"
    return new_content, changed


def _bump_package_json_content(content: str, findings: List[Finding]) -> Tuple[str, List[Finding]]:
    data = json.loads(content)
    wanted = {f.component: f for f in _highest(findings)}
    changed: List[Finding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in list(deps.items()):
            f = wanted.get(name)
            if f and _same_version(spec, f.current_version):
                prefix = spec[0] if isinstance(spec, str) and spec[:1] in "^~" else ""
                deps[name] = prefix + f.fixed_version
                changed.append(f)
    new_content = json.dumps(data, indent=2) + "\n"
    return new_content, changed


def _bump_pom_content(content: str, findings: List[Finding]) -> Tuple[str, List[Finding]]:
    changed: List[Finding] = []
    new_content = content
    for f in _highest(findings):
        art = re.escape(f.component)  # matched on <artifactId>
        rx = re.compile(
            r"(<artifactId>\s*" + art + r"\s*</artifactId>\s*<version>)([^<]*)(</version>)"
        )

        did_change = False

        def replace(match: re.Match) -> str:
            nonlocal did_change
            if not _same_version(match.group(2), f.current_version):
                return match.group(0)
            did_change = True
            return match.group(1) + f.fixed_version + match.group(3)

        new_content = rx.sub(replace, new_content)
        if did_change:
            changed.append(f)
    return new_content, changed


def _bump_gomod_content(content: str, findings: List[Finding]) -> Tuple[str, List[Finding]]:
    wanted = {f.component: f for f in _highest(findings)}
    changed: List[Finding] = []
    out_lines: List[str] = []
    for line in content.splitlines():
        m = re.match(r"^(?P<indent>\s*)(?P<mod>\S+)\s+(?P<ver>v?\S+)(?P<rest>.*)$", line)
        f = wanted.get(m.group("mod")) if m else None
        if f and _same_version(m.group("ver"), f.current_version):
            prefix = "v" if m.group("ver").startswith("v") else ""
            out_lines.append(f"{m.group('indent')}{m.group('mod')} {prefix}{f.fixed_version}{m.group('rest')}")
            changed.append(f)
        else:
            out_lines.append(line)
    new_content = "\n".join(out_lines)
    if content.endswith("\n"):
        new_content += "\n"
    return new_content, changed


# manifest (relative to root) + bumper, per ecosystem
_ECO_MANIFEST = {
    "npm": ("package.json", _bump_package_json_content),
    "maven": ("pom.xml", _bump_pom_content),
    "go": ("go.mod", _bump_gomod_content),
}


def _read(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def apply_dependency_fixes(root: str, findings: List[Finding],
                           req_file: str = "requirements.txt") -> Optional[Patch]:
    """Bump vulnerable dependencies across every supported manifest present.

    Groups findings by ecosystem, edits each manifest, and returns ONE patch
    spanning all changed files so the reviewer sees a single coherent change.
    """
    deps = [f for f in findings if f.type == "dependency_vuln" and f.component and f.fixed_version]
    if not deps:
        return None

    files: Dict[str, str] = {}
    changed_all: List[Finding] = []

    def run(rel: str, subset: List[Finding], bumper) -> None:
        if not subset:
            return
        content = _read(os.path.join(root, rel))
        if content is None:
            return
        new_content, changed = bumper(content, subset)
        if changed:
            files[rel] = new_content
            changed_all.extend(changed)

    # python / requirements — also handles ecosystem-less findings (legacy)
    run(req_file, [f for f in deps if f.ecosystem in ("python", None)], _bump_requirements_content)
    for eco, (rel, bumper) in _ECO_MANIFEST.items():
        run(rel, [f for f in deps if f.ecosystem == eco], bumper)

    if not changed_all:
        return None

    bumps = ", ".join(f"{f.component} {f.current_version}->{f.fixed_version} ({f.cve})" for f in changed_all)
    patch = Patch(
        finding=changed_all[0],
        summary=f"bump {len(changed_all)} vulnerable dependencies across {len(files)} manifest(s): {bumps}",
        files=files,
        provider="deps",
    )
    patch.extra_findings = changed_all  # type: ignore[attr-defined]
    return patch


def bump_requirements(app_dir: str, findings: List[Finding],
                      req_file: str = "requirements.txt") -> Optional[Patch]:
    """Backward-compatible requirements.txt-only bumper (returns a Patch)."""
    content = _read(os.path.join(app_dir, req_file))
    if content is None:
        return None
    new_content, changed = _bump_requirements_content(
        content, [f for f in findings if f.type == "dependency_vuln"]
    )
    if not changed:
        return None
    bumps = ", ".join(f"{f.component} {f.current_version}->{f.fixed_version} ({f.cve})" for f in changed)
    patch = Patch(
        finding=changed[0],
        summary=f"bump {len(changed)} vulnerable dependencies: {bumps}",
        files={req_file: new_content},
        provider="deps",
    )
    patch.extra_findings = changed  # type: ignore[attr-defined]
    return patch
