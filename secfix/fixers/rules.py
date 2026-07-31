"""Deterministic, template-based SAST fixer.

Handles well-understood vulnerability categories with mechanical, behaviour-
preserving transformations. Used as the default engine and as the trusted
fallback when the AI provider is disabled or produces an unverifiable patch.
"""
from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from ..models import Finding
from . import Patch


# --- individual transformations -------------------------------------------------

def _fix_weak_hash(src: str) -> Tuple[str, bool]:
    new = src
    # Python: hashlib.md5(/sha1( -> hashlib.sha256(
    new = re.sub(r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", new)
    # JavaScript/Node: crypto.createHash('md5'|'sha1') -> 'sha256'
    new = re.sub(r"(createHash\(\s*['\"])(md5|sha1)(['\"])", r"\1sha256\3", new, flags=re.IGNORECASE)
    # Java: MessageDigest.getInstance("MD5"|"SHA-1"|"SHA1") -> "SHA-256"
    new = re.sub(r'(getInstance\(\s*")(MD5|SHA-?1)(")', r"\1SHA-256\3", new, flags=re.IGNORECASE)
    # Go: crypto/md5 | crypto/sha1 import + md5.Sum/New -> sha256
    new = re.sub(r'"crypto/(md5|sha1)"', '"crypto/sha256"', new)
    new = re.sub(r"\b(md5|sha1)\.Sum\(", "sha256.Sum256(", new)
    new = re.sub(r"\b(md5|sha1)\.New\(", "sha256.New(", new)
    return new, new != src


def _fix_insecure_yaml(src: str) -> Tuple[str, bool]:
    new = src.replace("yaml.load(", "yaml.safe_load(")
    new = re.sub(r",\s*Loader\s*=\s*yaml\.\w+", "", new)
    return new, new != src


def _fix_command_injection(src: str) -> Tuple[str, bool]:
    changed = False

    # 1) turn:  cmd = "a b c " + var   into a token list:  cmd = ["a", "b", "c", var]
    def repl_assign(m: re.Match) -> str:
        nonlocal changed
        changed = True
        indent, var, literal, expr = m.group("indent"), m.group("var"), m.group("lit"), m.group("expr")
        tokens = [f'"{t}"' for t in literal.split()]
        tokens.append(expr.strip())
        return f'{indent}{var} = [{", ".join(tokens)}]'

    src = re.sub(
        r'(?P<indent>[ \t]*)(?P<var>\w+)\s*=\s*"(?P<lit>[^"]*)"\s*\+\s*(?P<expr>[A-Za-z_][\w.]*)',
        repl_assign,
        src,
    )
    # 2) drop the dangerous shell=True
    new = re.sub(r",\s*shell\s*=\s*True", "", src)
    if new != src:
        changed = True
    return new, changed


def _fix_sql_injection(src: str) -> Tuple[str, bool]:
    # execute("... '" + var + "'")  ->  execute("... ?", (var,))
    pattern = re.compile(
        r'execute\(\s*"(?P<prefix>[^"]*?)\'"\s*\+\s*(?P<var>[A-Za-z_][\w.]*)\s*\+\s*"\'"\s*\)'
    )

    def repl(m: re.Match) -> str:
        return f'execute("{m.group("prefix")}?", ({m.group("var")},))'

    new = pattern.sub(repl, src)
    return new, new != src


_HANDLERS = {
    "weak cryptographic hash": _fix_weak_hash,
    "insecure deserialization": _fix_insecure_yaml,
    "command injection": _fix_command_injection,
    "sql injection": _fix_sql_injection,
}

# Patterns proving a category is still present (used to verify the fix worked).
_RESIDUE = {
    "weak cryptographic hash": re.compile(
        r"hashlib\.(md5|sha1)\("
        r"|createHash\(\s*['\"](md5|sha1)"
        r"|getInstance\(\s*\"(MD5|SHA-?1)\""
        r"|crypto/(md5|sha1)\""
        r"|\b(md5|sha1)\.(Sum|New)\(",
        re.IGNORECASE,
    ),
    "insecure deserialization": re.compile(r"yaml\.load\("),
    "command injection": re.compile(r"shell\s*=\s*True\s*\)"),
    "sql injection": re.compile(r'execute\(\s*"[^"]*"\s*\+'),
}


def can_handle(finding: Finding) -> bool:
    return (finding.category or "").strip().lower() in _HANDLERS


def fix_code(app_dir: str, finding: Finding) -> Optional[Patch]:
    if not finding.file or not can_handle(finding):
        return None
    path = os.path.join(app_dir, finding.file)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()

    handler = _HANDLERS[finding.category.strip().lower()]
    new_content, changed = handler(original)
    if not changed:
        return None

    return Patch(
        finding=finding,
        summary=f"fix {finding.category} in {finding.file}",
        files={finding.file: new_content},
        provider="rule",
    )


def residue_present(content: str, finding: Finding) -> bool:
    """True if the vulnerability pattern is still present after a fix."""
    rx = _RESIDUE.get((finding.category or "").strip().lower())
    return bool(rx.search(content)) if rx else False
