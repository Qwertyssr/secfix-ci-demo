"""AI-assisted SAST fixer backed by Google Vertex AI (Gemini).

This provider is OPTIONAL and used for code findings that the deterministic rule
engine cannot handle. It is enabled only when:
  * SECFIX_LLM_PROVIDER=vertex, and
  * GOOGLE_APPLICATION_CREDENTIALS points at a service-account JSON, and
  * GOOGLE_CLOUD_PROJECT / VERTEX_LOCATION are set.

Credentials are read from the environment at runtime — never hard-coded. In CI,
store the service-account JSON as an encrypted secret and write it to a temp file
that GOOGLE_APPLICATION_CREDENTIALS references (see .github/workflows).

Every AI patch is still validated downstream (build + tests + residue re-check);
the model's output is never trusted blindly.
"""
from __future__ import annotations

import os
import textwrap
from typing import Optional

from ..models import Finding
from . import Patch

_PROMPT = textwrap.dedent(
    """\
    You are a secure-coding assistant. Fix ONLY the security vulnerability below
    and change as little as possible. Preserve all existing behaviour, public
    function signatures, and formatting. Do not add commentary.

    Vulnerability category: {category}
    File: {file}
    Reported line: {line}

    Return the COMPLETE corrected snippet below, nothing else — no
    markdown fences, no explanation.

    ----- CURRENT SNIPPET: lines {start_line}-{end_line} -----
    {content}
    """
)


def available() -> bool:
    return (
        os.getenv("SECFIX_LLM_PROVIDER", "").lower() == "vertex"
        and bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
        and bool(os.getenv("GOOGLE_CLOUD_PROJECT"))
    )


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = lines[1:] if lines else lines
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines)
    return text


def _context_window(content: str, line: int | None, radius: int = 20) -> tuple[int, int, str]:
    lines = content.splitlines(keepends=True)
    if not lines:
        return 1, 1, ""
    reported = max(1, min(line or 1, len(lines)))
    start = max(1, reported - radius)
    end = min(len(lines), reported + radius)
    return start, end, "".join(lines[start - 1:end])


def _replace_window(content: str, start: int, end: int, replacement: str) -> str:
    lines = content.splitlines(keepends=True)
    replacement_lines = replacement.splitlines(keepends=True)
    if replacement and not replacement.endswith(("\n", "\r")) and end < len(lines):
        replacement_lines[-1] += "\n"
    return "".join(lines[:start - 1] + replacement_lines + lines[end:])


def fix_code(app_dir: str, finding: Finding) -> Optional[Patch]:
    if not finding.file or not available():
        return None
    path = os.path.join(app_dir, finding.file)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()
    start_line, end_line, snippet = _context_window(original, finding.line)

    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel
    except ImportError:
        # SDK not installed in this environment; caller falls back to rules.
        return None

    vertexai.init(
        project=os.environ["GOOGLE_CLOUD_PROJECT"],
        location=os.getenv("VERTEX_LOCATION", "us-central1"),
    )
    model = GenerativeModel(os.getenv("VERTEX_MODEL", "gemini-1.5-pro"))
    prompt = _PROMPT.format(
        category=finding.category,
        file=finding.file,
        line=finding.line,
        start_line=start_line,
        end_line=end_line,
        content=snippet,
    )
    resp = model.generate_content(prompt)
    new_snippet = _strip_fences(resp.text)
    if not new_snippet or new_snippet == snippet:
        return None
    new_content = _replace_window(original, start_line, end_line, new_snippet)

    return Patch(
        finding=finding,
        summary=f"AI fix for {finding.category} in {finding.file}",
        files={finding.file: new_content},
        provider="vertex",
    )
