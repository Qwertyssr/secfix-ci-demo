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

    Return the COMPLETE corrected contents of the file, nothing else — no
    markdown fences, no explanation.

    ----- CURRENT FILE -----
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
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:] if lines else lines
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text


def fix_code(app_dir: str, finding: Finding) -> Optional[Patch]:
    if not finding.file or not available():
        return None
    path = os.path.join(app_dir, finding.file)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()

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
        content=original,
    )
    resp = model.generate_content(prompt)
    new_content = _strip_fences(resp.text)
    if not new_content or new_content == original:
        return None

    return Patch(
        finding=finding,
        summary=f"AI fix for {finding.category} in {finding.file}",
        files={finding.file: new_content},
        provider="vertex",
    )
