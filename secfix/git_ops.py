"""Generic git operations shared by the GitHub and GitLab publishers."""
from __future__ import annotations

import subprocess


def _git(repo_dir: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo_dir, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{proc.stderr}")
    return proc.stdout.strip()


def create_branch_and_commit(repo_dir: str, branch: str, message: str) -> None:
    _git(repo_dir, "switch", "-C", branch)
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "-c", "user.name=secfix-bot",
         "-c", "user.email=secfix-bot@users.noreply.github.com",
         "commit", "-m", message)


def push(repo_dir: str, branch: str, remote: str = "origin") -> None:
    _git(repo_dir, "push", "-u", remote, branch, "--force-with-lease")
