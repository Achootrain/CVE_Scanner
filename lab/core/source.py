"""Acquire per-tech source code for rule authoring.

Clones a tech's release into ``lab/research/<tech>/out/source/<ref>/``. Used
by the RAG pipeline (lab/rag/) as the L3 evidence corpus -- rule patterns
are extracted from THIS code, not from scan_results.jsonl (CLAUDE.md §6).

Why depth=1: we want the literal banner / build script / class definitions
that ship at one specific release, not history. A separate clone per release
is correct -- comparing v4 to v5 is what reveals the version-discriminating
signal.

Why ``out/source/<ref>/``: matches the path that lab/rag/index_builder walks.
``<ref>`` is the git ref (tag, sha, or branch) the caller supplied --
preserved literally so the on-disk layout is self-documenting.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
RESEARCH = REPO / "lab" / "research"


def source_dir(tech_slug: str, ref: str) -> Path:
    """Where ``acquire`` writes for a given (tech, ref)."""
    return RESEARCH / tech_slug / "out" / "source" / ref


def acquire(tech_slug: str, repo_url: str, ref: str, *, force: bool = False) -> Path:
    """git clone --depth 1 --branch <ref> <repo_url> into source_dir.

    Returns the clone directory. Re-running is idempotent: with ``force`` the
    existing dir is removed first; without ``force`` it's a no-op if already
    present and non-empty.

    Raises ``subprocess.CalledProcessError`` if the clone fails (ref doesn't
    exist, no network, etc.). Caller handles by trying a different ref.
    """
    dst = source_dir(tech_slug, ref)
    if dst.exists() and any(dst.iterdir()):
        if not force:
            return dst
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git", "clone",
            "--depth", "1",
            "--branch", ref,
            "--single-branch",
            repo_url,
            str(dst),
        ],
        check=True,
    )
    # Drop the .git dir -- we don't need history and it would just pollute
    # the index. The clone metadata is preserved by the on-disk path layout.
    git_dir = dst / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir, ignore_errors=True)
    return dst
