"""Retrieval API for the rule drafter (CLAUDE.md §12).

Four entry points, each filters the same FTS5 index by source kind. Every
returned Span carries ``content_hash`` so the drafter's post-validator can
re-hash and enforce the bounded-citation contract.

BM25 ranking comes from SQLite FTS5's ``bm25()`` auxiliary; lower score =
better match. We invert the sign so callers see "higher = better".
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_INDEX = HERE / ".index" / "rag.db"


SourceKind = Literal["source", "research", "policy", "rule"]


@dataclass(frozen=True)
class Span:
    source: SourceKind
    file_path: str
    line_start: int
    line_end: int
    content_hash: str
    text: str
    score: float
    tech: str | None = None

    def cite(self) -> dict:
        """The dict shape the drafter must include in source_json.citations.
        verify_citation re-hashes the file region and compares."""
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "content_hash": self.content_hash,
        }


# ---------------------------------------------------------------------------
# Query escaping
# ---------------------------------------------------------------------------

# FTS5 MATCH treats these as operators; strip them so user queries land as
# bag-of-words. We deliberately don't expose AND/OR/NEAR syntax yet -- the
# drafter calls these with natural-language signal descriptions.
_FTS_STRIP_RE = re.compile(r'[^\w\s\-./]+', re.UNICODE)


def _to_fts_query(q: str) -> str:
    """Sanitise a free-text query into an FTS5 MATCH expression.

    Each remaining token is wrapped in double quotes (FTS5's phrase form),
    which treats it as a literal -- safe for tokens containing hyphens or
    dots. Multiple tokens are OR-joined so a partial match still scores."""
    cleaned = _FTS_STRIP_RE.sub(" ", q.lower())
    tokens = [t for t in cleaned.split() if t]
    if not tokens:
        return '""'
    return " OR ".join(f'"{t}"' for t in tokens)


# ---------------------------------------------------------------------------
# Generic search
# ---------------------------------------------------------------------------

def _search(
    query: str,
    source_kinds: tuple[str, ...],
    *,
    tech: str | None,
    k: int,
    index_db: Path | None = None,
) -> list[Span]:
    index_db = index_db or DEFAULT_INDEX
    if not index_db.exists():
        raise FileNotFoundError(
            f"index not built: {index_db}\n"
            "run: python -m lab.research_cycle build-index"
        )
    fts_q = _to_fts_query(query)
    conn = sqlite3.connect(str(index_db))
    try:
        conn.row_factory = sqlite3.Row
        # FTS5: bm25() returns NEGATIVE relevance scores (more-negative = better),
        # so we invert to keep "higher = better" in the public API.
        placeholders = ",".join(["?"] * len(source_kinds))
        sql = f"""
            SELECT c.source, c.tech, c.file_path, c.line_start, c.line_end,
                   c.content_hash, c.text, bm25(rag_fts) AS bm
              FROM rag_fts
              JOIN rag_chunks c ON c.id = rag_fts.rowid
             WHERE rag_fts MATCH ?
               AND c.source IN ({placeholders})
        """
        params: list = [fts_q, *source_kinds]
        if tech is not None:
            sql += " AND c.tech = ?"
            params.append(tech)
        sql += " ORDER BY bm LIMIT ?"
        params.append(k)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    return [
        Span(
            source=r["source"],
            tech=r["tech"],
            file_path=r["file_path"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            content_hash=r["content_hash"],
            text=r["text"],
            score=-float(r["bm"]),
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrieve_source(query: str, tech: str, k: int = 10,
                    index_db: Path | None = None) -> list[Span]:
    """Semantic-shaped search over per-tech source code.

    The drafter calls this to ground a candidate rule in actual L3 evidence
    (CLAUDE.md §6 hierarchy). Tech filter is REQUIRED -- crossing tech
    boundaries here would let the agent cite Bootstrap's banner when
    drafting an Owl Carousel rule.
    """
    return _search(query, ("source",), tech=tech, k=k, index_db=index_db)


def retrieve_rules(signal_shape: str, tech: str | None = None, k: int = 10,
                   index_db: Path | None = None) -> list[Span]:
    """§9 duplicate-check gate.

    Returns lab_src_rules rows whose described signal is close to the
    proposed shape. tech=None searches across all techs (sometimes the
    nearest analog is a different tech's rule)."""
    return _search(signal_shape, ("rule",), tech=tech, k=k, index_db=index_db)


def retrieve_research(analog: str, tech: str | None = None, k: int = 5,
                      index_db: Path | None = None) -> list[Span]:
    """Cross-tech analogy lookup over prior lab/research/<tech>/ artifacts.

    Used when starting a new tech: 'how did we fingerprint version for a
    similar library?' Returns README + rules_src.json chunks."""
    return _search(analog, ("research",), tech=tech, k=k, index_db=index_db)


def retrieve_policy(topic: str, k: int = 3,
                    index_db: Path | None = None) -> list[Span]:
    """Search CLAUDE.md. Used by the drafter when triaging an ambiguous case
    ('tech detected, version absent' -> §8)."""
    return _search(topic, ("policy",), tech=None, k=k, index_db=index_db)


# ---------------------------------------------------------------------------
# Bounded-citation contract (guardrail #1)
# ---------------------------------------------------------------------------

def verify_citation(file_path: str, line_start: int, line_end: int,
                    content_hash: str) -> bool:
    """Re-hash the cited file region and compare to claimed content_hash.

    This is the structural enforcement that turns 'Source: X' from a
    free-text claim into a verifiable obligation. The drafter receives
    spans bearing content_hash; it must echo the SAME hash in its output;
    the post-validator re-derives the hash from the on-disk file and
    rejects on mismatch. The §10 'cite-without-fetch' failure mode is
    structurally impossible because the agent never sees content the
    retriever didn't fetch this turn.
    """
    # file_path is repo-relative for files; rule citations use the
    # ``lab.db:lab_src_rules#<tech>/<rule_id>`` synthetic form.
    if file_path.startswith("lab.db:lab_src_rules#"):
        return _verify_rule_citation(file_path, content_hash)
    abs_path = REPO / file_path
    if not abs_path.exists():
        return False
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if line_start < 1 or line_end > len(lines) or line_start > line_end:
        return False
    region = "\n".join(lines[line_start - 1:line_end])
    actual = hashlib.sha256(region.encode("utf-8")).hexdigest()
    return actual == content_hash


def _verify_rule_citation(synthetic: str, content_hash: str) -> bool:
    """For citations of lab_src_rules rows, re-derive the chunk text from
    the live row and re-hash."""
    # Lazy import to keep this module free of side effects.
    from lab.rag.index_builder import chunk_lab_src_rules, DEFAULT_LAB_DB
    target = synthetic.split("#", 1)[1] if "#" in synthetic else ""
    for chunk in chunk_lab_src_rules(DEFAULT_LAB_DB):
        if chunk.file_path.endswith(f"#{target}"):
            return chunk.content_hash == content_hash
    return False
