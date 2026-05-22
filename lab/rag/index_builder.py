"""Build the SQLite-FTS5 retrieval index for rule authoring.

Storage: ``lab/rag/.index/rag.db``. Two tables:

    rag_chunks(id, source, tech, file_path, line_start, line_end,
               content_hash, text)
    rag_fts                       -- FTS5 mirror over rag_chunks.text

FTS5 ships with the SQLite Python ships with on Windows/macOS/Linux, so no
new dependency. ``MATCH`` queries return BM25 scores via the ``bm25()``
auxiliary function.

What gets indexed (per CLAUDE.md §12):

  - ``source``    Per-tech source under ``lab/research/<tech>/out/source/<ref>/``.
                  30-line sliding window with 10-line overlap. Skips
                  ``node_modules/``, ``vendor/``, ``.git/``, and minified
                  ``*.min.{js,css}`` (kept BM25-only would require a second
                  index; for the first slice we skip them entirely).
  - ``research``  Per-tech research artifacts. Markdown split on ``##``/``###``;
                  rules_src.json one chunk per rule object.
  - ``policy``    ``CLAUDE.md`` split on ``##``.
  - ``rule``      ``lab_src_rules`` rows. One chunk per row, text =
                  ``note`` + ``source_json.principle``.

Explicitly NOT indexed: ``scan_results*.jsonl`` (would route the agent into
the §6 anti-pattern), upstream mirror DBs (CLAUDE.md §5).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RESEARCH = REPO / "lab" / "research"
DEFAULT_INDEX = HERE / ".index" / "rag.db"
DEFAULT_LAB_DB = REPO / "fingerprinter" / "lab.db"
CLAUDEMD = REPO / "CLAUDE.md"


# Files we will not embed individually. Globs are matched against the path
# relative to the source root.
#
# We deliberately INDEX dist/ and build/ -- those hold the canonical shipped
# assets (e.g. dist/owl.carousel.js) which are what fingerprints in the wild.
# A drafter targeting a banner candidate from dist/ must be able to
# retrieve_source on the same file or the §8 cause-B plumbing breaks.
# Minified bundles still get filtered via _SKIP_FILE_SUFFIXES.
_SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "__pycache__", ".cache"}
_SKIP_FILE_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", ".png", ".jpg", ".jpeg",
                       ".gif", ".woff", ".woff2", ".ttf", ".eot", ".ico", ".pdf",
                       ".zip", ".tar", ".gz", ".webp", ".svg")
_INDEX_FILE_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".css", ".scss", ".less",
                        ".html", ".json", ".yaml", ".yml", ".md", ".py", ".rb",
                        ".php", ".go", ".rs", ".java", ".sh")
_MAX_FILE_BYTES = 256_000   # skip giant generated files


SCHEMA = """
CREATE TABLE IF NOT EXISTS rag_chunks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    tech         TEXT,
    file_path    TEXT NOT NULL,
    line_start   INTEGER NOT NULL,
    line_end     INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    text         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_tech ON rag_chunks(tech);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_source ON rag_chunks(source);

CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts USING fts5(
    text,
    content='rag_chunks',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
"""

# Keep FTS5 in sync with rag_chunks via triggers.
TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS rag_chunks_ai AFTER INSERT ON rag_chunks BEGIN
    INSERT INTO rag_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS rag_chunks_ad AFTER DELETE ON rag_chunks BEGIN
    INSERT INTO rag_fts(rag_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
"""


@dataclass
class Chunk:
    source: str
    tech: str | None
    file_path: str
    line_start: int
    line_end: int
    text: str

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Chunkers (one per content kind)
# ---------------------------------------------------------------------------

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def chunk_source_file(path: Path, tech: str, rel_path: str,
                      window: int = 30, overlap: int = 10) -> list[Chunk]:
    """Sliding-window chunks for source files. BM25 over windows is robust
    even though it's not AST-aware -- a function definition split across two
    windows still surfaces both."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    if not lines:
        return []
    out: list[Chunk] = []
    step = max(1, window - overlap)
    i = 0
    while i < len(lines):
        end = min(i + window, len(lines))
        chunk_text = "\n".join(lines[i:end])
        if chunk_text.strip():
            out.append(Chunk(
                source="source",
                tech=tech,
                file_path=rel_path,
                line_start=i + 1,
                line_end=end,
                text=chunk_text,
            ))
        if end >= len(lines):
            break
        i += step
    return out


def chunk_markdown(path: Path, source_kind: str, tech: str | None,
                   rel_path: str) -> list[Chunk]:
    """Split markdown on top-level (##) headings; nested ### sections roll
    up into their parent ## chunk. The first chunk before any heading is
    emitted as a 'preamble'."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[Chunk] = []
    buf: list[str] = []
    buf_start = 1
    for idx, line in enumerate(lines, start=1):
        if line.startswith("## "):
            if any(s.strip() for s in buf):
                out.append(Chunk(
                    source=source_kind, tech=tech, file_path=rel_path,
                    line_start=buf_start, line_end=idx - 1,
                    text="\n".join(buf),
                ))
            buf = [line]
            buf_start = idx
        else:
            buf.append(line)
    if any(s.strip() for s in buf):
        out.append(Chunk(
            source=source_kind, tech=tech, file_path=rel_path,
            line_start=buf_start, line_end=len(lines),
            text="\n".join(buf),
        ))
    return out


def chunk_rules_src_json(path: Path, tech: str, rel_path: str) -> list[Chunk]:
    """One chunk per rule object across all sections. Each chunk carries the
    section name + rule object verbatim so retrieval against a signal_shape
    surfaces directly comparable shapes (§9 gate)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Chunk] = []
    for section, items in data.items():
        if section.startswith("_") or not isinstance(items, list):
            continue
        for rule in items:
            text = f"[{section}]\n{json.dumps(rule, ensure_ascii=False, indent=2)}"
            out.append(Chunk(
                source="research", tech=tech, file_path=rel_path,
                line_start=1, line_end=1,
                text=text,
            ))
    return out


def chunk_lab_src_rules(lab_db: Path) -> list[Chunk]:
    """One chunk per lab_src_rules row. Used for the §9 gate."""
    if not lab_db.exists():
        return []
    conn = sqlite3.connect(str(lab_db))
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT tech_slug, rule_id, section, kind, pattern, extracts_json, "
            "applies_to, confidence, source_json, note FROM lab_src_rules"
        ).fetchall()
    finally:
        conn.close()
    out: list[Chunk] = []
    for r in rows:
        principle = ""
        try:
            principle = json.loads(r["source_json"]).get("principle", "") or ""
        except (json.JSONDecodeError, TypeError):
            pass
        text = (
            f"[{r['section']}] {r['tech_slug']}/{r['rule_id']}\n"
            f"kind={r['kind']} applies_to={r['applies_to']} confidence={r['confidence']}\n"
            f"pattern={r['pattern']}\n"
            f"extracts={r['extracts_json']}\n"
            f"note={r['note'] or ''}\n"
            f"principle={principle}"
        )
        out.append(Chunk(
            source="rule",
            tech=r["tech_slug"],
            file_path=f"lab.db:lab_src_rules#{r['tech_slug']}/{r['rule_id']}",
            line_start=1, line_end=1,
            text=text,
        ))
    return out


# ---------------------------------------------------------------------------
# Tree walkers
# ---------------------------------------------------------------------------

def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        if parts & _SKIP_DIR_NAMES:
            continue
        name = p.name.lower()
        if any(name.endswith(sfx) for sfx in _SKIP_FILE_SUFFIXES):
            continue
        if not any(name.endswith(sfx) for sfx in _INDEX_FILE_SUFFIXES):
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _iter_research_files(tech_dir: Path):
    for p in tech_dir.iterdir():
        if not p.is_file():
            continue
        if p.name in {"dataset_dev.jsonl", "dataset_test.jsonl"}:
            continue
        yield p


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_index(index_db: Path | None = None,
                *,
                lab_db: Path | None = None,
                research_root: Path | None = None,
                policy_file: Path | None = None) -> dict:
    """(Re)build the index. Returns a dict with chunk counts per source kind.

    Idempotent: drops and recreates tables. Cheap enough at this scale to
    not bother with incremental updates yet.
    """
    index_db = index_db or DEFAULT_INDEX
    lab_db = lab_db or DEFAULT_LAB_DB
    research_root = research_root or RESEARCH
    policy_file = policy_file or CLAUDEMD

    index_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(index_db))
    try:
        conn.executescript("""
            DROP TABLE IF EXISTS rag_fts;
            DROP TABLE IF EXISTS rag_chunks;
        """)
        conn.executescript(SCHEMA)
        conn.executescript(TRIGGERS)

        chunks: list[Chunk] = []

        # Policy
        if policy_file.exists():
            chunks.extend(chunk_markdown(
                policy_file, "policy", None,
                str(policy_file.relative_to(REPO)),
            ))

        # Per-tech research artifacts + sources
        if research_root.exists():
            for tech_dir in sorted(p for p in research_root.iterdir() if p.is_dir()):
                tech = tech_dir.name
                if tech in {"__pycache__", "dashboard", "plugins"}:
                    continue
                # research/<tech>/*.md, rules_src.json
                for f in _iter_research_files(tech_dir):
                    rel = str(f.relative_to(REPO))
                    if f.suffix == ".md":
                        chunks.extend(chunk_markdown(f, "research", tech, rel))
                    elif f.name == "rules_src.json":
                        chunks.extend(chunk_rules_src_json(f, tech, rel))
                # research/<tech>/out/source/<ref>/**
                source_root = tech_dir / "out" / "source"
                if source_root.exists():
                    for ref_dir in sorted(p for p in source_root.iterdir() if p.is_dir()):
                        for src_file in _iter_source_files(ref_dir):
                            rel = str(src_file.relative_to(REPO))
                            chunks.extend(chunk_source_file(src_file, tech, rel))

        # lab_src_rules rows (the §9 gate corpus)
        chunks.extend(chunk_lab_src_rules(lab_db))

        # Bulk insert
        conn.executemany(
            """INSERT INTO rag_chunks
                  (source, tech, file_path, line_start, line_end, content_hash, text)
               VALUES (?,?,?,?,?,?,?)""",
            [
                (c.source, c.tech, c.file_path, c.line_start, c.line_end,
                 c.content_hash, c.text)
                for c in chunks
            ],
        )
        conn.commit()

        counts = {
            "chunks": len(chunks),
            "source": sum(1 for c in chunks if c.source == "source"),
            "research": sum(1 for c in chunks if c.source == "research"),
            "policy": sum(1 for c in chunks if c.source == "policy"),
            "rules": sum(1 for c in chunks if c.source == "rule"),
            "index_db": str(index_db),
        }
    finally:
        conn.close()
    return counts


def main() -> int:
    stats = build_index()
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
