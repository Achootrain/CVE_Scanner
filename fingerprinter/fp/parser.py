"""Parse Nuclei technology-detect YAML templates into a SQLite database.

Nuclei template structure (relevant subset):

    id: <template-id>
    info:
      name: ...
      author: ...
      severity: info
      description: ...
      classification: { cpe: ... }
      metadata: { verified, max-request, vendor, product, category, ... }
      tags: tech,foo,discovery
    http:
      - method: GET
        path: ["{{BaseURL}}", "{{BaseURL}}/x"]
        headers: { ... }
        body: ...
        redirects: true
        host-redirects: true
        max-redirects: 2
        stop-at-first-match: true
        matchers-condition: and|or
        matchers:
          - type: word | regex | status | kval | dsl | binary
            name: optional-name
            part: body | header | response | all | raw
            words|regex|status|kval|dsl|binary: [...]
            condition: and | or
            negative: true
        extractors:
          - type: regex | kval | xpath | json
            name: optional-name
            part: ...
            group: N
            regex|kval|xpath|json: [...]

Anything that is not one of the recognised matcher/extractor types is stored
as raw JSON under `payload` so the loader never silently drops data.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

LOG = logging.getLogger("fp.parser")

_MATCHER_PAYLOAD_KEYS = ("words", "regex", "status", "kval", "dsl", "binary")
_EXTRACTOR_PAYLOAD_KEYS = ("regex", "kval", "xpath", "json")


def _as_bool(v: Any) -> int:
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return 1 if v else 0
    if isinstance(v, str):
        return 1 if v.strip().lower() in {"1", "true", "yes", "on"} else 0
    return 0


def _as_csv(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v)


def _ensure_db(conn: sqlite3.Connection, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()


def _extract_info(info: dict) -> dict:
    classification = info.get("classification") or {}
    metadata = info.get("metadata") or {}
    return {
        "name": info.get("name") or "",
        "author": _as_csv(info.get("author")),
        "severity": info.get("severity"),
        "description": info.get("description"),
        "cpe": classification.get("cpe"),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "category": metadata.get("category"),
        "max_request": int(metadata.get("max-request") or 0),
        "verified": _as_bool(metadata.get("verified")),
        "tags": _as_csv(info.get("tags")),
    }


def _matcher_payload(m: dict) -> str:
    payload = {k: m[k] for k in _MATCHER_PAYLOAD_KEYS if k in m}
    if not payload:
        # Preserve whatever unknown keys the matcher carried — never lose data.
        payload = {k: v for k, v in m.items()
                   if k not in {"type", "name", "part", "condition", "negative", "group"}}
    # Nuclei word/regex matchers accept `case-insensitive: true` (default false).
    # Keep the flag alongside the primary payload so cache.py can honour it.
    if "case-insensitive" in m:
        payload["case-insensitive"] = bool(m.get("case-insensitive"))
    return json.dumps(payload, ensure_ascii=False)


def _extractor_payload(e: dict) -> str:
    payload = {k: e[k] for k in _EXTRACTOR_PAYLOAD_KEYS if k in e}
    if not payload:
        payload = {k: v for k, v in e.items()
                   if k not in {"type", "name", "part", "group", "internal"}}
    return json.dumps(payload, ensure_ascii=False)


def _insert_template(conn: sqlite3.Connection, doc: dict, raw: str, rel_path: str) -> int:
    info = _extract_info(doc.get("info") or {})
    cur = conn.execute(
        """
        INSERT OR REPLACE INTO templates
            (template_id, name, author, severity, description, vendor, product,
             category, cpe, tags, max_request, verified, file_path, raw_yaml)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            doc["id"], info["name"], info["author"], info["severity"],
            info["description"], info["vendor"], info["product"],
            info["category"], info["cpe"], info["tags"],
            info["max_request"], info["verified"], rel_path, raw,
        ),
    )
    return cur.lastrowid


def _insert_http_blocks(conn: sqlite3.Connection, template_pk: int, http_blocks: list) -> None:
    for block_idx, block in enumerate(http_blocks):
        if not isinstance(block, dict):
            continue
        cur = conn.execute(
            """
            INSERT INTO requests
                (template_id, block_idx, method, headers_json, body,
                 redirects, host_redirects, max_redirects,
                 stop_at_first_match, matchers_condition)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                template_pk, block_idx,
                (block.get("method") or "GET").upper(),
                json.dumps(block.get("headers")) if block.get("headers") else None,
                block.get("body"),
                _as_bool(block.get("redirects")),
                _as_bool(block.get("host-redirects")),
                int(block.get("max-redirects") or 0),
                _as_bool(block.get("stop-at-first-match")),
                (block.get("matchers-condition") or "or").lower(),
            ),
        )
        request_pk = cur.lastrowid

        paths = block.get("path") or []
        if isinstance(paths, str):
            paths = [paths]
        conn.executemany(
            "INSERT INTO paths (request_id, idx, path) VALUES (?,?,?)",
            [(request_pk, i, p) for i, p in enumerate(paths)],
        )

        for idx, m in enumerate(block.get("matchers") or []):
            if not isinstance(m, dict):
                continue
            conn.execute(
                """
                INSERT INTO matchers
                    (request_id, idx, type, name, part, condition, negative,
                     group_val, payload)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    request_pk, idx,
                    (m.get("type") or "").lower(),
                    m.get("name"),
                    (m.get("part") or "body").lower(),
                    (m.get("condition") or "or").lower(),
                    _as_bool(m.get("negative")),
                    int(m.get("group") or 0),
                    _matcher_payload(m),
                ),
            )

        for idx, e in enumerate(block.get("extractors") or []):
            if not isinstance(e, dict):
                continue
            conn.execute(
                """
                INSERT INTO extractors
                    (request_id, idx, type, name, part, group_val, internal, payload)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    request_pk, idx,
                    (e.get("type") or "").lower(),
                    e.get("name"),
                    (e.get("part") or "body").lower(),
                    int(e.get("group") or 0),
                    _as_bool(e.get("internal")),
                    _extractor_payload(e),
                ),
            )


def _iter_yaml_files(root: Path) -> Iterable[Path]:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith((".yaml", ".yml")):
                yield Path(dirpath) / name


def load_directory(templates_dir: Path, db_path: Path, schema_path: Path) -> dict:
    """Parse every YAML under `templates_dir` into the SQLite DB at `db_path`.

    Returns a dict summary: {parsed, errors, total}.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    _ensure_db(conn, schema_path)

    # Fresh load — wipe existing template data (cascades to child tables).
    conn.execute("DELETE FROM templates")
    conn.execute("DELETE FROM parse_errors")
    conn.commit()

    parsed, errors, total = 0, 0, 0
    for path in _iter_yaml_files(templates_dir):
        total += 1
        rel = str(path.relative_to(templates_dir)).replace("\\", "/")
        try:
            raw = path.read_text(encoding="utf-8")
            doc = yaml.safe_load(raw)
            if not isinstance(doc, dict) or "id" not in doc:
                raise ValueError("template missing top-level 'id'")
            template_pk = _insert_template(conn, doc, raw, rel)
            http_blocks = doc.get("http") or []
            if isinstance(http_blocks, dict):
                http_blocks = [http_blocks]
            _insert_http_blocks(conn, template_pk, http_blocks)
            parsed += 1
        except Exception as exc:  # noqa: BLE001 — catch-all is intentional at the loader boundary
            errors += 1
            conn.execute(
                "INSERT INTO parse_errors (file_path, error) VALUES (?, ?)",
                (rel, f"{type(exc).__name__}: {exc}"),
            )
            LOG.warning("parse error %s: %s", rel, exc)

    conn.commit()
    conn.close()
    return {"parsed": parsed, "errors": errors, "total": total}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if len(sys.argv) < 3:
        print("usage: python -m fp.parser <templates_dir> <db_path> [schema_path]")
        raise SystemExit(2)
    templates_dir = Path(sys.argv[1])
    db_path = Path(sys.argv[2])
    schema = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(__file__).with_name("schema.sql")
    summary = load_directory(templates_dir, db_path, schema)
    print(json.dumps(summary, indent=2))
