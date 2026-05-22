"""``lab_src_rules`` schema, import, and load-back.

Schema is locked: ``fp/stages.py`` reads ``lab_src_rules`` directly via SQL
(``SELECT id, kind, pattern, extracts_json, generation_map, applies_to,
confidence, source_json, note FROM lab_src_rules WHERE section = ?``).
Changing column names here breaks the scanner.

This module is tech-agnostic. Per-tech research dirs (``lab/research/<slug>/``)
hold rules_src.json files; ``research_cycle.py import-rules`` calls
``import_rules()`` here. The previous location was
``lab/research/fontawesome/import_rules.py`` -- that file is now a thin
re-export shim for back-compat.

Why per-tech-slug wipe-and-reinsert: rules_src.json is the source of truth on
disk. lab.db rows for the same tech_slug are derived state; idempotent
re-import lets authors edit the JSON and reflect changes immediately.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_DB = REPO / "fingerprinter" / "lab.db"
_ALIASES_PATH = HERE / "tech_aliases.json"


SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_src_rules (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  tech_slug       TEXT NOT NULL,
  rule_id         TEXT NOT NULL,
  section         TEXT NOT NULL,
  kind            TEXT NOT NULL,
  pattern         TEXT NOT NULL,
  extracts_json   TEXT NOT NULL,
  generation_map  TEXT,
  applies_to      TEXT,
  confidence      TEXT,
  source_json     TEXT NOT NULL,
  note            TEXT,
  UNIQUE(tech_slug, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_lab_src_rules_tech ON lab_src_rules(tech_slug);
CREATE INDEX IF NOT EXISTS idx_lab_src_rules_kind ON lab_src_rules(tech_slug, kind);
"""


# Sections in rules_src.json that hold actual rules. Must include every value
# that fp/stages.py loads from lab_src_rules (banner/css_class/kit/slug_url),
# plus author-side sections that propagate to other tables (url_*, webfont).
RULE_SECTIONS = (
    "banner_rules",
    "url_version_in_path_rules",
    "url_filename_rules",
    "webfont_rules",
    "css_class_rules",
    "kit_rules",
    "slug_url_rules",
)


def _load_aliases() -> dict[str, str]:
    try:
        data = json.loads(_ALIASES_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_")}


_ALIASES = _load_aliases()


def canonical_tech_name(tech_slug: str) -> str:
    """Map slug -> canonical scanner-name string (e.g. ``Font Awesome``).

    Unknown techs fall back to title-cased slug. ``url_version_in_path_rules``
    propagation writes this value into ``lab_url_patterns.tech``.
    """
    if tech_slug in _ALIASES:
        return _ALIASES[tech_slug]
    return tech_slug.replace("-", " ").replace(".", " ").title()


def _propagate_url_version_to_scanner(conn: sqlite3.Connection, tech_slug: str, rules: dict) -> int:
    """Bridge per-tech ``url_version_in_path_rules`` into ``lab_url_patterns``.

    The scanner's ``fp.url_ver`` reads ``lab_url_patterns``; without this
    bridge a CDN pattern authored for tech X stays invisible to the scanner.

    Idempotent: wipes ``origin='mined:src_rules:<tech>'`` rows first.
    """
    origin = f"mined:src_rules:{tech_slug}"
    conn.execute("DELETE FROM lab_url_patterns WHERE origin = ?", (origin,))
    tech_name = canonical_tech_name(tech_slug)
    n = 0
    for rule in rules.get("url_version_in_path_rules", []):
        extracts = rule.get("extracts", {})
        vspec = extracts.get("version")
        if not (isinstance(vspec, dict) and "g" in vspec):
            continue
        version_group = int(vspec["g"])
        family_hint = rule.get("id", "").replace("url_", "cdn: ")
        conn.execute(
            """INSERT INTO lab_url_patterns
                 (pattern, tech, pkg_group, version_group, family, origin, kind, note)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                rule["pattern"],
                tech_name,
                None,
                version_group,
                family_hint,
                origin,
                "cdn",
                f"propagated from lab_src_rules.{rule.get('id', '?')}",
            ),
        )
        n += 1
    return n


def import_rules(db_path: Path, rules_path: Path, tech_slug: str) -> dict:
    """Idempotent import of a rules_src.json file into lab_src_rules.

    Returns ``{db, tech_slug, inserted, propagated_to_scanner}``.
    """
    rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM lab_src_rules WHERE tech_slug = ?", (tech_slug,))
        inserted = 0
        for section in RULE_SECTIONS:
            for rule in rules.get(section, []):
                conn.execute(
                    """
                    INSERT INTO lab_src_rules
                      (tech_slug, rule_id, section, kind, pattern, extracts_json,
                       generation_map, applies_to, confidence, source_json, note)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tech_slug,
                        rule["id"],
                        section,
                        rule.get("kind", ""),
                        rule["pattern"],
                        json.dumps(rule.get("extracts", {}), ensure_ascii=False),
                        json.dumps(rule["generation_from_version"])
                        if "generation_from_version" in rule else None,
                        rule.get("applies_to"),
                        rule.get("confidence"),
                        json.dumps(rule.get("source", {}), ensure_ascii=False),
                        rule.get("note"),
                    ),
                )
                inserted += 1
        propagated = _propagate_url_version_to_scanner(conn, tech_slug, rules)
        conn.commit()
    finally:
        conn.close()
    return {
        "db": str(db_path),
        "tech_slug": tech_slug,
        "inserted": inserted,
        "propagated_to_scanner": propagated,
    }


def load_rules_from_db(db_path: Path, tech_slug: str) -> dict:
    """Reconstruct a rules_src.json-shaped dict from lab.db.

    Consumer-side API: detectors can read rules either from JSON or from the
    DB; the shape coming out matches what authoring tools wrote in. That
    makes lab.db a swap-in source of truth.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM lab_src_rules WHERE tech_slug=? ORDER BY section, rule_id",
            (tech_slug,),
        ).fetchall()
    finally:
        conn.close()
    out: dict = {"_meta": {"tech": tech_slug, "source": "lab.db (table lab_src_rules)"}}
    for r in rows:
        rule = {
            "id": r["rule_id"],
            "kind": r["kind"],
            "pattern": r["pattern"],
            "extracts": json.loads(r["extracts_json"]),
            "applies_to": r["applies_to"],
            "confidence": r["confidence"],
            "source": json.loads(r["source_json"]),
        }
        if r["generation_map"]:
            rule["generation_from_version"] = json.loads(r["generation_map"])
        if r["note"]:
            rule["note"] = r["note"]
        out.setdefault(r["section"], []).append(rule)
    return out
