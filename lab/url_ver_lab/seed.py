"""Seed lab.db with rows from lab/url_ver_lab/snapshot.json.

The snapshot.json was captured once via lab.url_ver_lab.snapshot from the
scanner's original in-code constants. After Phase A+B the scanner has no
inline constants; snapshot.json IS the authoritative seed input.

Idempotent: wipes existing rows whose origin starts with 'seeded:' and
re-inserts. Hand-curated rows (origin='hand-curated' or 'mined:...') are
preserved across re-seeds.

Usage:
    python -m lab.url_ver_lab.seed
    python -m lab.url_ver_lab.seed --print
    python -m lab.url_ver_lab.seed --db /path/to/lab.db --snapshot /path/to/snapshot.json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_DB = REPO / "fingerprinter" / "lab.db"
DEFAULT_SNAPSHOT = HERE / "snapshot.json"

from lab.url_ver_lab.schema import SCHEMA  # noqa: E402


def _wipe_seeded(conn: sqlite3.Connection) -> dict:
    cur = conn.cursor()
    cur.execute("DELETE FROM lab_url_patterns WHERE origin LIKE 'seeded:%'")
    url_del = cur.rowcount
    cur.execute("DELETE FROM lab_pkg_aliases WHERE origin LIKE 'seeded:%'")
    alias_del = cur.rowcount
    cur.execute("DELETE FROM lab_version_probes WHERE origin LIKE 'seeded:%'")
    vp_del = cur.rowcount
    return {"url_patterns_deleted": url_del, "pkg_aliases_deleted": alias_del, "version_probes_deleted": vp_del}


def _seed_aliases(conn: sqlite3.Connection, snap: dict) -> dict:
    counts = {"js-lib": 0, "cdn-pkg": 0, "wp-plugin": 0, "skip-stem": 0}
    cur = conn.cursor()

    for alias, tech in snap["_JS_LIB_MAP"].items():
        cur.execute(
            "INSERT OR IGNORE INTO lab_pkg_aliases (alias, tech, context, origin) VALUES (?,?,?,?)",
            (alias.lower(), tech, "js-lib", "seeded:_JS_LIB_MAP"),
        )
        if cur.rowcount:
            counts["js-lib"] += 1

    js_aliases = {a.lower() for a in snap["_JS_LIB_MAP"].keys()}
    for alias, tech in snap["_CDN_PKG_MAP"].items():
        alias_lc = alias.lower()
        if alias_lc in js_aliases:
            continue
        cur.execute(
            "INSERT OR IGNORE INTO lab_pkg_aliases (alias, tech, context, origin) VALUES (?,?,?,?)",
            (alias_lc, tech, "cdn-pkg", "seeded:_CDN_PKG_MAP"),
        )
        if cur.rowcount:
            counts["cdn-pkg"] += 1

    for alias, tech in snap["WP_PLUGIN_MAP"].items():
        cur.execute(
            "INSERT OR IGNORE INTO lab_pkg_aliases (alias, tech, context, origin) VALUES (?,?,?,?)",
            (alias.lower(), tech, "wp-plugin", "seeded:WP_PLUGIN_MAP"),
        )
        if cur.rowcount:
            counts["wp-plugin"] += 1

    for stem in snap["_SKIP_STEMS"]:
        cur.execute(
            "INSERT OR IGNORE INTO lab_pkg_aliases (alias, tech, context, origin) VALUES (?,?,?,?)",
            (stem.lower(), None, "skip-stem", "seeded:_SKIP_STEMS"),
        )
        if cur.rowcount:
            counts["skip-stem"] += 1

    return counts


def _family_for_cdn_pattern(rgx_str: str, fixed_name: str | None) -> str:
    if "use.fontawesome.com" in rgx_str.replace("\\.", "."):
        return "cdn: fontawesome"
    if "jsdelivr" in rgx_str:
        return "cdn: jsdelivr"
    if "unpkg" in rgx_str:
        return "cdn: unpkg"
    if "cdnjs" in rgx_str:
        return "cdn: cdnjs"
    if "googleapis" in rgx_str:
        return "cdn: google"
    if "bootstrapcdn" in rgx_str:
        return "cdn: bootstrapcdn"
    if "code.jquery.com" in rgx_str.replace("\\.", "."):
        return "cdn: jquery"
    if fixed_name:
        return f"cdn: {fixed_name.lower()}"
    return "cdn: other"


def _seed_patterns(conn: sqlite3.Connection, snap: dict) -> dict:
    cur = conn.cursor()
    n_cdn = n_framework = 0
    for entry in snap["_CDN_PATTERNS"]:
        family = _family_for_cdn_pattern(entry["pattern"], entry["fixed_name"])
        cur.execute(
            """INSERT INTO lab_url_patterns
                 (pattern, tech, pkg_group, version_group, family, origin, kind)
               VALUES (?,?,?,?,?,?,?)""",
            (entry["pattern"], entry["fixed_name"], entry["pkg_group"],
             entry["version_group"], family, "seeded:_CDN_PATTERNS", "cdn"),
        )
        n_cdn += 1
    for entry in snap["_FRAMEWORK_PATTERNS"]:
        slug = entry["slug"]
        cur.execute(
            """INSERT INTO lab_url_patterns
                 (pattern, tech, pkg_group, version_group, family, origin, kind, note)
               VALUES (?,?,?,?,?,?,?,?)""",
            (entry["pattern"], entry["tech"], None, None,
             f"framework: {slug}", "seeded:_FRAMEWORK_PATTERNS", "framework", f"slug={slug}"),
        )
        n_framework += 1
    return {"cdn": n_cdn, "framework": n_framework}


def _seed_version_probes(conn: sqlite3.Connection, snap: dict) -> int:
    cur = conn.cursor()
    n = 0
    for p in snap["version_probes_CATALOG"]:
        cur.execute(
            """INSERT INTO lab_version_probes
                 (name, path, regex, method, version_group, ok_status, part,
                  content_hint, headers_json, origin)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                p["name"], p["path"], p["regex"], p["method"], p["version_group"],
                ",".join(str(s) for s in p["ok_status"]),
                p["part"], p["content_hint"],
                json.dumps(p["headers"]) if p["headers"] else None,
                "seeded:CATALOG",
            ),
        )
        n += 1
    return n


def seed(db_path: Path, snapshot_path: Path = DEFAULT_SNAPSHOT) -> dict:
    snap = json.loads(snapshot_path.read_text(encoding="utf-8"))
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        wiped = _wipe_seeded(conn)
        aliases = _seed_aliases(conn, snap)
        patterns = _seed_patterns(conn, snap)
        n_vp = _seed_version_probes(conn, snap)
        conn.commit()
    finally:
        conn.close()
    return {
        "wiped": wiped, "aliases_inserted": aliases,
        "patterns_inserted": patterns, "version_probes_inserted": n_vp,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT))
    ap.add_argument("--print", action="store_true")
    args = ap.parse_args(argv)
    res = seed(Path(args.db), Path(args.snapshot))
    print(f"Seeded {args.db}:")
    print(f"  wiped: {res['wiped']}")
    print(f"  aliases: {res['aliases_inserted']}")
    print(f"  patterns: {res['patterns_inserted']}")
    print(f"  version_probes: {res['version_probes_inserted']}")
    if args.print:
        conn = sqlite3.connect(args.db)
        print("\n=== lab_pkg_aliases by context ===")
        for row in conn.execute("SELECT context, COUNT(*) FROM lab_pkg_aliases GROUP BY context").fetchall():
            print(f"  {row[1]:4d}  {row[0]}")
        print("\n=== lab_url_patterns by family ===")
        for row in conn.execute("SELECT family, kind, COUNT(*) FROM lab_url_patterns GROUP BY family, kind ORDER BY 3 DESC").fetchall():
            print(f"  {row[2]:3d}  [{row[1]:9s}] {row[0]}")
        print("\n=== lab_version_probes by name ===")
        for row in conn.execute("SELECT name, COUNT(*) FROM lab_version_probes GROUP BY name ORDER BY 2 DESC").fetchall():
            print(f"  {row[1]:3d}  {row[0]}")
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
