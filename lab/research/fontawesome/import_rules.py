"""Back-compat shim. The canonical importer is ``lab.core.rules``.

Historically this file owned the lab_src_rules schema and import logic. It
was moved to ``lab/core/rules.py`` so every tech goes through one importer
(adding a new tech is no longer "fork the FA file"). This file is kept so
existing callers like ``lab/research/fontawesome/detect_src.py`` and any
hand-written scripts still resolve.

Prefer ``from lab.core.rules import import_rules, load_rules_from_db`` in
new code.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from lab.core.rules import (  # noqa: E402
    SCHEMA,
    RULE_SECTIONS,
    canonical_tech_name as _canonical_tech_name,
    import_rules,
    load_rules_from_db,
)


DEFAULT_DB = REPO / "fingerprinter" / "lab.db"
DEFAULT_RULES = HERE / "rules_src.json"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--tech-slug", default="font-awesome")
    ap.add_argument("--print", action="store_true",
                    help="After import, query DB and print summary")
    args = ap.parse_args(argv)

    res = import_rules(Path(args.db), Path(args.rules), args.tech_slug)
    print(f"imported {res['inserted']} rules for tech_slug='{res['tech_slug']}' into {res['db']}")

    if args.print:
        loaded = load_rules_from_db(Path(args.db), args.tech_slug)
        print(f"\n=== rules in DB for {args.tech_slug} ===")
        for section, rules in loaded.items():
            if section.startswith("_"):
                continue
            print(f"\n[{section}]  ({len(rules)} rules)")
            for r in rules:
                src = r["source"]
                src_label = src.get("file") or src.get("documentation", "")[:60] or "?"
                print(f"  {r['id']:35s} {r['kind']:12s} src={src_label}")
    return 0


__all__ = [
    "SCHEMA",
    "RULE_SECTIONS",
    "_canonical_tech_name",
    "import_rules",
    "load_rules_from_db",
    "DEFAULT_DB",
    "DEFAULT_RULES",
    "main",
]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
