"""Command-line entry point: `python -m fp.cli {parse|build-cache|scan} ...`."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from . import cache as cache_mod
from . import parser as parser_mod
from . import scanner as scanner_mod


def _cmd_parse(args: argparse.Namespace) -> int:
    schema = Path(args.schema) if args.schema else Path(__file__).with_name("schema.sql")
    summary = parser_mod.load_directory(Path(args.templates), Path(args.db), schema)
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_build_cache(args: argparse.Namespace) -> int:
    cache = cache_mod.build_cache(args.db)
    if args.out:
        cache_mod.dump_cache(cache, args.out)
    print(json.dumps(cache["stats"], indent=2))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.cache:
        cache = cache_mod.load_cache(args.cache)
    else:
        cache = cache_mod.build_cache(args.db)

    results = asyncio.run(
        scanner_mod.scan_targets(
            cache,
            args.targets,
            concurrency=args.concurrency,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
        )
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _render_human(results)
    return 0


def _render_human(results: dict) -> None:
    for target, detections in results.items():
        print(f"\n=== {target} ===")
        if not detections:
            print("  (no detections)")
            continue
        # Deduplicate repeated hits (same template + matcher_name + path).
        seen = set()
        for d in detections:
            key = (d["template_id"], d["matcher_name"], d["path"])
            if key in seen:
                continue
            seen.add(key)
            label = d["name"]
            if d["matcher_name"]:
                label += f" :: {d['matcher_name']}"
            extras = []
            if d["vendor"] and d["product"]:
                extras.append(f"{d['vendor']}/{d['product']}")
            if d["extracted"]:
                flat = ", ".join(
                    f"{k}={v[0]}" for k, v in d["extracted"].items() if v
                )
                if flat:
                    extras.append(flat)
            tail = f"  [{'; '.join(extras)}]" if extras else ""
            print(f"  {d['template_id']:<35} {label}{tail}")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="fp")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_parse = sub.add_parser("parse", help="Parse YAML templates into SQLite")
    p_parse.add_argument("templates", help="Path to http/technologies directory")
    p_parse.add_argument("db", help="Path to SQLite DB (will be created)")
    p_parse.add_argument("--schema", help="Override schema.sql path")
    p_parse.set_defaults(func=_cmd_parse)

    p_cache = sub.add_parser("build-cache", help="Build in-memory cache, optionally dump to JSON")
    p_cache.add_argument("db")
    p_cache.add_argument("--out", help="Write cache JSON to this path")
    p_cache.set_defaults(func=_cmd_build_cache)

    p_scan = sub.add_parser("scan", help="Scan one or more targets")
    p_scan.add_argument("targets", nargs="+", help="Target URLs or hostnames")
    p_scan.add_argument("--db", default="fingerprints.db")
    p_scan.add_argument("--cache", help="Load JSON cache instead of rebuilding from DB")
    p_scan.add_argument("--concurrency", type=int, default=scanner_mod.DEFAULT_CONCURRENCY)
    p_scan.add_argument("--timeout", type=int, default=scanner_mod.DEFAULT_TIMEOUT)
    p_scan.add_argument("--verify-ssl", action="store_true")
    p_scan.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p_scan.set_defaults(func=_cmd_scan)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
