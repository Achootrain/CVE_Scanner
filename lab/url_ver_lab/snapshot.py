"""One-shot: snapshot fp.url_ver + fp.version_probes constants into JSON.

Why: the seeder previously read from those modules directly. Once we remove
the inline constants from the scanner (the whole point of Phase A+B), the
seeder needs a stable input that doesn't depend on the modules it's about
to mutate.

Procedure:
  1. Run this script ONCE before deleting constants from the scanner.
     `python -m lab.url_ver_lab.snapshot`
  2. It writes lab/url_ver_lab/snapshot.json with all the data.
  3. seed.py reads snapshot.json (not fp.url_ver) on subsequent re-seeds.
  4. To pick up upstream changes to fp.url_ver (e.g., from a future git pull
     of the scanner repo), re-run this snapshot, commit the JSON change.

After Phase A+B the scanner has no inline constants, so snapshot.json IS the
authoritative seed input. Hand-curated rows still live only in the DB.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
OUT = HERE / "snapshot.json"

sys.path.insert(0, str(REPO / "fingerprinter"))


def main() -> int:
    from fp import url_ver, version_probes

    snap = {
        "_meta": {
            "captured_from": "fp.url_ver + fp.version_probes",
            "purpose": "seed input for lab.url_ver_lab.seed; replaces direct module import after scanner-side constants are removed.",
        },
        "WP_PLUGIN_MAP": dict(url_ver.WP_PLUGIN_MAP),
        "_JS_LIB_MAP": dict(url_ver._JS_LIB_MAP),
        "_CDN_PKG_MAP": dict(url_ver._CDN_PKG_MAP),
        "_SKIP_STEMS": sorted(url_ver._SKIP_STEMS),
        "_CDN_PATTERNS": [
            {
                "pattern": rgx.pattern,
                "flags": rgx.flags,
                "pkg_group": pkg_group,
                "version_group": version_group,
                "fixed_name": fixed_name,
            }
            for rgx, pkg_group, version_group, fixed_name in url_ver._CDN_PATTERNS
        ],
        "_FRAMEWORK_PATTERNS": [
            {
                "pattern": rgx.pattern,
                "flags": rgx.flags,
                "tech": tech,
                "slug": slug,
            }
            for rgx, tech, slug in url_ver._FRAMEWORK_PATTERNS
        ],
        "version_probes_CATALOG": [
            {
                "name": p.name,
                "path": p.path,
                "regex": p.regex,
                "method": p.method,
                "version_group": p.version_group,
                "ok_status": list(p.ok_status),
                "part": p.part,
                "content_hint": p.content_hint,
                "headers": p.headers,
            }
            for p in version_probes.CATALOG
        ],
    }
    OUT.write_text(json.dumps(snap, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"  WP_PLUGIN_MAP: {len(snap['WP_PLUGIN_MAP'])}")
    print(f"  _JS_LIB_MAP: {len(snap['_JS_LIB_MAP'])}")
    print(f"  _CDN_PKG_MAP: {len(snap['_CDN_PKG_MAP'])}")
    print(f"  _SKIP_STEMS: {len(snap['_SKIP_STEMS'])}")
    print(f"  _CDN_PATTERNS: {len(snap['_CDN_PATTERNS'])}")
    print(f"  _FRAMEWORK_PATTERNS: {len(snap['_FRAMEWORK_PATTERNS'])}")
    print(f"  version_probes_CATALOG: {len(snap['version_probes_CATALOG'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
