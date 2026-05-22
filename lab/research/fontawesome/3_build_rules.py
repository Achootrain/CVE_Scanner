"""Transform cves.json + slugs.json -> rules.json.

One rule per plugin slug. Each rule carries:
  - path: /wp-content/plugins/<slug>/readme.txt  (universal WP plugin convention)
  - version_regex: extracts "Stable tag: X" from readme header
  - vulnerable_ranges: parsed affected_versions strings as (op, version) pairs
  - cves: list of CVE ids that constrain this plugin

After fetching the readme, callers compare the extracted version against every
range; a hit on any range means the plugin is vulnerable to that CVE.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

_RANGE_RE = re.compile(r"^\s*(<=|<|>=|>|through|=)\s*([0-9][\w.\-]*)\s*$", re.I)


def parse_range(s: str) -> dict | None:
    """Parse '<= 2.0.1' / '< 4.3.2' / 'through 2.3' -> {op, version}.

    'through X' is normalised to 'le' (inclusive).
    """
    m = _RANGE_RE.match(s)
    if not m:
        return None
    op_raw = m.group(1).lower()
    op_map = {"<=": "le", "<": "lt", ">=": "ge", ">": "gt", "through": "le", "=": "eq"}
    return {"op": op_map[op_raw], "version": m.group(2)}


def build_rules() -> dict:
    cves = json.loads((HERE /"cves.json").read_text(encoding="utf-8"))
    slugs_doc = json.loads((HERE /"slugs.json").read_text(encoding="utf-8"))

    # Map product name -> slug entry. Products in cves.json have several spellings
    # ("Advanced Custom Fields: Font Awesome Field" vs slugs.json's same string);
    # match by exact product string first, fall back to lowercased-no-colon.
    slug_by_product: dict[str, dict] = {s["product"]: s for s in slugs_doc["slugs"]}

    def norm(p: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", p.lower()).strip()

    norm_slug = {norm(s["product"]): s for s in slugs_doc["slugs"]}

    rules: dict[str, dict] = {}
    unmatched: list[str] = []

    for cve in cves["cves"]:
        product = cve["product"]
        s = slug_by_product.get(product) or norm_slug.get(norm(product))
        if not s:
            unmatched.append(f"{cve['cve']}: {product!r}")
            continue
        rng = parse_range(cve["affected_versions"])
        slug = s["slug"]
        rule = rules.setdefault(slug, {
            "slug": slug,
            "product": s["product"],
            "wp_status": s["status"],
            "wp_notes": s["notes"],
            "paths": [
                f"/wp-content/plugins/{slug}/readme.txt",
            ],
            "version_regex": r"(?im)^Stable\s*tag:\s*([0-9][\w.\-]*)",
            "cves": [],
        })
        rule["cves"].append({
            "cve": cve["cve"],
            "cvss": cve["cvss"],
            "vuln_type": cve["vuln_type"],
            "affected": cve["affected_versions"],
            "range": rng,
            "summary": cve["description_short"],
        })

    # Sort each rule's CVE list by published date (oldest first is fine; sort by cve id)
    for r in rules.values():
        r["cves"].sort(key=lambda c: c["cve"])

    return {
        "generated_at": "2026-05-13",
        "rule_count": len(rules),
        "unmatched_cves": unmatched,
        "rules": sorted(rules.values(), key=lambda r: r["slug"]),
    }


def main(argv: list[str]) -> int:
    out = build_rules()
    target = HERE / "rules.json"
    target.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {target} ({out['rule_count']} rules, {sum(len(r['cves']) for r in out['rules'])} CVEs)")
    if out["unmatched_cves"]:
        print("WARN unmatched:", out["unmatched_cves"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
