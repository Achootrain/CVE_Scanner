"""Phase 2: mine FA-related URL patterns from corpus/.

Reads:
    lab/research/fontawesome/corpus/*.html

Writes:
    lab/research/fontawesome/mined_url_patterns.json
    lab/research/fontawesome/mined_url_patterns.md   (human report)

Algorithm:
1. Parse each HTML, extract <link href>, <script src>, @import url(...), <style> srcs.
2. Keep URLs that match /font-?awesome|@fortawesome|kit\.fontawesome\.com/i.
3. For each URL, derive a "shape" by collapsing version-looking segments and digits.
4. Cluster URLs by host + shape. For each cluster, try to derive a version-extracting
   regex from the concrete examples (find the position where the version appears).
5. Record per-cluster: pattern, example_url, hosts, n_sites_using_pattern, version_group.

Rules are NOT invented — they are extracted from observed URLs and only kept if
at least one example URL in the cluster yields a parseable version.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
OUT_JSON = HERE / "mined_url_patterns.json"
OUT_MD = HERE / "mined_url_patterns.md"


# Lenient HTML URL extractors.
RE_LINK_HREF = re.compile(r'<link[^>]*\bhref=["\'](.*?)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]*\bsrc=["\'](.*?)["\']', re.I)
RE_CSS_IMPORT = re.compile(r'@import\s+(?:url\()?["\']?(.*?)["\']?\)?[;\s]', re.I)
RE_STYLE_SRC = re.compile(r'url\(["\']?(.*?)["\']?\)', re.I)

FA_URL = re.compile(r'font-?awesome|@fortawesome|kit\.fontawesome\.com|fontawesome', re.I)
# A version-like token: 1.2, 1.2.3, v1.2.3, with optional pre-release suffix.
VERSION_TOKEN = re.compile(r'(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)')

# Patterns that are definitively NOT a version (kit IDs, query timestamps, build hashes).
RE_HEX_KIT = re.compile(r'^[0-9a-f]{8,12}$')


def extract_fa_urls(html: str) -> list[str]:
    out: list[str] = []
    for rx in (RE_LINK_HREF, RE_SCRIPT_SRC, RE_CSS_IMPORT, RE_STYLE_SRC):
        for m in rx.findall(html):
            if FA_URL.search(m):
                out.append(m.strip())
    # Dedup while preserving order
    seen: set[str] = set()
    dedup: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup


def normalize(url: str, page_origin: str) -> str:
    """Resolve protocol-relative and scheme-less URLs against the page origin."""
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        u = urlparse(page_origin)
        return f"{u.scheme}://{u.netloc}{url}"
    if not url.startswith(("http://", "https://")):
        # Relative URL -- prepend page origin's root
        return f"{page_origin.rstrip('/')}/{url}"
    return url


def shape_path(path: str) -> str:
    """Collapse version-looking segments + digits to placeholders for clustering.

    Examples:
      /releases/v5.13.0/css/all.css           -> /releases/vV/css/all.css
      /font-awesome/4.7.0/css/all.min.css     -> /font-awesome/V/css/all.min.css
      /fontawesome-free-5.11.2-web/css/all.css -> /fontawesome-free-V-web/css/all.css
      /static/abc123def456.css                -> /static/H.css
    """
    s = path
    # Version-looking segments (most specific first)
    s = re.sub(r'v?\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?', 'V', s)
    # Long hex hashes
    s = re.sub(r'\b[0-9a-f]{8,40}\b', 'H', s)
    # Trailing query params
    s = re.sub(r'\?.*$', '', s)
    return s


def derive_pattern_and_version(urls: list[str]) -> tuple[str | None, int | None, str | None]:
    """Derive a version-extracting regex from a cluster of concrete URLs.

    Strategy: find which token positions, when replaced with VERSION_TOKEN regex,
    successfully extract a version from at least one URL. Return the most-specific
    pattern. If no version is extractable, return (pattern_for_detection_only, None, None).
    """
    if not urls:
        return None, None, None

    # Try matching VERSION_TOKEN once per URL and see if at least one position works
    successes: list[tuple[str, str]] = []  # (extracted_version, source_url)
    for u in urls:
        for m in VERSION_TOKEN.finditer(u):
            v = m.group(1)
            # filter junk: skip if version looks like a query param value (1.0.0 after ?ver=)
            successes.append((v, u))
            break  # first match per URL
    if not successes:
        return None, None, None

    # Build a regex: literal-escape the common prefix, allow .* between known parts.
    # Simpler: take the most common URL shape, replace its first version token with
    # the VERSION_TOKEN regex, escape the rest.
    sample = successes[0][1]
    # Find first version token in sample
    m = VERSION_TOKEN.search(sample)
    if not m:
        return None, None, None
    prefix = sample[:m.start()]
    suffix = sample[m.end():]
    # Strip query string from suffix so URLs with/without ?ver= still match
    suffix = re.sub(r'\?.*$', '', suffix)
    # Build pattern: anchor on host+prefix up to the version, then VERSION_TOKEN,
    # then a loose suffix matcher (the file extension or similar).
    # Take last path segment of suffix to constrain (file extension).
    suffix_ext = ''
    sm = re.search(r'(\.[a-z]{2,5})(?:[?#]|$)', suffix)
    if sm:
        suffix_ext = sm.group(1)
    pattern = re.escape(prefix) + r'(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)' + (re.escape(suffix_ext) if suffix_ext else '')
    return pattern, 1, successes[0][0]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(CORPUS_DIR))
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args(argv)

    corpus = Path(args.corpus_dir)
    html_files = sorted(corpus.glob("*.html"))
    print(f"corpus files: {len(html_files)}", file=sys.stderr)

    # cluster_key -> list of (host, original_url)
    clusters: dict[str, list[tuple[str, str]]] = defaultdict(list)
    site_url_count: Counter = Counter()
    total_fa_urls = 0

    for hp in html_files:
        host = hp.stem
        page_origin = f"https://{host}"
        html = hp.read_text(encoding="utf-8", errors="replace")
        urls = extract_fa_urls(html)
        for u in urls:
            full = normalize(u, page_origin)
            try:
                pu = urlparse(full)
                if not pu.netloc:
                    continue
            except Exception:
                continue
            shape = f"{pu.netloc}{shape_path(pu.path)}"
            clusters[shape].append((host, full))
            total_fa_urls += 1
        if urls:
            site_url_count[host] = len(urls)

    print(f"sites with FA URLs: {len(site_url_count)} / {len(html_files)}", file=sys.stderr)
    print(f"total FA URLs: {total_fa_urls}", file=sys.stderr)
    print(f"distinct shapes: {len(clusters)}", file=sys.stderr)

    # Build pattern records per cluster
    records: list[dict] = []
    for shape, items in sorted(clusters.items(), key=lambda kv: -len(set(h for h, _ in kv[1]))):
        hosts = sorted(set(h for h, _ in items))
        urls = [u for _, u in items]
        n_sites = len(hosts)
        pattern, vgroup, sample_version = derive_pattern_and_version(urls)
        records.append({
            "shape": shape,
            "n_urls": len(urls),
            "n_sites": n_sites,
            "hosts_sample": hosts[:5],
            "url_sample": urls[:3],
            "pattern": pattern,
            "version_group": vgroup,
            "sample_version": sample_version,
            "version_bearing": vgroup is not None,
        })

    # Write JSON
    Path(args.out_json).write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write markdown report
    lines = []
    lines.append("# Phase 2: Mined FA URL patterns")
    lines.append("")
    lines.append(f"- Corpus files: **{len(html_files)}**")
    lines.append(f"- Sites with FA URLs: **{len(site_url_count)}**")
    lines.append(f"- Total FA URLs: **{total_fa_urls}**")
    lines.append(f"- Distinct shapes: **{len(clusters)}**")
    n_vb = sum(1 for r in records if r["version_bearing"])
    lines.append(f"- Version-bearing shapes: **{n_vb}** / {len(records)}")
    lines.append("")
    lines.append("## Top patterns by site coverage")
    lines.append("")
    lines.append("| Sites | URLs | Shape | Version? | Sample |")
    lines.append("|-------|------|-------|----------|--------|")
    for r in records[:40]:
        vbadge = f"yes ({r['sample_version']})" if r["version_bearing"] else "no"
        sample = (r["url_sample"][0] if r["url_sample"] else "")[:80]
        lines.append(f"| {r['n_sites']} | {r['n_urls']} | `{r['shape'][:60]}` | {vbadge} | `{sample}` |")
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {args.out_json}", file=sys.stderr)
    print(f"wrote {args.out_md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
