"""Phase 3: mine FA version from CSS body for sites whose URL has no version.

Reads:
    lab/research/fontawesome/corpus/*.html  (Phase 1)

Writes:
    lab/research/fontawesome/mined_body_fingerprints.json
    lab/research/fontawesome/mined_body_fingerprints.md

Algorithm:
1. For each corpus HTML, extract all FA URLs (same as Phase 2).
2. Skip URLs that already yield a version from the URL itself.
3. Fetch each remaining URL (CSS / JS file). Polite throttle, 1 retry, 1 MiB cap.
4. Run version-comment regexes against the body:
   - /Font Awesome (?:Free |Pro )?(\d+\.\d+(?:\.\d+)?)/
   - /\* Font Awesome ... \d+\.\d+\.\d+ ... \*/  (CSS header banner)
   - /fontawesome.*?version[^\d]*(\d+\.\d+(?:\.\d+)?)/i  (generic)
5. Aggregate per host: list of (url, version, regex_id).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CORPUS_DIR = HERE / "corpus"
OUT_JSON = HERE / "mined_body_fingerprints.json"
OUT_MD = HERE / "mined_body_fingerprints.md"

sys.path.insert(0, str(REPO / "fingerprinter"))
sys.path.insert(0, str(REPO / "lab" / "research" / "dashboard"))
import fetchlib  # noqa: E402
import importlib.util  # noqa: E402
spec = importlib.util.spec_from_file_location("m2", HERE / "2_mine_urls.py")
m2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m2)  # type: ignore


# Body-content version regexes (ordered by specificity / trustworthiness).
BODY_RX = [
    # FA's own CSS banner: /*! Font Awesome Free 5.15.4 by @fontawesome ... */
    ("fa_banner", re.compile(r"Font Awesome (?:Free|Pro)?\s*(\d+\.\d+(?:\.\d+)?)", re.I)),
    # JS file header: var version = "5.15.4"
    ("js_version_var", re.compile(r"version\s*[:=]\s*[\"'](\d+\.\d+(?:\.\d+)?)[\"']", re.I)),
    # Generic FA comment block with version
    ("fa_comment_version", re.compile(r"fontawesome[\s\S]{0,200}?(\d+\.\d+\.\d+)", re.I)),
]


def looks_like_version(v: str) -> bool:
    parts = v.split(".")
    if len(parts) < 2:
        return False
    try:
        ints = [int(p) for p in parts[:3]]
    except ValueError:
        return False
    # FA versions are < 10.x
    return all(0 <= i < 100 for i in ints) and ints[0] < 10


def url_has_version(u: str) -> bool:
    for m in m2.VERSION_TOKEN.finditer(u):
        if looks_like_version(m.group(1)):
            return True
    return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(CORPUS_DIR))
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    ap.add_argument("--strategy", default="curl_cffi", choices=["requests", "curl_cffi"])
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--min-host-gap", type=float, default=0.3)
    ap.add_argument("--max-bytes", type=int, default=1024 * 1024)
    args = ap.parse_args(argv)

    corpus = Path(args.corpus_dir)
    html_files = sorted(corpus.glob("*.html"))

    # Collect (host, url) pairs to fetch: FA URLs without an extractable version.
    fetch_targets: list[tuple[str, str]] = []
    sites_with_fa = 0
    for hp in html_files:
        host = hp.stem
        html = hp.read_text(encoding="utf-8", errors="replace")
        urls = m2.extract_fa_urls(html)
        if not urls:
            continue
        sites_with_fa += 1
        for u in urls:
            full = m2.normalize(u, f"https://{host}")
            try:
                pu = urlparse(full)
                if not pu.netloc:
                    continue
            except Exception:
                continue
            # Skip if version already in URL
            if url_has_version(full):
                continue
            # Skip kit JS (no useful body for static version extraction)
            if re.search(r"kit\.fontawesome\.com|use\.fontawesome\.com/[0-9a-f]{8,}\.js", full):
                continue
            # Skip non-CSS/JS extensions to avoid binary woff/woff2
            if not re.search(r"\.(css|js)(?:\?|$)", full, re.I):
                continue
            fetch_targets.append((host, full))

    # Dedup (host, url) pairs
    seen: set[tuple[str, str]] = set()
    fetch_targets = [t for t in fetch_targets if not (t in seen or seen.add(t))]
    print(f"sites with FA URLs: {sites_with_fa}", file=sys.stderr)
    print(f"unversioned CSS/JS URLs to fetch: {len(fetch_targets)}", file=sys.stderr)

    fetcher = fetchlib.make_fetcher(args.strategy)
    throttle = fetchlib.HostThrottle(min_delay_s=args.min_host_gap)

    findings: list[dict] = []
    per_site_version: dict[str, list[dict]] = {}
    n_ok = n_err = n_match = 0
    started = time.time()
    for i, (host, url) in enumerate(fetch_targets, 1):
        u_host = urlparse(url).netloc
        throttle.acquire(u_host)
        try:
            res = fetcher.fetch(url, timeout=args.timeout, verify_ssl=False, extra_headers={})
        except Exception as e:
            n_err += 1
            print(f"  [{i:3d}/{len(fetch_targets)}] EXC {host} {url[:60]}: {e}", file=sys.stderr)
            continue
        if not res.is_ok or not res.body:
            n_err += 1
            print(f"  [{i:3d}/{len(fetch_targets)}] {res.status_tag} {host} {url[:60]}", file=sys.stderr)
            continue
        n_ok += 1
        body = res.body[: args.max_bytes]
        matched_here = []
        for rx_id, rx in BODY_RX:
            m = rx.search(body)
            if m and looks_like_version(m.group(1)):
                matched_here.append({"rx": rx_id, "version": m.group(1)})
                break  # take first/most-specific match
        if matched_here:
            n_match += 1
            row = {"host": host, "url": url, "matches": matched_here}
            findings.append(row)
            per_site_version.setdefault(host, []).append(row)
            v = matched_here[0]["version"]
            print(f"  [{i:3d}/{len(fetch_targets)}] HIT  {host:30s} -> {v}  ({matched_here[0]['rx']})", file=sys.stderr)
        else:
            print(f"  [{i:3d}/{len(fetch_targets)}] miss {host:30s} {url[:60]}", file=sys.stderr)

    elapsed = time.time() - started
    print(f"done in {elapsed:.1f}s: ok={n_ok} err={n_err} match={n_match}  sites_versioned={len(per_site_version)}", file=sys.stderr)

    Path(args.out_json).write_text(json.dumps({
        "fetched": len(fetch_targets),
        "ok": n_ok,
        "matched": n_match,
        "sites_with_version_from_body": len(per_site_version),
        "findings": findings,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Phase 3: FA version mined from body content",
        "",
        f"- Unversioned CSS/JS URLs probed: **{len(fetch_targets)}**",
        f"- Fetched OK: **{n_ok}**, errors: **{n_err}**",
        f"- Body-regex matches: **{n_match}**",
        f"- New sites with extractable version: **{len(per_site_version)}**",
        "",
        "## Findings",
        "",
        "| Host | Version | Regex | URL |",
        "|------|---------|-------|-----|",
    ]
    for row in findings:
        m0 = row["matches"][0]
        lines.append(f"| {row['host']} | {m0['version']} | {m0['rx']} | `{row['url'][:80]}` |")
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out_json}", file=sys.stderr)
    print(f"wrote {args.out_md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
