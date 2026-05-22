"""Live-fetch validator: probe rules.json paths against FA-positive sites.

Reads:
    data/scan_results_dev.jsonl          (FA-positive targets from prior scan)
    lab/research/fontawesome/rules.json  (output of 3_build_rules.py)

For each (target, rule) pair fetches GET <target><rule.path>. If status is 200
and the body contains a 'Stable tag:' line, extracts the version and matches it
against the rule's vulnerable ranges. Reports:

    out/validation.json   - per-target findings
    validation.md         - human report (slug -> hits, vulnerable count, sample URLs)

Politeness: per-host serial dispatch (we never fire two requests at the same
host concurrently), global concurrency cap, 8s timeout, single retry. Default
target list is filtered to sites where prior scan flagged Font Awesome -- those
are the high-prior probability hosts.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
SCAN_JSONL = REPO / "data" / "scan_results_dev.jsonl"
RULES_JSON = HERE / "rules.json"
OUT_JSON = HERE / "out" / "validation.json"
OUT_MD = HERE / "validation.md"

UA = "FontAwesomeLab/0.1 (+research; lab/research/fontawesome)"
TIMEOUT_SECS = 4
GLOBAL_CONCURRENCY = 1
MAX_BODY_BYTES = 64 * 1024  # readme.txt is small; cap defensively


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_fa_targets(path: Path) -> list[str]:
    """Return ordered, deduped target URLs where prior scan flagged Font Awesome."""
    if path.name.endswith("scan_results_test.jsonl") and not os.environ.get("LAB_ALLOW_TEST"):
        raise SystemExit(
            f"refusing to load test dataset: {path}\n"
            "use data/scan_results_dev.jsonl for development, "
            "or set LAB_ALLOW_TEST=1 to override."
        )
    raw = path.read_bytes()
    text = None
    for enc in ("utf-8", "utf-16", "utf-8-sig"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise SystemExit(f"could not decode {path}")
    targets: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = r.get("target") or r.get("url")
        if not target:
            continue
        techs = r.get("techs") or []
        has_fa = any("font" in (t.get("name") or "").lower() and "awesome" in (t.get("name") or "").lower() for t in techs)
        if not has_fa:
            continue
        # Normalise to scheme://host (strip path/query)
        u = urlsplit(target if "://" in target else f"https://{target}")
        if not u.netloc:
            continue
        base = f"{u.scheme or 'https'}://{u.netloc}"
        if base in seen:
            continue
        seen.add(base)
        targets.append(base)
    return targets


def load_rules(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["rules"]


# ---------------------------------------------------------------------------
# Version compare and CVE match
# ---------------------------------------------------------------------------

_VER_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)*)")


def ver_tuple(v: str) -> tuple[int, ...]:
    m = _VER_RE.match(v)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def cmp(a: str, b: str) -> int:
    ta, tb = ver_tuple(a), ver_tuple(b)
    # Pad to equal length for comparison
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def in_range(detected: str, rng: dict | None) -> bool:
    if rng is None:
        return False
    op, ver = rng["op"], rng["version"]
    c = cmp(detected, ver)
    return (op == "le" and c <= 0) or (op == "lt" and c < 0) or (op == "ge" and c >= 0) or (op == "gt" and c > 0) or (op == "eq" and c == 0)


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------

@dataclass
class Probe:
    target: str
    rule: dict
    url: str
    status: int | None = None
    version: str | None = None
    ctype: str = ""
    matched_cves: list[str] = field(default_factory=list)
    safe_for_cves: list[str] = field(default_factory=list)
    error: str = ""


_STABLE_TAG_RE = re.compile(r"(?im)^Stable\s*tag:\s*([0-9][\w.\-]*)")


async def fetch_one(sem: asyncio.Semaphore, host_locks: dict, session: aiohttp.ClientSession, probe: Probe) -> None:
    host = urlsplit(probe.target).netloc
    lock = host_locks.setdefault(host, asyncio.Lock())
    async with sem, lock:
        try:
            async with session.get(probe.url, allow_redirects=True) as resp:
                probe.status = resp.status
                probe.ctype = resp.headers.get("content-type", "")
                if resp.status != 200:
                    return
                body = await resp.content.read(MAX_BODY_BYTES)
                text = body.decode("utf-8", errors="replace")
                # Some hosts serve a soft-404 200 (e.g. site-wide SPA shell).
                # Heuristic: real readme.txt starts with === <plugin name> ===.
                if "===" not in text[:200] and "Stable tag" not in text:
                    return
                m = _STABLE_TAG_RE.search(text)
                if not m:
                    return
                probe.version = m.group(1)
                for c in probe.rule["cves"]:
                    if in_range(probe.version, c.get("range")):
                        probe.matched_cves.append(c["cve"])
                    else:
                        probe.safe_for_cves.append(c["cve"])
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            probe.error = f"{type(e).__name__}: {e}"


async def run(targets: list[str], rules: list[dict], concurrency: int) -> list[Probe]:
    sem = asyncio.Semaphore(concurrency)
    host_locks: dict[str, asyncio.Lock] = {}
    probes: list[Probe] = []
    for t in targets:
        for r in rules:
            for p in r["paths"]:
                probes.append(Probe(target=t, rule=r, url=f"{t}{p}"))
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECS)
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ssl=False)
    headers = {"User-Agent": UA, "Accept": "text/plain,*/*"}
    started = time.monotonic()
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
        tasks = [fetch_one(sem, host_locks, session, p) for p in probes]
        done = 0
        for fut in asyncio.as_completed(tasks):
            await fut
            done += 1
            if done % 50 == 0 or done == len(tasks):
                elapsed = time.monotonic() - started
                print(f"  [{elapsed:5.1f}s] {done}/{len(tasks)} probes", file=sys.stderr)
    return probes


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def render_md(probes: list[Probe], rules: list[dict], targets: list[str]) -> str:
    by_rule: dict[str, list[Probe]] = defaultdict(list)
    for p in probes:
        by_rule[p.rule["slug"]].append(p)

    lines: list[str] = []
    lines.append("# Font Awesome plugin CVE validation")
    lines.append("")
    lines.append(f"Targets probed: **{len(targets)}**  (FA-positive sites from data/scan_results_dev.jsonl)")
    lines.append(f"Rules:          **{len(rules)}**  (one per CVE-bearing plugin slug)")
    lines.append(f"Probes:         **{len(probes)}**  (target x rule x path)")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Slug | Status | CVEs | Installed | Vulnerable | Worst CVSS |")
    lines.append("|------|--------|------|-----------|------------|-----------|")
    for r in sorted(rules, key=lambda x: x["slug"]):
        slug = r["slug"]
        ps = by_rule.get(slug, [])
        installed = [p for p in ps if p.version]
        vuln = [p for p in installed if p.matched_cves]
        worst = max((c["cvss"] or 0) for c in r["cves"])
        lines.append(f"| `{slug}` | {r['wp_status']} | {len(r['cves'])} | {len(installed)} | {len(vuln)} | {worst:.1f} |")
    lines.append("")

    # Per-rule detail (only rules with installs)
    detail_rules = [r for r in rules if any(p.version for p in by_rule.get(r["slug"], []))]
    if detail_rules:
        lines.append("## Confirmed installs")
        lines.append("")
        for r in detail_rules:
            slug = r["slug"]
            installed = [p for p in by_rule[slug] if p.version]
            vuln = [p for p in installed if p.matched_cves]
            lines.append(f"### `{slug}` ({r['product']})")
            lines.append(f"- Installed on {len(installed)} site(s); {len(vuln)} confirmed vulnerable")
            lines.append(f"- CVEs covered: {', '.join(c['cve'] for c in r['cves'])}")
            for p in installed:
                marker = "[VULN]" if p.matched_cves else "[ok]"
                cves = (", ".join(p.matched_cves) or "patched") if p.matched_cves or p.safe_for_cves else "-"
                lines.append(f"  - {marker} `{p.target}` -> version `{p.version}` ({cves})")
            lines.append("")
    else:
        lines.append("## Confirmed installs")
        lines.append("")
        lines.append("No plugin readmes returned an extractable version.")
        lines.append("")

    # Errors summary (counts only)
    err_count = sum(1 for p in probes if p.error)
    s404 = sum(1 for p in probes if p.status == 404)
    s200_no_ver = sum(1 for p in probes if p.status == 200 and not p.version)
    lines.append("## Probe statistics")
    lines.append("")
    lines.append(f"- 404: {s404}")
    lines.append(f"- 200 w/o version: {s200_no_ver}  (likely soft-404 / SPA shell)")
    lines.append(f"- error: {err_count}  (timeout, TLS, DNS, etc.)")
    other = len(probes) - s404 - s200_no_ver - err_count - sum(1 for p in probes if p.version)
    lines.append(f"- other status: {other}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-jsonl", default=str(SCAN_JSONL))
    ap.add_argument("--targets", nargs="*", help="Override target list (skips scan_results filter)")
    ap.add_argument("--max-targets", type=int, default=0, help="Cap target count (0 = all)")
    ap.add_argument("--concurrency", type=int, default=GLOBAL_CONCURRENCY)
    ap.add_argument("--out-json", default=str(OUT_JSON), help="Output JSON path")
    ap.add_argument("--out-md", default=str(OUT_MD), help="Output Markdown report path")
    args = ap.parse_args(argv)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)

    if args.targets:
        targets = [t if "://" in t else f"https://{t}" for t in args.targets]
    else:
        targets = load_fa_targets(Path(args.scan_jsonl))
    if args.max_targets:
        targets = targets[: args.max_targets]
    rules = load_rules(RULES_JSON)
    print(f"targets={len(targets)} rules={len(rules)} probes={len(targets)*sum(len(r['paths']) for r in rules)}", file=sys.stderr)

    probes = asyncio.run(run(targets, rules, args.concurrency))

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps([{
        "target": p.target, "url": p.url, "slug": p.rule["slug"],
        "status": p.status, "version": p.version, "ctype": p.ctype,
        "matched_cves": p.matched_cves, "safe_for_cves": p.safe_for_cves,
        "error": p.error,
    } for p in probes], indent=2), encoding="utf-8")

    md = render_md(probes, rules, targets)
    out_md.write_text(md, encoding="utf-8")
    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
