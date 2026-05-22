"""Back-test lab-mined rules against a scanner JSONL.

For every detected tech in scan_results.jsonl (optionally filtering to
techs the scanner could not version), find lab rules whose library/plugin
slug normalizes to the same name, and fetch `<target_scheme_host><rule.path>`
to run the rule's regex against the body. Report extracted versions.
"""

from __future__ import annotations

import random
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

# Shared HTTP-fetch primitives live under fingerprinter/fetchlib/. Add the
# repo's fingerprinter/ dir to sys.path so we can import without packaging.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_FP_DIR = _REPO_ROOT / "fingerprinter"
if str(_FP_DIR) not in sys.path:
    sys.path.insert(0, str(_FP_DIR))
# Make ``lab.core`` importable for the JSONL reader re-export below.
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import fetchlib  # noqa: E402
from fetchlib import (  # noqa: E402
    BROWSER_HEADERS,
    CHROME_UA,
    FetchResult,
    HostThrottle,
    MAX_BODY_BYTES,
    available_strategies,
    detect_block,
    make_fetcher,
)
from lab.core.corpus import read_jsonl as _read_jsonl_core, guard_test_dataset as _guard_test_dataset_core  # noqa: E402


DEFAULT_UA = CHROME_UA
DEFAULT_STRATEGY = "curl_cffi"


def http_client_info(strategy: str | None = None) -> str:
    """One-line label of the active HTTP strategy. Surfaced in the UI."""
    avail = available_strategies()
    if strategy is None:
        strategy = DEFAULT_STRATEGY if avail.get(DEFAULT_STRATEGY) else "requests"
    if not avail.get(strategy, False):
        return f"{strategy} (NOT AVAILABLE; falling back to requests)"
    if strategy == "curl_cffi":
        return "curl_cffi (TLS-impersonate: chrome120)"
    if strategy == "playwright":
        return ("playwright (headless real Chrome via channel=auto -> "
                "system Chrome / Edge / bundled chromium fallback; "
                "stealth init script)")
    return "requests (UA spoofing only; install curl_cffi for TLS bypass)"


# JSONL reading lives in lab.core.corpus (single canonical implementation,
# shared by research_cycle.py, this module, and any per-tech mining script).
# Re-export for back-compat with callers using ``import backtest;
# backtest.read_jsonl(...)``.
read_jsonl = _read_jsonl_core
_guard_test_dataset = _guard_test_dataset_core


# ---------------------------------------------------------------------------
# Tech-name <-> lab-slug index
# ---------------------------------------------------------------------------

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def build_lab_index(libs) -> dict[str, list]:
    """Map normalized name -> [Library, ...].

    A lab entry is indexed under both its directory slug and its product
    name (when known) so 'better font awesome' (scan name) matches
    'better-font-awesome' (slug) AND 'Better Font Awesome' (product).
    """
    idx: dict[str, list] = defaultdict(list)
    for lib in libs:
        if lib.rule_count == 0:
            continue
        keys = {_norm(lib.slug), _norm(lib.name)}
        keys.discard("")
        for k in keys:
            idx[k].append(lib)
    return idx


def _collect_url_pool(rec: dict) -> list[tuple[str, str]]:
    """All URLs the scanner already discovered for this target.

    Returns (url, discovered_via) tuples, deduped on url. `discovered_via`
    is `endpoint:<discovered_by>` or `evidence:<source>` so the back-test
    result can show where the URL came from.
    """
    seen: dict[str, str] = {}
    for e in rec.get("endpoints", []) or []:
        u = (e.get("url") or "").strip()
        if u and u not in seen:
            seen[u] = f"endpoint:{e.get('discovered_by') or '?'}"
    for tech in rec.get("techs", []) or []:
        for ev in tech.get("evidence", []) or []:
            u = (ev.get("url") or "").strip()
            if u and u not in seen:
                seen[u] = f"evidence:{ev.get('source') or '?'}"
    return list(seen.items())


def _default_url_patterns_for(lib) -> list[dict]:
    """Auto-derive WP `?ver=X.Y.Z` URL pattern from each lib's slug.

    WP convention: every plugin/library asset is loaded with `?ver=X.Y.Z`
    in the query. So `jquery.min.js?ver=3.7.1`, `font-awesome.css?ver=5.1.5`
    are universal. The pattern requires the library's name to appear in the
    URL path - this is the false-positive guard so e.g. the FA pattern
    doesn't extract jQuery's version off a `jquery?ver=` URL.

    Skipped if the lib already declares its own url_patterns.
    """
    if lib.url_pattern_rules:
        return []
    norm = re.sub(r"[^a-z0-9]+", "[-_]?", lib.slug.lower()).strip("[-_]?")
    if not norm:
        return []
    return [{
        "pattern": rf"(?:^|[/]){norm}[^?]*\?ver=([0-9][\w.\-]*)",
        "regex_family": f"WP asset URL: ?ver=X.Y.Z ({lib.slug}) [auto]",
        "validated_examples": [],
    }]


def build_pattern_pool(libs) -> list[dict]:
    """Collect every unique regex string mined across the entire lab.

    Lab regex patterns are generic in version content (capture group) and
    only plugin-specific in *where* they were mined. The same `Stable tag:`
    regex shows up across every WP plugin's readme rule, the same JSON
    `"version":` pattern across every package.json rule, etc. Pooling them
    universally - and applying every pattern to every back-test URL whose
    tech matched the lab - eliminates the "lab didn't happen to mine this
    pattern for this plugin" gap that we hit on font-awesome's readme.txt.

    Deduped by exact regex string. First seen wins for attribution.
    """
    seen: set[str] = set()
    pool: list[dict] = []
    for lib in libs:
        for rule in lib.rules.get("rules", []) or []:
            regex = rule.get("regex") or ""
            if not regex or regex in seen:
                continue
            seen.add(regex)
            pool.append({
                "regex": regex,
                "regex_family": rule.get("regex_family") or "",
                "origin_slug": lib.slug,
                "origin_path": rule.get("path") or "",
            })
    return pool


def find_matching_libs(idx: dict[str, list], tech_name: str) -> list:
    """Look up libs for a scan-side tech name.

    Strategy:
    1. Exact match on the normalized tech name (cheap and unambiguous).
    2. Substring match: if a lab key is contained in the normalized tech
       name, it's a hit. This catches nuclei template names with extra
       suffixes like 'Font Awesome Detection' -> 'fontawesomedetection'
       which contains lab key 'fontawesome'. Guard on key length >= 4 so
       very short keys can't accidentally hit half the corpus.

    Returns deduped Library list preserving first-seen order across both
    match passes.
    """
    norm = _norm(tech_name)
    if not norm:
        return []
    seen_ids: set[int] = set()
    out: list = []
    # Pass 1: exact
    for lib in idx.get(norm, []):
        if id(lib) not in seen_ids:
            seen_ids.add(id(lib))
            out.append(lib)
    # Pass 2: substring (lab key inside normalized tech name)
    for k, libs in idx.items():
        if len(k) < 4 or k == norm or k not in norm:
            continue
        for lib in libs:
            if id(lib) not in seen_ids:
                seen_ids.add(id(lib))
                out.append(lib)
    return out


# ---------------------------------------------------------------------------
# Candidate / Result
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    target: str                 # original target string from scan record
    target_host: str            # "scheme://host" derived from target
    tech_name: str              # scan-side tech name (lowercased)
    lib_slug: str               # lab dir name that matched
    rule_path: str              # informational - lab rule's canonical path
    rule_regex: str             # Python regex with one capture group
    rule_label: str             # regex_family label, for reporting
    evidence_url: str           # body kind: URL to fetch. url kind: URL to regex-match.
    evidence_source: str = ""   # which scanner source recorded the evidence
    kind: str = "body"          # "body" (fetch+regex) or "url" (regex on URL string only)
    discovered_via: str = ""    # url kind only: where the URL came from in the scan record

    @property
    def url(self) -> str:
        return self.evidence_url

    def to_row(self) -> dict:
        d = asdict(self)
        d["regex_family"] = d.pop("rule_label")
        d["url"] = self.url
        return d


@dataclass
class Result:
    candidate: Candidate
    status: str                 # "ok" | "no_match" | "http_4xx" | "http_5xx" | "error"
    http_status: int | None = None
    extracted_version: str | None = None
    error: str | None = None

    def to_row(self) -> dict:
        return {
            "target": self.candidate.target,
            "tech": self.candidate.tech_name,
            "lib_slug": self.candidate.lib_slug,
            "rule_path": self.candidate.rule_path,
            "regex_family": self.candidate.rule_label,
            "url": self.candidate.url,
            "evidence_source": self.candidate.evidence_source,
            "status": self.status,
            "http_status": self.http_status,
            "extracted_version": self.extracted_version or "",
            "error": self.error or "",
        }


# ---------------------------------------------------------------------------
# Build candidates from scan results
# ---------------------------------------------------------------------------

def _target_host(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    p = urlparse(t)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def iter_candidates(
    scan_path: Path,
    libs,
    *,
    only_unversioned: bool = True,
    use_pattern_pool: bool = True,
) -> Iterable[Candidate]:
    """Yield Candidates only for tech detections the scanner already recorded
    evidence URLs for.

    URL source: the detection's `evidence[].url` array (the exact URL where
    the scanner observed the tech leaking).

    Regex sources, applied in this order to each (URL, tech) pair:
      1. Per-lib rules whose library slug normalizes to (or contains) the
         detected tech's name. The lab's mined `(path, regex)` pairs are
         attached here with full attribution.
      2. The universal pattern pool (every unique regex mined anywhere in
         the lab). This catches the case where the right pattern was mined
         for a sibling plugin but not for the one the scanner detected.
         Disable with `use_pattern_pool=False`.

    Dedups by (evidence_url, regex string) globally so the same pattern
    contributed by multiple sources is fetched + tested once per URL.
    """
    idx = build_lab_index(libs)
    pool = build_pattern_pool(libs) if use_pattern_pool else []
    seen: set[tuple[str, str, str]] = set()   # (url, regex, kind)
    for rec in read_jsonl(scan_path):
        target = (rec.get("target") or "").strip()
        if not target:
            continue
        host = _target_host(target)
        # Per-record URL pool (endpoints + every tech's evidence URLs). Used
        # below to apply URL-pattern rules without any HTTP fetch.
        url_pool = _collect_url_pool(rec)
        for tech in rec.get("techs", []) or []:
            if only_unversioned and tech.get("version"):
                continue
            name = (tech.get("name") or "").lower().strip()
            if not name:
                continue
            matched_libs = find_matching_libs(idx, name)
            if not matched_libs:
                continue
            for ev in tech.get("evidence", []) or []:
                ev_url = (ev.get("url") or "").strip()
                if not ev_url:
                    continue
                ev_source = (ev.get("source") or "").strip()

                # Pass 1: per-lib body rules (preserves rule_path attribution).
                for lib in matched_libs:
                    for rule in lib.rules.get("rules", []) or []:
                        regex = rule.get("regex") or ""
                        if not regex:
                            continue
                        key = (ev_url, regex, "body")
                        if key in seen:
                            continue
                        seen.add(key)
                        yield Candidate(
                            target=target,
                            target_host=host,
                            tech_name=name,
                            lib_slug=lib.slug,
                            rule_path=(rule.get("path") or "").strip(),
                            rule_regex=regex,
                            rule_label=rule.get("regex_family") or "",
                            evidence_url=ev_url,
                            evidence_source=ev_source,
                            kind="body",
                        )

                # Pass 2: universal pattern pool over the same evidence URL.
                for entry in pool:
                    key = (ev_url, entry["regex"], "body")
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Candidate(
                        target=target,
                        target_host=host,
                        tech_name=name,
                        lib_slug=f"pool:{entry['origin_slug']}",
                        rule_path=entry["origin_path"],
                        rule_regex=entry["regex"],
                        rule_label=entry["regex_family"],
                        evidence_url=ev_url,
                        evidence_source=ev_source,
                        kind="body",
                    )

            # Pass 2.5: bundled-tech rules. For each matched lab lib, the
            # lib may declare paths inside its own tree that bundle another
            # tech's version-bearing asset (e.g., a WP plugin shipping FA's
            # CSS at /vendor/.../font-awesome.min.css). Construct the URL
            # against the target's host and treat it like a body candidate.
            for lib in matched_libs:
                for brule in lib.bundled_tech_rules:
                    tmpl = (brule.get("url_path_template") or "").strip()
                    regex = brule.get("regex") or ""
                    if not tmpl or not regex or not host:
                        continue
                    bundled_url = host.rstrip("/") + tmpl
                    key = (bundled_url, regex, "body")
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Candidate(
                        target=target,
                        target_host=host,
                        tech_name=name,
                        lib_slug=f"bundled:{brule.get('bundled_tech') or '?'}",
                        rule_path=tmpl,
                        rule_regex=regex,
                        rule_label=brule.get("regex_family") or "",
                        evidence_url=bundled_url,
                        evidence_source=f"bundled-in:{lib.slug}",
                        kind="bundled",
                    )

            # Pass 3: URL-pattern rules against the per-target URL pool.
            # Runs ONCE per (matched_tech, lib) - independent of evidence URLs
            # (the URL pool is what the scanner already discovered).
            for lib in matched_libs:
                upatterns = list(lib.url_pattern_rules) + _default_url_patterns_for(lib)
                if not upatterns:
                    continue
                for upat in upatterns:
                    regex = upat.get("pattern") or ""
                    if not regex:
                        continue
                    for url, via in url_pool:
                        key = (url, regex, "url")
                        if key in seen:
                            continue
                        seen.add(key)
                        yield Candidate(
                            target=target,
                            target_host=host,
                            tech_name=name,
                            lib_slug=lib.slug,
                            rule_path="",
                            rule_regex=regex,
                            rule_label=upat.get("regex_family") or "",
                            evidence_url=url,
                            evidence_source="",
                            kind="url",
                            discovered_via=via,
                        )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
# Block detection, BROWSER_HEADERS, CHROME_UA, HostThrottle, and the three
# fetcher implementations all live in `fingerprinter/fetchlib/` so the
# scanner and the back-test share one source of truth. The only piece
# that stays local is `_apply_regex` - that's back-test-specific.


# ---------------------------------------------------------------------------
# Cross-host HTML link walk (closes the scanner's missing <link href> step)
# ---------------------------------------------------------------------------
# Single source of truth for the broad <tag href|src=URL> regex now lives
# in fp.jsextract (re-exported here so the rest of this file keeps the same
# call sites). Keep aliases pointing at the shared helpers.

from urlcrawl import (  # noqa: E402
    HTML_LINK_URL_RE as _HTML_URL_RE,
    looks_like_html as _looks_like_html,
    extract_html_link_urls as _extract_html_urls,
)


def cross_host_walk_pass(
    scan_path: Path,
    libs,
    *,
    strategy: str = DEFAULT_STRATEGY,
    verify_ssl: bool = False,
    timeout: float = 10.0,
    ua: str = DEFAULT_UA,
    min_delay_s: float = 0.3,
    jitter_s: float = 0.15,
    max_targets: int | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Result]:
    """Second-pass extraction that closes the scanner's missing cross-host
    `<link href>` walk.

    For each FA-flagged target with at least one HTML evidence URL, fetch
    the homepage, regex out `<link>/<script>/<img>` URLs, keep the ones
    containing a normalized matched-lib slug substring, then apply that
    lib's `url_patterns` to each kept URL. No body fetch needed for the
    extracted URLs - the version sits in the URL path itself (e.g.
    `use.fontawesome.com/releases/v6.6.0/`).
    """
    if not libs:
        return []
    idx = build_lab_index(libs)
    libs_by_slug = {lib.slug: lib for lib in libs}

    # Pre-compile lib slug keywords. For each lib, derive substrings we
    # search for in extracted URLs (normalized + dashed forms).
    lib_keywords: dict[str, set[str]] = {}
    for lib in libs:
        if not lib.url_pattern_rules:
            continue
        norm = _norm(lib.slug)
        keys = {norm, lib.slug.lower()}
        keys.discard("")
        lib_keywords[lib.slug] = keys

    # Build the walk target set: per target, which matched libs.
    targets: dict[str, set[str]] = {}   # target_homepage_url -> {matched_lib_slug}
    for rec in read_jsonl(scan_path):
        target = (rec.get("target") or "").strip()
        if not target:
            continue
        host = _target_host(target)
        if not host:
            continue
        matched_for_target: set[str] = set()
        for tech in rec.get("techs", []) or []:
            name = (tech.get("name") or "").lower().strip()
            if not name:
                continue
            for lib in find_matching_libs(idx, name):
                if lib.slug in lib_keywords:
                    matched_for_target.add(lib.slug)
        if matched_for_target:
            # Walk the homepage (cheapest, most reliable HTML page).
            targets[host.rstrip("/") + "/"] = matched_for_target

    if max_targets:
        items = list(targets.items())[:max_targets]
        targets = dict(items)

    if not targets:
        return []

    fetcher = make_fetcher(strategy, verify_ssl=verify_ssl)
    throttle = HostThrottle(min_delay_s=min_delay_s, jitter_s=jitter_s)
    out: list[Result] = []
    total = len(targets)

    try:
        for i, (homepage, slugs) in enumerate(targets.items(), 1):
            host = urlparse(homepage).netloc
            throttle.acquire(host)
            fr = fetcher.fetch(homepage, timeout=timeout, ua=ua, verify_ssl=verify_ssl)
            if not fr.is_ok or not _looks_like_html(fr.body):
                if progress_cb:
                    progress_cb(i, total)
                continue
            extracted = _extract_html_urls(fr.body)
            # Filter cross-host (and same-host) URLs to those carrying any
            # matched lib's slug substring. Match against URL lowered +
            # non-alnum-stripped so 'font-awesome' and 'fontawesome' both hit.
            for u in extracted:
                u_norm = re.sub(r"[^a-z0-9]", "", u.lower())
                for slug in slugs:
                    if not any(k in u_norm for k in lib_keywords[slug] if k):
                        continue
                    lib = libs_by_slug[slug]
                    # Apply this lib's url_patterns to the URL string itself.
                    for upat in lib.url_pattern_rules:
                        try:
                            m = re.search(upat.get("pattern", ""), u)
                        except re.error:
                            continue
                        if not m:
                            continue
                        try:
                            version = m.group(1)
                        except IndexError:
                            continue
                        synth = Candidate(
                            target=homepage.rstrip("/"),
                            target_host=host,
                            tech_name=f"(html-walk via {slug})",
                            lib_slug=f"html-walk:{slug}",
                            rule_path="",
                            rule_regex=upat.get("pattern", ""),
                            rule_label=upat.get("regex_family", ""),
                            evidence_url=u,
                            evidence_source=f"html-walk:{homepage}",
                            kind="url",
                            discovered_via=f"html-walk:{homepage}",
                        )
                        out.append(Result(synth, status="ok",
                                          http_status=fr.http_status,
                                          extracted_version=version))
            if progress_cb:
                progress_cb(i, total)
    finally:
        fetcher.close()

    return out


def _apply_regex(cand: Candidate, body: str, http_status: int | None) -> Result:
    try:
        m = re.search(cand.rule_regex, body)
    except re.error as e:
        return Result(cand, status="error", http_status=http_status,
                      error=f"regex compile: {e}")
    if not m:
        return Result(cand, status="no_match", http_status=http_status)
    try:
        version = m.group(1)
    except IndexError:
        version = m.group(0)
    return Result(cand, status="ok", http_status=http_status,
                  extracted_version=version)


def run_backtest(
    candidates: list[Candidate],
    *,
    concurrency: int = 10,
    timeout: float = 10.0,
    ua: str = DEFAULT_UA,
    verify_ssl: bool = False,
    strategy: str = DEFAULT_STRATEGY,
    min_delay_s: float = 0.25,
    jitter_s: float = 0.15,
    retry_on_block: bool = True,
    retry_backoff_s: float = 2.0,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Result]:
    """Dedupe HTTP fetches by URL: every unique evidence URL is fetched once,
    and ALL candidate regexes attached to that URL are applied to the single
    fetched body. Progress is reported in URLs, not in candidates.
    """
    if not candidates:
        return []

    # Split off URL-kind candidates - they don't need HTTP, just regex
    # against the URL string itself.
    url_kind = [c for c in candidates if c.kind == "url"]
    body_kind = [c for c in candidates if c.kind != "url"]

    results: list[Result] = []
    for c in url_kind:
        try:
            m = re.search(c.rule_regex, c.url)
        except re.error as e:
            results.append(Result(c, status="error", error=f"regex compile: {e}"))
            continue
        if not m:
            results.append(Result(c, status="no_match"))
            continue
        try:
            version = m.group(1)
        except IndexError:
            version = m.group(0)
        results.append(Result(c, status="ok", extracted_version=version))

    if not body_kind:
        if progress_cb is not None:
            progress_cb(len(url_kind), len(url_kind))
        return results

    by_url: dict[str, list[Candidate]] = defaultdict(list)
    for c in body_kind:
        by_url[c.url].append(c)

    total_urls = len(by_url)
    fetcher = make_fetcher(strategy, verify_ssl=verify_ssl)
    throttle = HostThrottle(min_delay_s=min_delay_s, jitter_s=jitter_s)

    # Playwright's sync runtime isn't thread-safe; serialize when it's
    # active. The other strategies are safe to fan out at `concurrency`.
    effective_concurrency = 1 if strategy == "playwright" else max(1, concurrency)

    def _fetch_one(url: str) -> FetchResult:
        host = urlparse(url).netloc
        throttle.acquire(host)
        fr = fetcher.fetch(url, timeout=timeout, ua=ua, verify_ssl=verify_ssl)
        if retry_on_block and fr.is_blocked:
            time.sleep(retry_backoff_s + random.uniform(0, jitter_s * 2))
            throttle.acquire(host)
            fr2 = fetcher.fetch(url, timeout=timeout, ua=ua, verify_ssl=verify_ssl)
            if not fr2.is_blocked:
                return fr2
        return fr

    try:
        with ThreadPoolExecutor(max_workers=effective_concurrency) as pool:
            futs = {pool.submit(_fetch_one, url): url for url in by_url}
            done = 0
            for fut in as_completed(futs):
                url = futs[fut]
                fr: FetchResult = fut.result()
                cands_for_url = by_url[url]
                if fr.is_ok:
                    for cand in cands_for_url:
                        results.append(_apply_regex(cand, fr.body, fr.http_status))
                else:
                    # Same fetch outcome applies to every candidate sharing this URL.
                    if fr.status_tag == "empty":
                        rstatus, rerr = "no_match", "empty body"
                    elif fr.status_tag == "blocked":
                        rstatus, rerr = "blocked", fr.error  # vendor label
                    elif fr.status_tag == "error":
                        rstatus, rerr = "error", fr.error
                    else:
                        rstatus, rerr = fr.status_tag, None
                    for cand in cands_for_url:
                        results.append(Result(
                            cand, status=rstatus, http_status=fr.http_status, error=rerr,
                        ))
                done += 1
                if progress_cb is not None:
                    progress_cb(done, total_urls)
    finally:
        fetcher.close()
    return results


# ---------------------------------------------------------------------------
# Aggregate summary
# ---------------------------------------------------------------------------

@dataclass
class BacktestSummary:
    total: int = 0
    ok: int = 0
    no_match: int = 0
    http_4xx: int = 0
    http_5xx: int = 0
    blocked: int = 0
    error: int = 0
    distinct_target_tech_versioned: int = 0  # (target, tech) pairs with >= 1 ok


def summarize(results: list[Result]) -> BacktestSummary:
    s = BacktestSummary(total=len(results))
    pairs: set[tuple[str, str]] = set()
    for r in results:
        if r.status == "ok":
            s.ok += 1
            pairs.add((r.candidate.target, r.candidate.tech_name))
        elif r.status == "no_match":
            s.no_match += 1
        elif r.status == "http_4xx":
            s.http_4xx += 1
        elif r.status == "http_5xx":
            s.http_5xx += 1
        elif r.status == "blocked":
            s.blocked += 1
        else:
            s.error += 1
    s.distinct_target_tech_versioned = len(pairs)
    return s
