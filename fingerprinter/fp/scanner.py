"""Concurrent HTTP scan engine driven by the in-memory fingerprint cache.

Scan flow for a single target::

    1. Collect every unique path in the cache (already deduplicated).
    2. Issue one HTTP request per path, bounded by a semaphore.
    3. For each request, walk the list of template-requests that reference
       that path and evaluate their matchers against the response.
    4. When a template's matchers pass, run its extractors and record a
       Detection with name/vendor/product/version/cpe.

The engine implements the four matcher families that account for 99% of
real-world detections in /http/technologies — ``word``, ``regex``, ``status``,
``kval`` — plus a best-effort DSL evaluator for the two DSL idioms that show
up in this corpus: ``status_code == N`` and ``mmh3(base64_py(body))`` favicon
hashes.  Anything else is reported as unsupported and skipped without
corrupting detection results.
"""

from __future__ import annotations

import asyncio
import base64
import faulthandler
import hashlib
import logging
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from curl_cffi.requests import AsyncSession as _CurlSession

from fetchlib import build_request_headers as _build_request_headers

from . import backend_leaks as backend_mod
from . import jsextract as jsextract_mod
from . import retirejs as retire_mod
from . import safe_regex as sre_mod
from . import wappalyzer as wap_mod
from . import whatweb as ww_mod
from .response_sink import ResponseSink

try:  # mmh3 is optional — favicon DSL matching is a nice-to-have.
    import mmh3  # type: ignore

    _HAVE_MMH3 = True
except ImportError:  # pragma: no cover
    _HAVE_MMH3 = False

LOG = logging.getLogger("fp.scanner")

DEFAULT_UA = "Mozilla/5.0 (compatible; NucleiFpScanner/0.1)"
DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 20
# Cap scripts fetched for retire.js scanning per target. Some pages
# reference 100+ bundles via loaders; bounding keeps scan time predictable.
MAX_RETIRE_SCRIPTS = 30
# Cap paths probed by the jsextract pass. Keeps scan time bounded when a
# minified bundle contains hundreds of route strings.
MAX_JSEXTRACT_PATHS = 50
# Only try retire.js on script bodies up to this size. Bigger bundles (e.g.
# 5 MB monolithic vendor.js) are rare to hit version strings in and expensive
# to download; the 1 MB cap catches the common minified-library case.
MAX_RETIRE_BODY_BYTES = 1 * 1024 * 1024
# Loose HTML ref extractors — no DOM parser, good enough for server-rendered
# pages where CMSes and SPAs disclose bundle URLs with embedded version tags.
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc=["']([^"']+)["']""", re.IGNORECASE)
# Auxiliary HTML paths to probe when retire.js is enabled. CMS login/admin
# pages are the hotspots for third-party JS libraries (jQuery, bootstrap,
# etc.); the default nuclei probe set rarely covers them because technology-
# detection rules fire off the homepage. Keep this list small and universal.
RETIRE_AUX_PATHS = ("/wp-login.php", "/wp-admin/", "/admin/", "/login", "/user/login")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    template_id: str
    name: str
    matcher_name: str | None
    vendor: str | None
    product: str | None
    category: str | None
    cpe: str | None
    severity: str | None
    tags: list[str]
    url: str
    path: str
    extracted: dict[str, list[str]] = field(default_factory=dict)
    source: str = "nuclei"
    version: str | None = None
    confidence: int | None = None
    # Asset URL whose content triggered the matcher (e.g. a <link href> URL).
    # Distinct from `url`, which is the page URL the scanner probed. For
    # body-text word matchers we backfill this so downstream version-mining
    # has an asset URL to inspect (otherwise `url=https://site/` is useless).
    evidence_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "template_id": self.template_id,
            "name": self.name,
            "matcher_name": self.matcher_name,
            "vendor": self.vendor,
            "product": self.product,
            "category": self.category,
            "cpe": self.cpe,
            "severity": self.severity,
            "tags": self.tags,
            "url": self.url,
            "evidence_url": self.evidence_url,
            "path": self.path,
            "extracted": self.extracted,
            "version": self.version,
            "confidence": self.confidence,
        }


@dataclass
class FetchedResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    error: str | None = None
    is_baseline: bool = False  # set when (status, body sha256) matches the absent-path probe

    @property
    def header_text(self) -> str:
        # Nuclei's `part: header` serialises as "Key: Value\r\n".
        return "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())

    @property
    def body_text(self) -> str:
        # Response may not be valid utf-8 — decode leniently.
        return self.body.decode("utf-8", errors="replace")

    @property
    def response_text(self) -> str:
        return f"HTTP/1.1 {self.status}\r\n{self.header_text}\r\n{self.body_text}"


# ---------------------------------------------------------------------------
# Matcher primitives
# ---------------------------------------------------------------------------


def _part_text(resp: FetchedResponse, part: str) -> str:
    if part == "body":
        return resp.body_text
    if part == "header":
        return resp.header_text
    if part in {"response", "all", "raw"}:
        return resp.response_text
    # Unknown part values are Nuclei header-name selectors
    # (e.g. "cf_cache_status" -> "CF-Cache-Status"). Return the header
    # value or empty string so patterns like ".*" only match when the
    # header is actually present.
    lowered_hdrs = {k.lower(): v for k, v in resp.headers.items()}
    return lowered_hdrs.get(part.lower().replace("_", "-"), "")


# Tag-URL extractor used to back-fill Detection.evidence_url. Captures the
# href/src VALUE of every <link> or <script> tag in the body. Lenient regex —
# does not need to be HTML-spec-correct; we just need the URL string.
_TAG_URL_RE = re.compile(
    r'<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _find_matcher_evidence_url(resp: FetchedResponse, matcher: dict) -> str | None:
    """Return the first <link>/<script> URL whose value carries the matched
    token. None if the matcher isn't body-text-based or if no asset URL
    in the body carries it.

    Handles two matcher kinds:
      - 'word'  : substring search over each body URL string.
      - 'regex' : run regex over body; if the match span overlaps an asset
                  URL or contains href="..."/src="...", return that URL.

    Returns the raw href/src attribute value (possibly relative). Stages
    that need to fetch this URL are responsible for resolving it against
    the page URL -- the scanner does not normalise here.
    """
    if matcher.get("part", "body") != "body":
        return None
    values = matcher.get("values") or []
    if not values:
        return None
    mtype = matcher.get("type")
    body = resp.body_text
    case_ins = bool(matcher.get("case_insensitive"))

    if mtype == "word":
        urls = _TAG_URL_RE.findall(body)
        if not urls:
            return None
        for u in urls:
            haystack = u.lower() if case_ins else u
            for v in values:
                needle = v.lower() if case_ins else v
                if needle in haystack:
                    return u
        return None

    if mtype == "regex":
        # Pre-compute URL spans once.
        url_spans = [(m.group(1), m.start(1), m.end(1))
                     for m in _TAG_URL_RE.finditer(body)]
        flags = re.IGNORECASE if case_ins else 0
        for pattern in values:
            try:
                rgx = re.compile(pattern, flags)
            except re.error:
                continue
            m = rgx.search(body)
            if not m:
                continue
            # 1. Try extracting href="..."/src="..." from the matched substring.
            sub = _TAG_URL_RE.search(m.group(0))
            if sub:
                return sub.group(1)
            # 2. Otherwise return the asset URL whose span overlaps the match.
            ms, me = m.start(), m.end()
            for url, us, ue in url_spans:
                if us <= me and ue >= ms:
                    return url
            # 3. Fall back: nearest URL by position.
            after = [u for u in url_spans if u[1] >= ms]
            if after:
                return after[0][0]
        return None

    return None


def _word_match(matcher: dict, resp: FetchedResponse) -> bool:
    # Nuclei word matchers are case-sensitive by default; cache.py pre-lowers
    # `values` only when the template sets `case-insensitive: true`.
    raw = _part_text(resp, matcher["part"])
    text = raw.lower() if matcher.get("case_insensitive") else raw
    values: list[str] = matcher["values"]
    if not values:
        return False
    hits = (v in text for v in values)
    ok = all(hits) if matcher["condition"] == "and" else any(hits)
    return not ok if matcher["negative"] else ok


# Per-regex wall-clock timeout, shared with retirejs + wappalyzer via
# fp.safe_regex. The shared module owns the blacklist + diagnostic
# counters so a slow pattern observed in nuclei matchers blocks the
# same pattern when retire.js encounters it on the next target.
REGEX_TIMEOUT_S = sre_mod.DEFAULT_TIMEOUT
# Back-compat aliases. Kept so any external caller (or test that pokes
# at internals) keeps working without an import surface change.
_SLOW_REGEX_BLACKLIST = sre_mod._BLACKLIST


def _safe_regex_search(pattern: str, text: str, flags: int,
                       timeout: float = REGEX_TIMEOUT_S):
    """Thin wrapper around fp.safe_regex.safe_search for back-compat."""
    return sre_mod.safe_search(pattern, text, flags, timeout)


# ---------------------------------------------------------------------------
# Hang watchdog -- the diagnostic the user actually needs
# ---------------------------------------------------------------------------
#
# faulthandler.dump_traceback_later() registers an OS-level timer that,
# after N seconds without being cancelled, dumps the Python traceback of
# EVERY live thread to stderr -- including the C-level location of any
# thread parked inside re.search. That is the single most direct answer
# to "what line of code is hung". Armed at scan() entry, cancelled at
# scan() exit (or exception). repeat=True so a stuck scan emits a fresh
# traceback every N seconds, not just once.
#
# Multiple concurrent scans (pipeline --parallel >1) share the global
# watchdog. The reference counter ensures the first arm wins and the
# last cancel disarms; nested scans don't clobber each other's threshold.

_HANG_WATCH_LOCK = threading.Lock()
_HANG_WATCH_COUNT = 0


def _arm_hang_watch(seconds: float) -> None:
    global _HANG_WATCH_COUNT
    with _HANG_WATCH_LOCK:
        if _HANG_WATCH_COUNT == 0:
            try:
                faulthandler.dump_traceback_later(
                    seconds, repeat=True, file=sys.stderr,
                )
            except Exception:  # noqa: BLE001
                # faulthandler may be disabled in restrictive embeddings;
                # don't let diagnostics break the scan.
                pass
        _HANG_WATCH_COUNT += 1


def _disarm_hang_watch() -> None:
    global _HANG_WATCH_COUNT
    with _HANG_WATCH_LOCK:
        _HANG_WATCH_COUNT = max(0, _HANG_WATCH_COUNT - 1)
        if _HANG_WATCH_COUNT == 0:
            try:
                faulthandler.cancel_dump_traceback_later()
            except Exception:  # noqa: BLE001
                pass


def _regex_match(matcher: dict, resp: FetchedResponse) -> bool:
    text = _part_text(resp, matcher["part"])
    values: list[str] = matcher["values"]
    if not values:
        return False
    flags = re.MULTILINE | re.DOTALL
    if matcher.get("case_insensitive"):
        flags |= re.IGNORECASE
    hits = [bool(_safe_regex_search(v, text, flags)) for v in values]
    ok = all(hits) if matcher["condition"] == "and" else any(hits)
    return not ok if matcher["negative"] else ok


def _status_match(matcher: dict, resp: FetchedResponse) -> bool:
    ok = resp.status in matcher["values"]
    return not ok if matcher["negative"] else ok


def _kval_match(matcher: dict, resp: FetchedResponse) -> bool:
    # Nuclei `kval` is true if the named response header is present at all.
    lowered = {k.lower().replace("_", "-"): v for k, v in resp.headers.items()}
    checks = [k in lowered for k in matcher["values"]]
    ok = all(checks) if matcher["condition"] == "and" else any(checks)
    return not ok if matcher["negative"] else ok


# Best-effort DSL evaluator — handles the two idioms used in this corpus.
_DSL_STATUS_RE = re.compile(r"status_code\s*==\s*(\d+)")
_DSL_MMH3_RE = re.compile(r'"(-?\d+)"\s*==\s*mmh3\(base64_py\(body\)\)')


def _dsl_match(matcher: dict, resp: FetchedResponse) -> bool:
    for expr in matcher["values"]:
        if not isinstance(expr, str):
            continue
        ok = _eval_dsl_expr(expr, resp)
        if not ok:
            return False if matcher["condition"] == "and" else ok  # short-circuit AND
        if matcher["condition"] != "and":
            return not ok if matcher["negative"] else ok
    # For AND we fall through here only if every expression passed.
    return not matcher["negative"]


def _eval_dsl_expr(expr: str, resp: FetchedResponse) -> bool:
    """Evaluate the two DSL forms this corpus exercises.

    Forms handled:
      * ``status_code == N``
      * ``"HASH" == mmh3(base64_py(body))``
      * Conjunctions of the above joined by ``&&``.
    """
    parts = [p.strip() for p in expr.split("&&")]
    for part in parts:
        m = _DSL_STATUS_RE.search(part)
        if m and f"status_code=={m.group(1)}" in part.replace(" ", ""):
            if resp.status != int(m.group(1)):
                return False
            continue
        m = _DSL_MMH3_RE.search(part)
        if m:
            if not _HAVE_MMH3:
                return False
            expected = int(m.group(1))
            encoded = base64.encodebytes(resp.body)  # base64_py matches Python's base64.encodebytes
            actual = mmh3.hash(encoded)
            if actual != expected:
                return False
            continue
        # Unknown form — treat as a miss rather than a hard error.
        return False
    return True


_MATCHERS = {
    "word": _word_match,
    "regex": _regex_match,
    "status": _status_match,
    "kval": _kval_match,
    "dsl": _dsl_match,
}


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def _run_extractors(extractors: list[dict], resp: FetchedResponse) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ex in extractors:
        etype = ex["type"]
        part_text = _part_text(resp, ex["part"])
        key = ex["name"] or f"{etype}_{ex.get('group', 0)}"
        if etype == "regex":
            group = ex.get("group", 0)
            matches: list[str] = []
            for pat in ex["values"]:
                # finditer would yield matches incrementally but can't be
                # interrupted; rerun with the timeout-guarded search loop
                # so a pathological pattern can't block the whole scan.
                offset = 0
                while True:
                    sub = part_text[offset:]
                    if not sub:
                        break
                    m = _safe_regex_search(pat, sub, re.MULTILINE | re.DOTALL)
                    if m is None:
                        break
                    try:
                        matches.append(m.group(group))
                    except IndexError:
                        matches.append(m.group(0))
                    advance = m.end() if m.end() > 0 else 1
                    offset += advance
            if matches:
                out.setdefault(key, []).extend(matches)
        elif etype == "kval":
            lowered = {k.lower().replace("_", "-"): v for k, v in resp.headers.items()}
            for k in ex["values"]:
                v = lowered.get(k)
                if v:
                    out.setdefault(key, []).append(v)
    return out


# ---------------------------------------------------------------------------
# Matcher orchestration per request-group
# ---------------------------------------------------------------------------


def _evaluate_request(
    req: dict, template: dict, url: str, path: str, resp: FetchedResponse
) -> list[Detection]:
    matchers = req["matchers"]
    if not matchers:
        return []

    if req["matchers_condition"] == "and":
        # AND: every matcher must pass. Emit a single detection with no sub-name.
        for m in matchers:
            handler = _MATCHERS.get(m["type"])
            if handler is None or not handler(m, resp):
                return []
        extracted = _run_extractors(req["extractors"], resp)
        return [_make_detection(template, None, url, path, extracted)]

    # OR: each passing matcher is its own sub-detection keyed by matcher name.
    detections: list[Detection] = []
    for m in matchers:
        handler = _MATCHERS.get(m["type"])
        if handler is None:
            continue
        if handler(m, resp):
            extracted = _run_extractors(req["extractors"], resp) if req["extractors"] else {}
            evidence_url = _find_matcher_evidence_url(resp, m)
            detections.append(_make_detection(template, m["name"], url, path, extracted, evidence_url))
    return detections


def _make_detection(
    template: dict, matcher_name: str | None, url: str, path: str, extracted: dict,
    evidence_url: str | None = None,
) -> Detection:
    return Detection(
        template_id=template["id"],
        name=template["name"],
        matcher_name=matcher_name,
        vendor=template.get("vendor"),
        product=template.get("product"),
        category=template.get("category"),
        cpe=template.get("cpe"),
        severity=template.get("severity"),
        tags=template.get("tags") or [],
        url=url,
        path=path,
        extracted=extracted,
        evidence_url=evidence_url,
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def _normalise_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parts = urlsplit(target)
    return f"{parts.scheme}://{parts.netloc}"


class Scanner:
    def __init__(
        self,
        cache: dict,
        *,
        wap_cache: dict | None = None,
        retire_cache: dict | None = None,
        ww_cache: list | None = None,
        backend_probe: bool = False,
        jsextract: bool = False,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_UA,
        verify_ssl: bool = False,
        response_sink: ResponseSink | None = None,
        use_cloak: bool = False,
        cloak_mode: str = "api",
    ) -> None:
        self.cache = cache
        self.wap_cache = wap_cache
        self.retire_cache = retire_cache
        self.ww_cache = ww_cache or []
        self.backend_probe = backend_probe
        self.jsextract = jsextract
        self.sem = asyncio.Semaphore(concurrency)
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._use_cloak = use_cloak
        self._cloak_mode = cloak_mode
        # Full Chrome 121 header shape (Accept-Language, sec-ch-ua, Sec-Fetch-*,
        # etc.) -- sending the UA alone without matching client-hint headers is
        # itself a WAF tell. Single source of truth in fetchlib.headers.
        self.headers = _build_request_headers(ua=user_agent)
        self.response_sink = response_sink

    async def _compute_baseline(
        self, session: _CurlSession, base: str
    ) -> tuple[int, str] | None:
        """Probe a guaranteed-absent path to learn this host's "not found"
        response signature. A SPA / catch-all-rewrite host returns 200 +
        index.html here; the (status, body sha256) tuple lets later code
        suppress identical responses on probed paths as phantom hits.
        Returns None when the probe itself fails."""
        probe_path = f"/__fp_baseline_{uuid.uuid4().hex[:16]}"
        resp = await self._fetch(session, urljoin(base + "/", probe_path.lstrip("/")))
        if resp.error or resp.status == 0:
            return None
        return (resp.status, hashlib.sha256(resp.body).hexdigest())

    async def _fetch(
        self, session: _CurlSession, url: str
    ) -> FetchedResponse:
        async with self.sem:
            try:
                r = await session.get(url, allow_redirects=True)
                return FetchedResponse(
                    url=str(r.url),
                    status=r.status_code,
                    headers=dict(r.headers),
                    body=r.content,
                )
            except Exception as exc:  # noqa: BLE001
                return FetchedResponse(url=url, status=0, headers={}, body=b"", error=str(exc))

    def _run_matchers_sync(
        self,
        paths: list[str],
        responses: list[FetchedResponse],
        deadline: float,
    ) -> tuple[list[Detection], FetchedResponse | None, int, int, bool,
               list[tuple[int, str, int, float, int]]]:
        """Synchronous matcher loop, designed to run inside asyncio.to_thread.

        Returns (detections, root_resp, evaluated_count, skipped_count,
        budget_hit, slow_log) where slow_log is per-response timing for
        the worst offenders -- the data the user needs to identify which
        single response triggered a hang.

        slow_log entry: (response_idx, path, body_len, elapsed_s, n_requests).
        """
        detections: list[Detection] = []
        root_resp: FetchedResponse | None = None
        requests_table = self.cache["requests"]
        templates = self.cache["templates"]
        by_path = self.cache["by_path"]

        evaluated = 0
        skipped = 0
        budget_hit = False
        # Capture the worst per-response timings. Tuned tight on purpose
        # -- 1.0s of synchronous matcher work for ONE response is already
        # pathological on a 30-path nuclei probe table; we want to see
        # those so the user can correlate them with the regex-thread
        # tracebacks faulthandler emits.
        slow_threshold = 1.0
        slow_log: list[tuple[int, str, int, float, int]] = []

        for idx, (path, resp) in enumerate(zip(paths, responses)):
            if path == "/" and resp.status and not resp.error:
                root_resp = resp
            if resp.error or resp.status == 0:
                continue
            if resp.is_baseline:
                continue
            if time.monotonic() > deadline:
                if not budget_hit:
                    LOG.warning(
                        "matcher budget exhausted at idx=%d/%d (path=%r); "
                        "skipping remainder", idx, len(paths), path,
                    )
                    budget_hit = True
                skipped += 1
                continue

            evaluated += 1
            t_resp0 = time.monotonic()
            req_count = 0
            for req_pk in by_path.get(path, []):
                req = requests_table.get(req_pk) or requests_table.get(str(req_pk))
                if not req:
                    continue
                template = (
                    templates.get(req["template_pk"])
                    or templates.get(str(req["template_pk"]))
                )
                if not template:
                    continue
                req_count += 1
                req_detections = _evaluate_request(
                    req, template, resp.url, path, resp,
                )
                if req_detections:
                    detections.extend(req_detections)
                    if req["stop_at_first_match"]:
                        break
                # Inner-loop budget check: a single response can iterate
                # hundreds of template requests on broad nuclei paths
                # (e.g. /, /robots.txt). Without this check, one slow
                # response could blow past the deadline before the outer
                # loop notices.
                if time.monotonic() > deadline:
                    break

            elapsed = time.monotonic() - t_resp0
            if elapsed >= slow_threshold:
                body_len = len(resp.body) if resp.body else 0
                slow_log.append((idx, path, body_len, elapsed, req_count))

        return detections, root_resp, evaluated, skipped, budget_hit, slow_log

    async def scan(
        self, target: str, *, probe_timeout: float | None = None
    ) -> list[Detection]:
        base = _normalise_target(target)
        detections: list[Detection] = []
        _sink_responses: list[FetchedResponse] = []

        # Per-stage breadcrumb logger. Goes to stderr so the pipeline's
        # heartbeat can interleave with it and the user can see exactly
        # which scan substage is in flight. Skipped only when scan is
        # running in tests (LOG suppressed at WARNING level).
        _scan_t0 = time.monotonic()
        def _stage(name: str, detail: str = "") -> None:
            elapsed = time.monotonic() - _scan_t0
            d = f" {detail}" if detail else ""
            print(f"  [scan +{elapsed:5.1f}s] {name}{d}", file=sys.stderr, flush=True)

        # Hang watchdog. Threshold is generous enough that a normal scan
        # never trips it (probe_timeout covers fetch; matcher_budget is
        # half of that; post-stages add at most ~30s). If the threshold
        # fires, faulthandler dumps the Python C-level traceback of EVERY
        # thread to stderr -- including the daemon regex thread parked
        # inside re.search. That is the precise "where is it hung"
        # diagnostic.
        hang_threshold = (probe_timeout * 2.0 + 60.0) if probe_timeout else 180.0
        _arm_hang_watch(hang_threshold)
        # Reset per-target safe_regex counters but keep the cross-target
        # blacklist (so a slow pattern stays blacklisted on subsequent
        # targets in a bulk run).
        sre_mod.reset_call_stats()

        _stage("begin", f"{base} hang_dump_after={hang_threshold:.0f}s")
        try:
            return await self._scan_inner(target, base, probe_timeout, _stage,
                                          detections, _sink_responses)
        finally:
            _disarm_hang_watch()

    async def _scan_inner(
        self,
        target: str,
        base: str,
        probe_timeout: float | None,
        _stage,
        detections: list[Detection],
        _sink_responses: list[FetchedResponse],
    ) -> list[Detection]:

        if self._use_cloak:
            # Headless real Chromium with stealth init script. Slower per
            # fetch (~1-3s in api mode, ~3-5s in page mode) but defeats
            # JS-challenge gates curl_cffi can't. ``cloak_mode="page"``
            # is what makes Stage 5 escalation actually resolve interstitials.
            from .cloak_fetcher import AsyncCloakFetcher
            session_ctx: Any = AsyncCloakFetcher(
                mode=self._cloak_mode,
                headers=self.headers,
                timeout=self._timeout,
                verify=self._verify_ssl,
            )
        else:
            session_ctx = _CurlSession(
                impersonate="chrome120",
                headers=self.headers,
                timeout=self._timeout,
                verify=self._verify_ssl,
            )
        async with session_ctx as session:
            # Capture how the server answers a guaranteed-absent path BEFORE
            # any other request. SPA / catch-all-rewrite hosts (Vercel, Netlify,
            # Cloudflare Pages) return 200 + index.html for every unknown URL,
            # which would otherwise cause every nuclei matcher that triggers
            # on the index body to fire on every nonexistent probed path.
            baseline_sig = await self._compute_baseline(session, base)
            _stage("baseline", f"sig={'set' if baseline_sig else 'none'}")

            paths = list(self.cache["by_path"].keys())
            # Ensure the root is fetched so Wappalyzer has something to analyse
            # even if no nuclei template happens to probe "/".
            if self.wap_cache and "/" not in paths:
                paths = ["/"] + paths
            # When retire.js is enabled, also probe the small set of CMS-login
            # /admin paths where third-party JS libraries typically live —
            # nuclei templates rarely fire on these paths.
            if self.retire_cache:
                for aux in RETIRE_AUX_PATHS:
                    if aux not in paths:
                        paths.append(aux)

            # Wrap each coroutine in a Task so asyncio.wait can give us
            # partial results when probe_timeout fires. asyncio.gather would
            # block until ALL probes complete (or the outer wait_for cancels
            # everything and discards results); asyncio.wait returns done/
            # pending so we process whatever finished before the deadline.
            _stage("fetch begin", f"{len(paths)} paths probe_timeout={probe_timeout}")
            fetch_tasks = [
                asyncio.create_task(
                    self._fetch(session, urljoin(base + "/", p.lstrip("/")))
                )
                for p in paths
            ]

            if probe_timeout is not None:
                done_set, pending_set = await asyncio.wait(
                    fetch_tasks, timeout=probe_timeout
                )
                if pending_set:
                    LOG.debug(
                        "scan probe timeout: %d/%d requests cancelled for %s",
                        len(pending_set), len(fetch_tasks), base,
                    )
                    for t in pending_set:
                        t.cancel()
                    # Use asyncio.wait (not gather) for the drain so we always
                    # return after 5s even if curl_cffi tasks don't respond to
                    # cancellation (known Windows ProactorEventLoop behaviour).
                    # Remaining tasks are cleaned up when the session closes.
                    await asyncio.wait(pending_set, timeout=5.0)
                _err = FetchedResponse(url=base, status=0, headers={}, body=b"",
                                       error="probe_timeout")
                responses: list[FetchedResponse] = []
                for t in fetch_tasks:
                    if t in done_set:
                        try:
                            responses.append(t.result())
                        except Exception as exc:
                            responses.append(FetchedResponse(
                                url=base, status=0, headers={}, body=b"", error=str(exc)
                            ))
                    else:
                        responses.append(_err)
            else:
                responses = list(await asyncio.gather(*fetch_tasks))

            ok = sum(1 for r in responses if r.status and not r.error)
            _stage("fetch done", f"{ok}/{len(responses)} ok")
            _sink_responses.extend(responses)

        # Mark non-root responses whose (status, body sha256) matches the
        # baseline as phantom hits — they are the SPA shell, not a real
        # match. "/" is always preserved so genuine homepage analysis runs
        # even when the homepage IS the SPA shell.
        baseline_marked = 0
        if baseline_sig is not None:
            for path, resp in zip(paths, responses):
                if path == "/" or resp.error or resp.status == 0:
                    continue
                sig = (resp.status, hashlib.sha256(resp.body).hexdigest())
                if sig == baseline_sig:
                    resp.is_baseline = True
                    baseline_marked += 1
        _stage("baseline-mark", f"{baseline_marked} responses dedup'd")

        # Wall-clock budget for the matcher loop. Even with per-regex
        # timeouts, on hostile targets (28tech.com.vn-style SPA shells where
        # CSRF tokens defeat baseline dedup) we may discover dozens of new
        # pathological patterns, each costing 2s to detect. Cap the total
        # so the scan stage cannot consume more than `probe_timeout/2`
        # additional wall clock after the fetch deadline.
        matcher_budget = (probe_timeout / 2.0) if probe_timeout else 30.0
        matcher_deadline = time.monotonic() + matcher_budget
        sre_pre = sre_mod.stats_snapshot()
        _stage(
            "matchers begin",
            f"budget={matcher_budget:.0f}s "
            f"blacklist={sre_pre['blacklist_size']} "
            f"leaked_threads_alive={sre_pre['leaked_threads_alive']}",
        )

        # Run the synchronous matcher loop in a worker thread so the
        # event loop stays responsive (heartbeat fires, faulthandler
        # watchdog ticks, other pipeline stages can progress). Per-regex
        # threads spawned inside _evaluate_request are unaffected --
        # asyncio.to_thread just runs the function in the default
        # ThreadPoolExecutor; nested threading is fine.
        (
            matcher_dets,
            root_resp,
            evaluated_count,
            skipped_count,
            budget_hit,
            slow_responses,
        ) = await asyncio.to_thread(
            self._run_matchers_sync, paths, responses, matcher_deadline,
        )
        detections.extend(matcher_dets)

        sre_post = sre_mod.stats_snapshot()
        _stage(
            "matchers done",
            f"evaluated={evaluated_count} skipped={skipped_count} "
            f"budget_hit={budget_hit} hits={len(detections)} "
            f"regex_calls={sre_post['calls']} timeouts={sre_post['timeouts']} "
            f"slow_calls={sre_post['slow_calls']} "
            f"blacklist={sre_post['blacklist_size']} "
            f"leaked_threads_alive={sre_post['leaked_threads_alive']}",
        )
        # Per-response slow log: which responses individually owned the
        # most matcher time. If a hang reproduces, the response listed
        # here with the largest elapsed is the input that triggered it
        # -- pair this with the faulthandler traceback dump to identify
        # which template's regex backtracked on which body.
        if slow_responses:
            slow_responses.sort(key=lambda r: -r[3])
            for idx, path, body_len, elapsed, n_reqs in slow_responses[:5]:
                _stage(
                    "matchers slow-resp",
                    f"idx={idx} path={path!r} body={body_len}B "
                    f"elapsed={elapsed:.2f}s reqs_evaluated={n_reqs}",
                )
        # Top non-timeout slow regex patterns this target. Catastrophic
        # backtracking that completes JUST under REGEX_TIMEOUT_S is
        # exactly what the existing blacklist misses; logging these here
        # gives the user a "next pattern to investigate" list.
        slow_top = sre_mod.slow_top(5)
        for elapsed, pat, text_len in slow_top:
            _stage(
                "matchers slow-regex",
                f"elapsed={elapsed:.2f}s text_len={text_len} pattern={pat!r}",
            )

        if self.wap_cache and root_resp is not None:
            _stage("wappalyzer begin")
            wap_before = len(detections)
            # Offload to a worker thread: wappalyzer.evaluate runs ~2.8k
            # regex patterns synchronously and has been seen taking >30s
            # on adversarial HTML.
            wap_results = await asyncio.to_thread(
                wap_mod.evaluate,
                self.wap_cache, root_resp.url, root_resp.headers, root_resp.body,
            )
            for wd in wap_results:
                detections.append(_wap_to_detection(wd))
            _stage("wappalyzer done", f"+{len(detections)-wap_before} hits")

        if self.ww_cache and root_resp is not None:
            _stage("whatweb begin")
            ww_before = len(detections)
            ww_results = await asyncio.to_thread(
                ww_mod.scan_response,
                root_resp.url, root_resp.status,
                root_resp.headers, root_resp.body_text,
                self.ww_cache,
            )
            for hit in ww_results:
                detections.append(_ww_to_detection(hit))
            _stage("whatweb done", f"+{len(detections)-ww_before} hits")

        if self.retire_cache or self.backend_probe or self.jsextract:
            _stage("script-bodies begin")
            # Collect script refs from EVERY HTML response, not just `/`.
            # The scanner's probe list includes paths like `/wp-login.php`
            # and `/wp-admin/` whose referenced scripts often differ from
            # the homepage's — jQuery on WP lives on the login page, not
            # on Gutenberg-rendered root. Deduping across sources keeps
            # cost bounded at MAX_RETIRE_SCRIPTS in aggregate.
            html_responses = [
                r for r in responses
                if r.status and not r.error
                and _looks_like_html(r)
                and not r.is_baseline
            ]
            _stage("script-bodies html-resp", f"{len(html_responses)} html docs to crawl for <script src>")

            # Asset URL harvest: every HTML response the scanner already
            # fetched is walked for <link href> / <script src> / etc URLs;
            # url_ver mines them for CDN-versioned tech refs. This is the
            # ONE place a versioned CDN URL sitting in the homepage HTML
            # gets turned into a Detection -- without this, sites like
            # berich.vn (which load FA from cdnjs but don't put the URL
            # anywhere katana / jsextract sees) get presence-only hits.
            from . import url_ver as _uv_mod
            from urlcrawl import extract_html_link_urls as _extract_links
            _seen_link_urls: set[str] = set()
            for r in html_responses:
                for u in _extract_links(r.body_text):
                    if u and u not in _seen_link_urls:
                        _seen_link_urls.add(u)
            if _seen_link_urls:
                for _hit in _uv_mod.extract_ver_params(list(_seen_link_urls)):
                    detections.append(Detection(
                        template_id=f"url-ver:{_hit.slug}",
                        name=_hit.tech,
                        matcher_name=None,
                        vendor=None, product=_hit.tech, category=None,
                        cpe=None, severity=None, tags=[],
                        url=_hit.url, path="/",
                        extracted={},
                        source="url-ver",
                        version=_hit.version,
                    ))
                _stage(
                    "html-asset-walk",
                    f"{len(_seen_link_urls)} URLs harvested, "
                    f"+{sum(1 for d in detections if d.source == 'url-ver')} url-ver detections",
                )
            if html_responses:
                async with _CurlSession(
                    impersonate="chrome120",
                    headers=self.headers,
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                ) as session:
                    refs, script_responses = await self._fetch_script_bodies(
                        session, html_responses
                    )
                    _stage("script-bodies fetched", f"{len(refs)} unique scripts")
                    _sink_responses.extend(script_responses)
                    if self.retire_cache:
                        before = len(detections)
                        # retire.js patterns are also raw regex over
                        # bundle bodies up to 1 MiB each. Push to a
                        # worker thread so a pathological pattern can't
                        # block the event loop.
                        retire_dets = await asyncio.to_thread(
                            self._retire_scan_bodies, refs, script_responses,
                        )
                        detections.extend(retire_dets)
                        _stage("retire.js done", f"+{len(detections)-before} hits")
                    if self.backend_probe:
                        before = len(detections)
                        detections.extend(await self._backend_scan(
                            session, base,
                            html_responses=html_responses,
                            script_refs=refs,
                            script_responses=script_responses,
                        ))
                        _stage("backend-probe done", f"+{len(detections)-before} hits")
                    if self.jsextract:
                        before = len(detections)
                        js_paths = _collect_jsextract_paths(refs, script_responses)
                        detections.extend(
                            await self._probe_jsextract_paths(
                                session, base, js_paths, baseline_sig
                            )
                        )
                        _stage("jsextract done", f"+{len(detections)-before} hits")

        sre_final = sre_mod.stats_snapshot()
        _stage(
            "scan complete",
            f"total={len(detections)} "
            f"regex_calls={sre_final['calls']} "
            f"timeouts={sre_final['timeouts']} "
            f"slow_calls={sre_final['slow_calls']} "
            f"blacklist={sre_final['blacklist_size']} "
            f"leaked_threads_alive={sre_final['leaked_threads_alive']} "
            f"leaked_threads_total={sre_final['leaked_threads']}",
        )

        if self.response_sink is not None and detections:
            dets_by_url: dict[str, list[Detection]] = {}
            for d in detections:
                dets_by_url.setdefault(d.url, []).append(d)
            for resp in _sink_responses:
                matched = dets_by_url.get(resp.url)
                if matched:
                    self.response_sink.record(resp, matched, base, self.headers)

        return detections

    # --- shared script fetcher ------------------------------------------

    async def _fetch_script_bodies(
        self, session: _CurlSession,
        html_responses: list[FetchedResponse],
    ) -> tuple[list[str], list[FetchedResponse]]:
        """Extract same-host `<script src>` URLs from each HTML response,
        dedupe, and fetch bodies for retire.js / backend-leak consumers.

        Scripts are ranked by frequency (# pages that reference them) so
        core bundles beat long-tail assets when the MAX_RETIRE_SCRIPTS cap
        applies. Tie-broken by first-seen page order so root-page scripts
        always win over same-frequency scripts from later nuclei paths.
        """
        script_freq: dict[str, int] = {}
        script_first: dict[str, int] = {}
        for page_idx, resp in enumerate(html_responses):
            for url in extract_script_refs(resp.body_text, resp.url):
                script_freq[url] = script_freq.get(url, 0) + 1
                if url not in script_first:
                    script_first[url] = page_idx
        refs = sorted(
            script_freq,
            key=lambda u: (-script_freq[u], script_first[u]),
        )[:MAX_RETIRE_SCRIPTS]
        if not refs:
            return [], []
        script_responses: list[FetchedResponse] = await asyncio.gather(
            *[self._fetch(session, url) for url in refs]
        )
        # One-shot retry for transient CDN/WAF blocks (common on Cloudflare
        # targets where the first request gets a challenge and the second
        # gets the real asset).
        needs_retry = [i for i, r in enumerate(script_responses) if r.error or r.status == 0]
        if needs_retry:
            retried: list[FetchedResponse] = await asyncio.gather(
                *[self._fetch(session, refs[i]) for i in needs_retry]
            )
            for i, r in zip(needs_retry, retried):
                if not r.error and r.status:
                    script_responses[i] = r
        return refs, script_responses

    # --- retire.js scan over already-fetched bodies ----------------------

    def _retire_scan_bodies(
        self, refs: list[str], script_responses: list[FetchedResponse],
    ) -> list[Detection]:
        out: list[Detection] = []
        for url, resp in zip(refs, script_responses):
            if resp.error or resp.status >= 400 or not resp.body:
                continue
            if len(resp.body) > MAX_RETIRE_BODY_BYTES:
                continue
            body_text = resp.body_text
            parts = urlsplit(url)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            for rd in retire_mod.scan_body(body_text, url, self.retire_cache):
                out.append(_retire_to_detection(rd, url, path))
        return out

    # --- jsextract: probe paths discovered in JS bundles -----------------

    async def _probe_jsextract_paths(
        self,
        session: _CurlSession,
        base: str,
        extracted: list[jsextract_mod.ExtractedPath],
        baseline_sig: tuple[int, str] | None,
    ) -> list[Detection]:
        if not extracted:
            return []
        to_probe = extracted[:MAX_JSEXTRACT_PATHS]
        tasks = [
            self._fetch(session, urljoin(base + "/", ep.path.lstrip("/")))
            for ep in to_probe
        ]
        responses = await asyncio.gather(*tasks)
        _conf = {"call": 80, "api": 60, "template": 40}
        out: list[Detection] = []
        for ep, resp in zip(to_probe, responses):
            if resp.error or resp.status == 0:
                continue
            if baseline_sig is not None:
                sig = (resp.status, hashlib.sha256(resp.body).hexdigest())
                if sig == baseline_sig:
                    continue
            out.append(_jsextract_to_detection(ep, resp, _conf.get(ep.confidence, 50)))
        return out

    # --- bundle-leak sweep + reflective backend probes -------------------

    async def _backend_scan(
        self, session: _CurlSession, base: str,
        *,
        html_responses: list[FetchedResponse],
        script_refs: list[str],
        script_responses: list[FetchedResponse],
    ) -> list[Detection]:
        # Sweep both root HTML and any fetched script bodies for backend
        # host references. HTML catches `<script src>` to third-party hosts
        # (Stripe/Razorpay JS); scripts carry the rest of the topology.
        # No size gate here — bundle-leak detection is a regex sweep over
        # already-fetched bytes, and modern Vite/Webpack bundles routinely
        # exceed retire.js's 1 MiB pattern-matching cap while still carrying
        # the URL strings we care about.
        bodies: list[tuple[str, str]] = []
        for resp in html_responses:
            if resp.body:
                bodies.append((resp.url, resp.body_text))
        for url, resp in zip(script_refs, script_responses):
            if resp.error or not resp.body:
                continue
            bodies.append((url, resp.body_text))

        target_host = backend_mod.target_host_of(base)

        # Always emit bundle-leak detections — they cost zero extra HTTP.
        seen_leak_keys: set[tuple[str, str]] = set()
        out: list[Detection] = []
        for source_url, body in bodies:
            for leak in backend_mod.extract_leaks(body, source_url):
                key = (leak.provider or "", leak.host)
                if key in seen_leak_keys:
                    continue
                seen_leak_keys.add(key)
                out.append(_bundle_leak_to_detection(leak))

        # Reflective probes: rank provider-matched candidates first, fall
        # back to same-registrable-domain hosts. Bounded by
        # MAX_BACKEND_HOSTS × MAX_PROBES_PER_HOST inside the module.
        candidates = backend_mod.discover_candidate_hosts(bodies, target_host)
        if not candidates:
            return out
        probe_tasks = [backend_mod.probe_host(session, c) for c in candidates]
        probe_results = await asyncio.gather(*probe_tasks)
        for hits in probe_results:
            for hit in hits:
                out.append(_backend_hit_to_detection(hit))
        return out


def _collect_jsextract_paths(
    refs: list[str], script_responses: list[FetchedResponse]
) -> list[jsextract_mod.ExtractedPath]:
    """Run jsextract over already-fetched script bodies; dedupe by path."""
    seen: set[str] = set()
    out: list[jsextract_mod.ExtractedPath] = []
    for url, resp in zip(refs, script_responses):
        if resp.error or resp.status >= 400 or not resp.body:
            continue
        for ep in jsextract_mod.extract_paths(resp.body_text, source_url=url):
            if ep.path not in seen:
                seen.add(ep.path)
                out.append(ep)
    return out


def _jsextract_to_detection(
    ep: jsextract_mod.ExtractedPath, resp: FetchedResponse, confidence: int
) -> Detection:
    extracted: dict[str, list[str]] = {"status": [str(resp.status)]}
    for hdr in ("server", "x-powered-by", "x-framework", "content-type"):
        val = next((v for k, v in resp.headers.items() if k.lower() == hdr), None)
        if val:
            extracted[hdr] = [val]
    return Detection(
        template_id=f"jsextract:{ep.path}",
        name=ep.path,
        matcher_name=ep.confidence,
        vendor=None,
        product=None,
        category="api-endpoint",
        cpe=None,
        severity=None,
        tags=["jsextract", ep.confidence],
        url=resp.url,
        path=ep.path,
        extracted=extracted,
        source="jsextract",
        version=None,
        confidence=confidence,
    )


def _looks_like_html(resp: FetchedResponse) -> bool:
    """Heuristic: does this response carry HTML worth crawling for scripts?"""
    ct = resp.headers.get("Content-Type", "").lower()
    if "html" in ct:
        return True
    # Some servers omit Content-Type; fall back to a sniff.
    head = resp.body[:128].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html"))


def extract_script_refs(
    body: str, base_url: str, *, same_host_only: bool = True
) -> list[str]:
    """Pull `<script src>` URLs from an HTML body.

    Returns fully-resolved absolute URLs, deduped, capped at MAX_RETIRE_SCRIPTS.
    Drops data:, javascript:, and (when same_host_only=True) cross-host URLs.
    The scanner uses same_host_only=True (retire.js only cares about scripts the
    target serves itself). The js-extract CLI uses same_host_only=False so that
    CDN-hosted application bundles are also fetched and parsed.
    """
    if not body:
        return []
    base_netloc = urlsplit(base_url).netloc
    seen: set[str] = set()
    out: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(body):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("data:", "javascript:", "#")):
            continue
        abs_url = urljoin(base_url, raw)
        parts = urlsplit(abs_url)
        if parts.scheme not in ("http", "https"):
            continue
        if same_host_only and parts.netloc and parts.netloc != base_netloc:
            continue
        if abs_url in seen:
            continue
        seen.add(abs_url)
        out.append(abs_url)
        if len(out) >= MAX_RETIRE_SCRIPTS:
            break
    return out


def _retire_to_detection(rd: retire_mod.Detection, url: str, path: str) -> Detection:
    return Detection(
        template_id=f"retire:{rd.tech}",
        name=rd.tech,
        matcher_name=rd.source,         # 'filecontent' | 'filename' | 'uri' | 'hash'
        vendor=None,
        product=rd.tech,
        category="javascript-library",
        cpe=None,
        severity=None,
        tags=["javascript", "retirejs"],
        url=url,
        path=path,
        extracted={"version": [rd.version]} if rd.version else {},
        source="retirejs",
        version=rd.version,
    )


def _bundle_leak_to_detection(leak: backend_mod.BundleLeak) -> Detection:
    provider = leak.provider or "unknown-host"
    name = leak.provider or leak.host
    return Detection(
        template_id=f"bundle:{provider.lower().replace(' ', '-')}",
        name=name,
        matcher_name=None,
        vendor=None,
        product=leak.provider,
        category=leak.category,
        cpe=None,
        severity=None,
        tags=["bundle-leak"] + ([leak.category] if leak.category else []),
        url=leak.found_in_url,
        path="<bundle-leak>",
        extracted={"host": [leak.host]},
        source="bundle-leak",
        version=None,
        # Reference-only — host appeared in fetched code but we haven't
        # confirmed the service is alive at that host.
        confidence=70,
    )


def _backend_hit_to_detection(hit: backend_mod.BackendProbeHit) -> Detection:
    extracted = dict(hit.extracted)
    extracted.setdefault("host", [hit.host])
    if hit.evidence:
        extracted.setdefault("evidence", [hit.evidence])
    return Detection(
        template_id=f"backend:{hit.provider.lower().replace(' ', '-')}-{hit.signature.lower().replace(' ', '-')}",
        name=hit.signature,
        matcher_name=hit.evidence or None,
        vendor=None,
        product=hit.provider,
        category=hit.category,
        cpe=None,
        severity=None,
        tags=["backend-probe", hit.category],
        url=hit.probe_url,
        path=urlsplit(hit.probe_url).path or "/",
        extracted=extracted,
        source="backend-probe",
        version=None,
        # Confirmed via response shape — high confidence.
        confidence=95,
    )


def _ww_to_detection(hit: "ww_mod.WwDetection") -> Detection:
    return Detection(
        template_id=f"ww:{hit.tech_name}",
        name=hit.tech_name,
        matcher_name=None,
        vendor=None,
        product=hit.tech_name,
        category=None,
        cpe=None,
        severity=None,
        tags=[],
        url=hit.url,
        path="/",
        extracted={},
        source="whatweb",
        version=hit.version,
        confidence=80,
    )


def _wap_to_detection(wd: dict) -> Detection:
    versions = wd.get("versions") or []
    return Detection(
        template_id=f"wap:{wd['name']}",
        name=wd["name"],
        matcher_name=None,
        vendor=None,
        product=wd["name"],
        category=", ".join(wd.get("categories") or []) or None,
        cpe=wd.get("cpe"),
        severity=None,
        tags=wd.get("categories") or [],
        url=wd.get("url") or "",
        path="/",
        extracted={"version": versions} if versions else {},
        source="wappalyzer",
        version=wd.get("version"),
        confidence=wd.get("confidence"),
        evidence_url=wd.get("evidence_url"),
    )


async def scan_targets(
    cache: dict,
    targets: list[str],
    *,
    wap_cache: dict | None = None,
    retire_cache: dict | None = None,
    ww_cache: list | None = None,
    backend_probe: bool = False,
    jsextract: bool = False,
    user_agent: str = DEFAULT_UA,
    response_sink: ResponseSink | None = None,
    probe_timeout: float | None = None,
    use_cloak: bool = False,
    cloak_mode: str = "api",
    **kwargs: Any,
) -> dict[str, list[dict]]:
    scanner = Scanner(
        cache, wap_cache=wap_cache, retire_cache=retire_cache,
        ww_cache=ww_cache,
        backend_probe=backend_probe, jsextract=jsextract,
        user_agent=user_agent, response_sink=response_sink,
        use_cloak=use_cloak, cloak_mode=cloak_mode, **kwargs,
    )
    out: dict[str, list[dict]] = {}
    for target in targets:
        dets = await scanner.scan(target, probe_timeout=probe_timeout)
        out[target] = [d.to_dict() for d in dets]
    return out
