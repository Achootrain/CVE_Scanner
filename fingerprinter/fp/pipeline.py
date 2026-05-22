"""End-to-end fully-automated tech+version fingerprinting pipeline.

Orchestrates the unauthenticated (no session, no browser) fingerprint
sources into a single per-target output suitable for AI-training ground
truth. Composes:

  1. ``scanner.scan_targets`` -- nuclei + Wappalyzer + retire.js +
     backend-leak probes + JS endpoint extraction (one engine call).
  2. ``katana.crawl`` -- static endpoint extraction + config-blob leak
     extraction over the HTML body sweep. Optional (requires the katana
     binary on PATH).
  3. ``version_probes.run_catalog`` -- hand-curated path/regex disclosure
     probes for self-hosted CMS / apps / BaaS.

Browser-driven sources (``session-capture``, ``browser-capture``) are
deliberately excluded from this pipeline -- they require interactive
login. They are listed as future-work in the output's ``unfinished``
field so consumers know the corpus is upper-bounded by what static
probing can see.

Output schema (per target):

    {
      "target": "https://...",
      "techs": [
        {
          "name": "WordPress",
          "version": "6.4.3",
          "version_confidence": "exact" | "approx" | None,
          "categories": ["CMS"],
          "sources": ["wappalyzer", "version-probe", "nuclei"],
          "evidence": [{"source":..., "template_id":..., "url":..., "version":...}, ...],
        },
        ...
      ],
      "leaks": {
        "config_blob": [...],     // ConfigLeak.to_dict() entries
        "backend_hosts": [...],   // distinct hosts surfaced from leaks
      },
      "endpoints": [...],         // katana/jsextract paths if available
      "stats": {...},
      "unfinished": ["session-capture", "browser-capture"],
    }
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from . import backend_leaks as bl_mod
from . import cache as cache_mod
from . import cdn_check as cdn_mod
from . import whatweb as ww_mod
from . import cross_page as cross_page_mod
from . import katana as katana_mod
from . import progress as progress_mod
from . import response_sink as sink_mod
from . import retirejs as retire_mod
from . import scanner as scanner_mod
from . import version_probes as vp_mod
from . import wappalyzer as wap_mod
from . import url_ver as uv_mod

LOG = logging.getLogger("fp.pipeline")


# ---------------------------------------------------------------------------
# User-Agent presets
# ---------------------------------------------------------------------------
#
# The honest scanner UA gets soft-blocked by Cloudflare bot-management on
# forum / news / e-commerce targets, which strips dynamic markers from the
# response (XenForo brand tags, framework cookies, even some response
# headers). The "chrome" preset reuses the same Chrome UA that
# backend_leaks.py already uses for cross-host probes -- proven WAF-
# transparent on Supabase + masterji.co (Phase 5b live verification).
# Switching it on for the main scan is the single biggest detection
# improvement on bot-fronted targets.

UA_PRESETS = {
    "scanner": scanner_mod.DEFAULT_UA,    # Honest "this is a scanner" UA
    "chrome": bl_mod.PROBE_USER_AGENT,    # Chrome 121 desktop -- WAF-transparent
}


def resolve_ua(spec: str) -> str:
    """Resolve a UA spec into the actual UA string.

    Accepts a preset name (``scanner`` / ``chrome``) or a verbatim UA
    string. Anything not in the preset table is treated as a literal UA so
    the user can paste their own browser's UA directly.
    """
    return UA_PRESETS.get(spec, spec)


# ---------------------------------------------------------------------------
# Tech reconciliation
# ---------------------------------------------------------------------------


@dataclass
class TechRecord:
    """Unified per-tech record after merging all sources."""
    name: str
    version: str | None = None
    version_confidence: str | None = None  # "exact" | "approx"
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "version_confidence": self.version_confidence,
            "categories": sorted(set(self.categories)),
            "sources": sorted(set(self.sources)),
            "evidence": self.evidence,
        }


# Source-precedence for version reconciliation: when two sources report a
# version for the same tech, pick the more authoritative one. version-probe
# wins because the catalog is hand-curated and exact-string-anchored.
_SOURCE_RANK = {
    "version-probe": 5,
    "retirejs": 4,
    "lab": 4,            # mined + cross-validated against real source tarballs
    "banner": 4,         # BodyExtractStage banner_rules -- source-grounded per §6
    "readme": 4,         # SlugReadmeStage slug_url_rules -- source-grounded per §6
    "wappalyzer": 3,
    "whatweb": 3,
    "nuclei": 2,
    "backend-probe": 2,
    "url-ver": 2,
    "bundle-leak": 1,
    "config-leak": 1,
}


def _is_more_specific(a: str, b: str) -> bool:
    """Return True if version `a` is more specific (more dots) than `b`.
    Used to prefer 1.2.3 over 1.2 when both come from the same-rank source."""
    return a.count(".") > b.count(".")


def _norm_name(name: str) -> str:
    """Canonicalise tech name for dedup. Strips ``wap:`` / ``retire:`` /
    ``vp:`` prefixes, lowercases, and collapses spaces to hyphens so
    ``jQuery Migrate`` (Wappalyzer) and ``jquery-migrate`` (retire.js) merge."""
    for pfx in ("wap:", "retire:", "vp:"):
        if name.lower().startswith(pfx):
            name = name[len(pfx):]
    return name.strip().lower().replace(" ", "-")


def _add_evidence(
    rec: TechRecord, source: str, version: str | None, evidence: dict,
) -> None:
    """Merge a new piece of evidence into a TechRecord, applying the
    version-precedence rule."""
    rec.sources.append(source)
    rec.evidence.append(evidence)
    if not version:
        return
    # First version seen wins, unless current source is higher rank or
    # same rank with more specificity.
    cur_rank = _SOURCE_RANK.get(rec.evidence[0].get("source", ""), 0) if rec.version else -1
    new_rank = _SOURCE_RANK.get(source, 0)
    if rec.version is None:
        rec.version = version
        return
    if new_rank > cur_rank:
        rec.version = version
    elif new_rank == cur_rank and _is_more_specific(version, rec.version):
        rec.version = version


_WP_PLUGIN_URL_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9][a-z0-9_\-]*)/readme\.txt$",
    re.IGNORECASE,
)

# Lazy-loaded alias cache so _canonical_name_from_url can resolve slug ->
# canonical display name (e.g. wordpress-seo -> Yoast SEO) without taking
# StageContext as a parameter. Loaded on first hit; small enough that the
# whole table fits cheaply.
_ALIAS_CACHE: dict[str, str] | None = None


def _alias_cache() -> dict[str, str]:
    global _ALIAS_CACHE
    if _ALIAS_CACHE is not None:
        return _ALIAS_CACHE
    import sqlite3 as _sql
    from pathlib import Path as _P
    db_path = _P(__file__).resolve().parent.parent / "lab.db"
    out: dict[str, str] = {}
    try:
        conn = _sql.connect(str(db_path))
        try:
            for alias, tech in conn.execute(
                "SELECT alias, tech FROM lab_pkg_aliases "
                "WHERE alias IS NOT NULL AND tech IS NOT NULL"
            ):
                out[alias.lower()] = tech
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass
    _ALIAS_CACHE = out
    return out


def _canonical_name_from_url(name: str, url: str | None) -> str:
    """If the evidence URL is a WordPress plugin readme, replace the
    nuclei templates' long marketing-copy titles with the canonical
    plugin name. Resolution order:

      1. URL -> slug via _WP_PLUGIN_URL_RE
      2. slug -> canonical via lab_pkg_aliases (Yoast SEO, etc.)
      3. fallback: bare slug (when no alias row exists)

    Generic by URL shape, not by tech list. The alias step is what makes
    Wappalyzer's 'Yoast SEO' detection reconcile with SlugReadmeStage's
    readme-derived detection under one TechRecord."""
    if not url:
        return name
    m = _WP_PLUGIN_URL_RE.search(url)
    if not m:
        return name
    slug = m.group(1).lower()
    canonical = _alias_cache().get(slug)
    return canonical if canonical else slug


def _from_scanner(detection: dict) -> tuple[str, str | None, list[str], dict]:
    """Pull (name, version, categories, evidence) from a scanner Detection dict."""
    # For multi-tech OR templates (e.g. tech-detect.yaml with 570 matchers),
    # product is None and name is the generic template title. matcher_name
    # is the actual technology that fired — prefer it over the template name.
    name = (
        detection.get("product")
        or detection.get("matcher_name")
        or detection.get("name")
        or detection.get("template_id", "")
    )
    # Promote the URL-shape slug over the nuclei template title when the
    # evidence URL is a WP plugin readme path. Lets the slug-readme stage's
    # versioned output merge with the nuclei detection record under one key.
    name = _canonical_name_from_url(name, detection.get("evidence_url") or detection.get("url"))
    version = detection.get("version")
    if not version:
        # Wappalyzer puts version under extracted["version"][0] sometimes.
        ex = detection.get("extracted") or {}
        for key in ("version", "Version"):
            v = ex.get(key)
            if v:
                version = v[0]
                break
    cats = []
    if detection.get("category"):
        cats.append(detection["category"])
    if "tags" in detection and detection["tags"]:
        cats.extend(detection["tags"])
    # Prefer evidence_url (the asset URL whose content triggered the matcher,
    # e.g. .../font-awesome.min.css) over url (the page URL the scanner probed,
    # often just "/"). Page URL is preserved as page_url for traceability.
    # Scanner emits evidence_url verbatim from HTML, so it may be relative
    # ("catalog/x.css"), root-relative ("/x.css"), or protocol-relative
    # ("//fonts.googleapis.com/css?..."). Resolve against the page URL here
    # -- the same way fetching stages do via _resolve_against -- so consumers
    # (scan_results.jsonl, [detect] log, dashboard) get absolute URLs.
    page_url = detection.get("url")
    ev_url = detection.get("evidence_url")
    if ev_url and page_url:
        ev_url = urljoin(page_url, ev_url)
    asset_url = ev_url or page_url
    evidence = {
        "source": detection.get("source", "nuclei"),
        "template_id": detection.get("template_id"),
        "matcher": detection.get("matcher_name"),
        "url": asset_url,
        "page_url": page_url,
        "path": detection.get("path"),
        "version": version,
    }
    return name, version, cats, evidence


def reconcile(
    detections: list[dict],
    probe_hits: list[vp_mod.ProbeHit],
) -> list[TechRecord]:
    """Merge scanner Detection dicts and version-probe ProbeHits into a
    deduplicated list of TechRecord per canonicalised name.

    Detections with ``source="jsextract"`` are NOT techs -- they are URL
    paths discovered in JS bundles, named after the path itself
    (``/api/users``). They belong in the pipeline's ``endpoints`` list,
    not the tech list. Filtering them out here keeps the merged output
    type-clean: techs are products, endpoints are URLs, never mixed.
    """
    out: dict[str, TechRecord] = {}

    for d in detections:
        if d.get("source") == "jsextract":
            continue  # routed to endpoints by run_pipeline, not a tech
        name, version, cats, ev = _from_scanner(d)
        if not name:
            continue
        key = _norm_name(name)
        rec = out.setdefault(key, TechRecord(name=name.replace("wap:", "").replace("retire:", "")))
        rec.categories.extend(cats)
        _add_evidence(rec, d.get("source", "nuclei"), version, ev)

    for hit in probe_hits:
        key = _norm_name(hit.probe.name)
        rec = out.setdefault(key, TechRecord(name=hit.probe.name))
        ev = {
            "source": "version-probe",
            "template_id": f"vp:{hit.probe.name}",
            "url": hit.url,
            "path": hit.probe.path,
            "status": hit.status,
            "version": hit.version,
        }
        _add_evidence(rec, "version-probe", hit.version, ev)

    for rec in out.values():
        if rec.version:
            rec.version_confidence = "exact"

    # Stable ordering: techs with versions first, then alphabetical.
    return sorted(
        out.values(),
        key=lambda r: (r.version is None, r.name.lower()),
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass
class PipelineConfig:
    """Toggles for the pipeline. Defaults are tuned for unauthenticated mass
    scanning -- enable the optional sources only when the corresponding
    inputs (cache file, retire.js DB, katana binary) are available."""
    nuclei_cache: str | None = None       # path to cache.json
    fingerprints_db: str | None = None    # alt: build cache from DB
    wap_db: str | None = None
    retire_db: str | None = None
    ww_db: str | None = None
    lab_db: str | None = None
    backend_probe: bool = True
    jsextract: bool = True
    run_katana: bool = True
    katana_extract_html: bool = True
    # Default ON so the pipeline re-fetches every unique deduped JS body
    # and runs the call/api/template regex tiers + retire.js-style sweep
    # over each. This is the gap that left leetcode at 5 versioned techs
    # despite 50 JS URLs in the dedup set -- without body fetch, JS-bundle
    # version pins (and config-blob leaks inside JS) are invisible.
    katana_extract_bodies: bool = True
    katana_max_urls: int = 500
    katana_depth: int = 2
    # Cross-page rescan: take katana's discovered page URLs (capped) and
    # re-run Wappalyzer + retire.js on each. Picks up tech that only
    # surfaces on non-root routes (admin pages, API 404s, login forms)
    # without paying the nuclei path-probe fanout cost.
    run_cross_page_rescan: bool = True
    cross_page_max_urls: int = 30
    run_version_probes: bool = True
    concurrency: int = 20
    timeout: int = 10
    # Hard wall-clock cap on the nuclei scan stage. With 647 paths and
    # concurrency=20 the expected time is ~30s; 90s gives 3x headroom
    # while preventing a slow target from blocking katana result collection.
    scan_timeout: int = 90
    # Hard wall-clock cap on the katana crawl stage. Katana can hang
    # indefinitely on slow/unresponsive targets; 60s is generous for a
    # depth-2 crawl on a reachable host.
    katana_timeout: int = 60
    # Hard cap on the version-probe catalog run. 15 probes run concurrently
    # with 8s each; 30s is generous headroom.
    vp_timeout: int = 30
    # Hard cap on the cross-page rescan. 30 URLs * 10s timeout each = 300s
    # worst-case sequential; 120s assumes reasonable concurrency.
    cross_page_timeout: int = 120
    verify_ssl: bool = False
    # UA preset name ("scanner" / "chrome") or a verbatim UA string.
    # Default is "chrome" because pipeline targets are mass-scan bot-
    # fronted sites where the honest scanner UA underperforms.
    user_agent: str = "chrome"
    # Progress reporting on stderr. Default ON: a real-time per-stage
    # log + heartbeat is the difference between "is it stuck?" and
    # "I can see katana is still on body sweep, 25s elapsed". Set
    # quiet=True to suppress for machine-driven runs that pipe --json.
    quiet: bool = False
    # AI training data collection. When set, every HTTP response that
    # contributed to a tech detection is archived as JSONL to this directory.
    # Two files per target: <slug>.responses.jsonl + <slug>.labels.jsonl,
    # joined by body SHA1. Bodies are base64-encoded; responses deduplicated
    # globally by SHA1 across the entire run.
    save_responses: str | None = None
    # Swap the scanner's curl_cffi main loop for CloakBrowser (stealth
    # Chromium). Defeats JS-challenge interstitials (Cloudflare, Akamai)
    # curl_cffi can't crack but pays ~1-3s per fetch. Default OFF -- opt in
    # per target when curl_cffi gets soft-blocked, or let Stage 5 escalate
    # automatically on cdn_check block / empty detections. Requires
    # `pip install cloakbrowser` (the stealth binary auto-downloads on
    # first run).
    use_cloak: bool = False


def _compose_endpoints(
    detections: list[dict],
    katana_result: katana_mod.KatanaResult | None,
) -> tuple[list[dict], list[dict], list[str]]:
    """Build the (endpoints, config_leaks, backend_hosts) triple from
    scanner detections and the optional katana crawl result.

    Endpoint sources, in dedup priority (first-seen wins):

      1. ``scanner-jsextract`` -- paths extracted by the scanner's --jsextract
         pass (already in detections with ``source="jsextract"``).
      2. ``katana-extracted`` -- paths regex-extracted from JS/HTML bodies
         re-fetched by ``katana.crawl``.
      3. ``katana-page``      -- raw page URLs katana crawled (deduped).
      4. ``katana-js``        -- raw JS bundle URLs katana surfaced.

    Buckets 3+4 are the user-visible record of what katana actually
    crawled; without them the pipeline reports counts in ``stats`` but
    throws the URLs away. They are what feeds downstream re-probes /
    fuzzers / retire.js re-runs.
    """
    endpoints: list[dict] = []
    config_leaks: list[dict] = []
    backend_hosts: list[str] = []

    for d in detections:
        if d.get("source") != "jsextract":
            continue
        endpoints.append({
            "path": d.get("path", ""),
            "confidence": d.get("matcher_name", ""),
            "source_url": d.get("url", ""),
            "discovered_by": "scanner-jsextract",
        })

    if katana_result is not None:
        for ep in katana_result.paths:
            d = ep.to_dict()
            d["discovered_by"] = "katana-extracted"
            endpoints.append(d)
        for url in katana_result.page_urls:
            endpoints.append({
                "path": url,
                "confidence": "crawl",
                "source_url": katana_result.seed,
                "discovered_by": "katana-page",
            })
        for url in katana_result.js_urls:
            endpoints.append({
                "path": url,
                "confidence": "crawl",
                "source_url": katana_result.seed,
                "discovered_by": "katana-js",
            })
        config_leaks = [cl.to_dict() for cl in katana_result.config_leaks]
        seen_hosts: set[str] = set()
        for cl in katana_result.config_leaks:
            if cl.leak_class != "backend_url":
                continue
            host = urlsplit(cl.value).hostname
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                backend_hosts.append(host)

    seen_paths: set[str] = set()
    deduped: list[dict] = []
    for e in endpoints:
        p = e.get("path", "")
        if p in seen_paths:
            continue
        seen_paths.add(p)
        deduped.append(e)
    return deduped, config_leaks, backend_hosts


async def _populate_root_html(ctx: "Any") -> None:
    """Fetch the target's root HTML once and stash it in ``ctx.html_bodies``.

    Stage 3 (Inline extract) consumes ``ctx.html_bodies`` directly so it
    stays pure (no fetch). The cost is one extra GET per target -- cheap
    compared to scanner/katana and worth the §7a "stage = pure transform
    over content" framing.
    """
    from curl_cffi.requests import AsyncSession as _CurlSession
    from fetchlib import build_request_headers
    try:
        async with _CurlSession(
            impersonate="chrome120",
            headers=build_request_headers(ua=ctx.ua),
            timeout=ctx.timeout,
            verify=ctx.verify_ssl,
        ) as session:
            r = await session.get(ctx.target, allow_redirects=True)
            if r.status_code == 200 and r.text:
                ctx.html_bodies[ctx.target] = r.text[: 1 * 1024 * 1024]
    except Exception:  # noqa: BLE001
        pass  # Stage 3 becomes a no-op for this target -- acceptable degradation.


def _should_escalate(
    cdn_block: dict | None, detections: list[dict], cfg: "PipelineConfig",
) -> bool:
    """Stage 5 gate: only escalate when the curl_cffi tier looks blocked.

    Conditions (any one fires):
      - cdn_check explicitly reported a block (provider returned a
        challenge / 403);
      - the entire funnel produced zero detections AND the user did not
        already pre-select the browser fetcher (no point escalating to a
        tier we're already on).
    """
    if cfg.use_cloak:
        return False
    if cdn_block:
        return True
    return not any(
        isinstance(d, dict) and (d.get("name") or d.get("product"))
        for d in detections
    )


async def _stage5_escalate(
    target: str,
    cache: dict,
    wap_cache: dict | None,
    retire_cache: dict | None,
    ww_cache: list,
    funnel: list,
    prev_ctx: "Any",
    cfg: "PipelineConfig",
    ua: str,
) -> list[dict]:
    """Re-run Stage 0 (scanner) with the CloakBrowser fetcher and re-apply
    the funnel. Returns only NEW detections (deduped against ``prev_ctx``).

    The escalation is one-shot per target -- we do not chain a third
    fetcher tier even if the browser run also looks blocked.
    """
    try:
        scan_results = await scanner_mod.scan_targets(
            cache, [target],
            wap_cache=wap_cache,
            retire_cache=retire_cache,
            ww_cache=ww_cache,
            backend_probe=False,  # already done in tier 1
            jsextract=False,
            concurrency=cfg.concurrency,
            timeout=cfg.timeout,
            verify_ssl=cfg.verify_ssl,
            user_agent=ua,
            probe_timeout=float(cfg.scan_timeout),
            use_cloak=True,
            # Page mode: real Page.goto, HTTP/2 to target, JS executed.
            # ~3-5s/fetch but the only way the cloak tier actually defeats
            # Cloudflare/Akamai JS-challenge interstitials. APIRequestContext
            # mode here would just rerun the same blocked HTTP/1.1 fingerprint
            # and waste the escalation budget.
            cloak_mode="page",
        )
    except Exception:  # noqa: BLE001
        return []
    browser_dets = scan_results.get(target, [])
    if not browser_dets:
        return []

    from . import stages as stages_mod
    new_pool = list(prev_ctx.url_pool)
    for d in browser_dets:
        eu = d.get("evidence_url") if isinstance(d, dict) else None
        if eu and eu not in new_pool:
            new_pool.append(eu)
    esc_ctx = stages_mod.StageContext(
        target=target,
        lab_db=cfg.lab_db,
        ua=ua,
        timeout=cfg.timeout,
        verify_ssl=cfg.verify_ssl,
        detections=list(browser_dets),
        url_pool=new_pool,
    )
    await _populate_root_html(esc_ctx)
    for stage in funnel:
        try:
            new_dets = await stage.apply(esc_ctx)
        except Exception:  # noqa: BLE001
            continue
        if new_dets:
            esc_ctx.detections.extend(new_dets)

    seen_keys: set[tuple[str, str]] = set()
    for d in prev_ctx.detections:
        if isinstance(d, dict):
            seen_keys.add((
                (d.get("name") or d.get("product") or "").lower(),
                d.get("version") or "",
            ))
    out: list[dict] = []
    for d in esc_ctx.detections:
        if not isinstance(d, dict):
            continue
        key = (
            (d.get("name") or d.get("product") or "").lower(),
            d.get("version") or "",
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        d = dict(d)
        d["source"] = (d.get("source") or "browser") + "+browser"
        out.append(d)
    return out


async def run_pipeline(
    target: str,
    cfg: PipelineConfig | None = None,
    _sink: "sink_mod.ResponseSink | None" = None,
) -> dict[str, Any]:
    """Run the full fingerprint pipeline against one target URL.

    Returns the per-target output dict described in the module docstring.
    Each source contributes its own slice; failures in optional sources
    (katana binary missing, retire DB absent, etc.) degrade gracefully:
    the source is skipped, recorded under stats.skipped, and the rest of
    the pipeline still runs.
    """
    cfg = cfg or PipelineConfig()
    ua = resolve_ua(cfg.user_agent)
    stats: dict[str, Any] = {"skipped": [], "errors": [], "user_agent": ua}
    prog = progress_mod.ProgressLogger(enabled=not cfg.quiet)
    prog.header(target)

    # When the cloak tier is on, install the loop exception silencer once
    # per run. Aborted-navigation Futures get GC'd in unpredictable windows
    # (often between targets); the silencer must outlive any per-fetcher
    # __aexit__ to keep them out of the log. Idempotent.
    if cfg.use_cloak:
        from . import cloak_fetcher as _cloak_mod
        _cloak_mod.install_silencer_on_running_loop()

    # 1. Build the scanner cache (preferring cache.json over DB rebuild).
    if cfg.nuclei_cache:
        cache = cache_mod.load_cache(cfg.nuclei_cache)
    elif cfg.fingerprints_db:
        cache = cache_mod.build_cache(cfg.fingerprints_db)
    else:
        stats["errors"].append("no nuclei_cache or fingerprints_db provided")
        return {
            "target": target,
            "techs": [],
            "leaks": {"config_blob": [], "backend_hosts": []},
            "endpoints": [],
            "stats": stats,
            "unfinished": ["session-capture", "browser-capture"],
        }

    wap_cache = wap_mod.build_cache(cfg.wap_db) if cfg.wap_db else None
    retire_cache = retire_mod.build_cache(cfg.retire_db) if cfg.retire_db else None
    ww_cache = ww_mod.build_cache(cfg.ww_db) if cfg.ww_db else []
    from . import lab_rules as lab_mod
    lab_cache = lab_mod.build_cache(cfg.lab_db) if cfg.lab_db else None
    if cfg.wap_db is None:
        stats["skipped"].append("wappalyzer (no --wap-db)")
    if cfg.retire_db is None:
        stats["skipped"].append("retirejs (no --retire-db)")
    if cfg.ww_db is None:
        stats["skipped"].append("whatweb (no --ww-db)")
    if cfg.lab_db is None:
        stats["skipped"].append("lab-rules (no --lab-db)")

    # Use caller-provided sink (bulk run) or create one locally (single run).
    _owns_sink = _sink is None and cfg.save_responses is not None
    rsink = _sink or (sink_mod.ResponseSink(cfg.save_responses) if cfg.save_responses else None)

    # 2. Run scan, katana, version-probes concurrently. Each is an
    # independent network workload; running serially would triple wall time.
    cdn_task: asyncio.Task = asyncio.create_task(
        cdn_mod.check(target, user_agent=ua)
    )

    scan_task: asyncio.Task = asyncio.create_task(
        scanner_mod.scan_targets(
            cache, [target],
            wap_cache=wap_cache,
            retire_cache=retire_cache,
            ww_cache=ww_cache,
            backend_probe=cfg.backend_probe,
            jsextract=cfg.jsextract,
            concurrency=cfg.concurrency,
            timeout=cfg.timeout,
            verify_ssl=cfg.verify_ssl,
            user_agent=ua,
            response_sink=rsink,
            probe_timeout=float(cfg.scan_timeout),
            use_cloak=cfg.use_cloak,
        )
    )
    prog.start("scan", "concurrent")

    katana_task: asyncio.Task | None = None
    if cfg.run_katana and katana_mod.find_katana_binary():
        katana_task = asyncio.create_task(
            katana_mod.crawl(
                target,
                depth=cfg.katana_depth,
                max_katana_urls=cfg.katana_max_urls,
                extract_bodies=cfg.katana_extract_bodies,
                extract_html=cfg.katana_extract_html,
                katana_timeout=cfg.katana_timeout,
                user_agent=ua,
            )
        )
        prog.start("katana", "concurrent")
    elif cfg.run_katana:
        stats["skipped"].append("katana (binary not on PATH)")
        prog.skip("katana", "binary not on PATH")

    vp_task: asyncio.Task | None = None
    if cfg.run_version_probes:
        vp_task = asyncio.create_task(
            vp_mod.run_catalog(
                target, timeout=vp_mod.DEFAULT_TIMEOUT, user_agent=ua,
            )
        )
        prog.start("version-probes", "concurrent")

    # Heartbeat shows which stages are still running every ~10s so the
    # user can tell a slow stage from a hung run.
    named_tasks: dict[str, asyncio.Task] = {"scan": scan_task}
    if katana_task is not None:
        named_tasks["katana"] = katana_task
    if vp_task is not None:
        named_tasks["version-probes"] = vp_task
    heartbeat_task = asyncio.create_task(
        progress_mod.heartbeat(prog, named_tasks)
    )

    # scan_targets now owns the probe timeout internally via probe_timeout=,
    # using asyncio.wait so it returns partial results from whatever probes
    # completed before the deadline rather than discarding everything.
    try:
        scan_results = await scan_task
    except Exception as exc:  # noqa: BLE001
        prog.error("scan", exc)
        scan_results = {}
        stats["errors"].append(f"scan: {exc}")
    detections: list[dict] = scan_results.get(target, [])
    prog.done("scan", f"{len(detections)} detections")

    cdn_block = await cdn_task
    if cdn_block:
        stats["cdn_blocked"] = cdn_block.to_dict()
        prog.done(
            "cdn-check",
            f"BLOCKED by {cdn_block.provider} "
            f"(HTTP {cdn_block.status}: {cdn_block.reason}) -- "
            "results may be incomplete",
        )
    else:
        stats["cdn_blocked"] = None

    katana_result = None
    if katana_task is not None:
        try:
            katana_result = await asyncio.wait_for(katana_task, timeout=cfg.katana_timeout)
        except asyncio.TimeoutError:
            katana_task.cancel()
            try:
                await katana_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            prog.done("katana", f"timed out after {cfg.katana_timeout}s -- partial results")
            stats["errors"].append(f"katana: timed out after {cfg.katana_timeout}s")
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"katana: {exc}")
            prog.error("katana", exc)
        else:
            kstats = katana_result.stats if katana_result else {}
            budget = " [BUDGET HIT]" if kstats.get("katana_budget_hit") else ""
            prog.done(
                "katana",
                f"{kstats.get('katana_records', 0)} records, "
                f"pages={kstats.get('page_urls_deduped', 0)} "
                f"js={kstats.get('js_urls_deduped', 0)}{budget}",
            )

    probe_hits: list[vp_mod.ProbeHit] = []
    if vp_task is not None:
        try:
            probe_hits = await asyncio.wait_for(vp_task, timeout=cfg.vp_timeout)
        except asyncio.TimeoutError:
            vp_task.cancel()
            try:
                await vp_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            prog.done("version-probes", f"timed out after {cfg.vp_timeout}s")
            stats["errors"].append(f"version-probes: timed out after {cfg.vp_timeout}s")
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"version-probes: {exc}")
            prog.error("version-probes", exc)
        else:
            prog.done("version-probes", f"{len(probe_hits)} hits")

    heartbeat_task.cancel()
    try:
        await heartbeat_task
    except asyncio.CancelledError:
        pass

    # 2b. Cross-page rescan. This depends on katana's page_urls so it
    # cannot run in parallel with katana_task -- but it is fast (one GET
    # per capped URL plus aggregated retire.js script fetch) so the
    # serial cost is small. Skip cleanly when there are no katana pages
    # to rescan, or when both wap_cache and retire_cache are absent.
    cross_page_detections: list[dict] = []
    if (
        cfg.run_cross_page_rescan
        and katana_result is not None
        and katana_result.page_urls
        and (wap_cache is not None or retire_cache is not None)
    ):
        n_avail = len(katana_result.page_urls)
        budget = min(n_avail, cfg.cross_page_max_urls)
        prog.start("cross-page rescan", f"{budget}/{n_avail} URLs from katana")
        cp_task = asyncio.create_task(
            cross_page_mod.rescan(
                katana_result.page_urls,
                wap_cache=wap_cache,
                retire_cache=retire_cache,
                user_agent=ua,
                max_urls=cfg.cross_page_max_urls,
                timeout=cfg.timeout,
            )
        )
        cp_heartbeat = asyncio.create_task(
            progress_mod.heartbeat(prog, {"cross-page rescan": cp_task})
        )
        try:
            cross_page_detections, cp_stats = await asyncio.wait_for(
                cp_task, timeout=cfg.cross_page_timeout,
            )
            stats["cross_page"] = cp_stats
            prog.done(
                "cross-page rescan",
                f"fetched={cp_stats.get('urls_fetched', 0)}/"
                f"{cp_stats.get('urls_after_dedup', 0)} "
                f"wap={cp_stats.get('wap_detections', 0)} "
                f"retire={cp_stats.get('retire_detections', 0)}",
            )
        except asyncio.TimeoutError:
            prog.done("cross-page rescan", f"timed out after {cfg.cross_page_timeout}s -- partial results")
            stats["errors"].append(f"cross-page-rescan: timed out after {cfg.cross_page_timeout}s")
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"cross-page-rescan: {exc}")
            prog.error("cross-page rescan", exc)
        finally:
            cp_heartbeat.cancel()
            try:
                await cp_heartbeat
            except asyncio.CancelledError:
                pass
    elif cfg.run_cross_page_rescan and katana_result is None:
        # Already noted katana skip; don't double-log.
        pass
    elif cfg.run_cross_page_rescan:
        stats["skipped"].append("cross-page-rescan (no katana pages or no wap/retire cache)")
        prog.skip("cross-page rescan", "no katana pages or no wap/retire cache")

    # §7a funnel: Stages 1-4 run uniformly off a single StageContext.
    # Stage 0 (Discovery) is the scanner + katana + cross-page block above;
    # its outputs feed `ctx` here. Stage 5 (Browser escalation) wraps the
    # funnel below and may re-run when blocking is detected.
    from . import stages as stages_mod

    url_pool: list[str] = []
    if katana_result is not None:
        url_pool.extend(katana_result.page_urls)
        url_pool.extend(katana_result.js_urls)
    for _d in detections + cross_page_detections:
        eu = _d.get("evidence_url") if isinstance(_d, dict) else None
        if eu and eu not in url_pool:
            url_pool.append(eu)

    ctx = stages_mod.StageContext(
        target=target,
        lab_db=cfg.lab_db,
        ua=ua,
        timeout=cfg.timeout,
        verify_ssl=cfg.verify_ssl,
        detections=list(detections + cross_page_detections),
        url_pool=url_pool,
    )
    # Pre-populate html_bodies for Stage 3 by re-fetching the root once.
    # Cheap (1 request), keeps Stage 3 pure -- it never touches the network.
    await _populate_root_html(ctx)

    funnel: list[stages_mod.Stage] = [
        stages_mod.UrlExtractStage(),
        stages_mod.BodyExtractStage(),
        stages_mod.InlineExtractStage(),
        stages_mod.BundleScanStage(),
        stages_mod.SlugReadmeStage(),
    ]
    funnel_dets: list[dict] = []
    for stage in funnel:
        try:
            new_dets = await stage.apply(ctx)
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"{stage.name}: {exc}")
            prog.error(stage.name, exc)
            continue
        if new_dets:
            funnel_dets.extend(new_dets)
            ctx.detections.extend(new_dets)
            prog.done(stage.name, f"{len(new_dets)} detections")
        stats.setdefault(f"{stage.name}_hits", len(new_dets))

    # Stage 5: browser-tier escalation. Re-run Stage 0 + the funnel through
    # CloakBrowser when curl_cffi got softblocked. Gated to avoid the
    # ~3x-slower fetch on every target.
    if _should_escalate(stats.get("cdn_blocked"), ctx.detections, cfg):
        prog.start("browser-escalate", "cdn block or empty detections")
        esc_dets = await _stage5_escalate(
            target, cache, wap_cache, retire_cache, ww_cache,
            funnel, ctx, cfg, ua,
        )
        if esc_dets:
            funnel_dets.extend(esc_dets)
            ctx.detections.extend(esc_dets)
        stats["browser_escalate_hits"] = len(esc_dets)
        prog.done("browser-escalate", f"{len(esc_dets)} additional detections")

    # Lab-mined body + bundled rules. Probes plugin readmes + main PHP
    # files + bundled-tech paths whenever the scanner detected a tech that
    # matches a lab slug. ``apply()`` is no-op if lab_cache is None or no
    # detections match any lab slug.
    lab_detections: list[dict] = []
    if lab_cache is not None and detections:
        from curl_cffi.requests import AsyncSession as _CurlSession
        prog.start("lab-rules", "probing matched lab slugs")
        try:
            from . import lab_rules as lab_mod
            from fetchlib import build_request_headers
            async with _CurlSession(
                impersonate="chrome120",
                headers=build_request_headers(ua=ua),
                timeout=cfg.timeout,
                verify=cfg.verify_ssl,
            ) as lab_session:
                hits = await lab_mod.apply(
                    target, detections, lab_session, lab_cache,
                    timeout=cfg.timeout,
                )
            lab_detections = [h.to_detection_dict() for h in hits]
            stats["lab_rule_hits"] = len(lab_detections)
            prog.done("lab-rules", f"{len(lab_detections)} hits")
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"lab-rules: {exc}")
            prog.error("lab-rules", exc)

    # Merge Stage 0 (scanner + cross-page) with the §7a funnel output and
    # the lab_rules apply() pass. ctx.detections already contains the
    # Stage 0 inputs plus stages 1-4 + any Stage 5 escalation hits; lab
    # rules are kept separate because lab_rules.apply() has its own
    # rules+fetcher model and runs concurrently with the funnel.
    detections_for_reconcile = ctx.detections + lab_detections

    # 3. Reconcile.
    techs = reconcile(detections_for_reconcile, probe_hits)
    prog.done(
        "reconcile",
        f"{len(techs)} techs, {sum(1 for t in techs if t.version)} versioned",
    )
    # Per-detection events for live dashboard rendering. One line per tech;
    # dashboards parse them with a single regex on the stderr tail.
    for _t in techs:
        _first_evidence_url = (_t.evidence[0].get("url") if _t.evidence else None) or None
        prog.detect(target, _t.name, _t.version, _first_evidence_url)

    # 4. Compose output. Surface katana endpoint paths + config-blob leaks
    # alongside the tech list so the consumer has the raw evidence.
    endpoints, config_leaks, backend_hosts = _compose_endpoints(
        detections, katana_result,
    )
    if katana_result is not None:
        stats["katana"] = katana_result.stats

    stats["scan_detections"] = len(detections)
    stats["cross_page_detections"] = len(cross_page_detections)
    stats["version_probe_hits"] = len(probe_hits)
    stats["techs_total"] = len(techs)
    stats["techs_with_version"] = sum(1 for t in techs if t.version)

    if _owns_sink and rsink is not None:
        rsink.close()

    return {
        "target": target,
        "techs": [t.to_dict() for t in techs],
        "leaks": {
            "config_blob": config_leaks,
            "backend_hosts": backend_hosts,
        },
        "endpoints": endpoints,
        "stats": stats,
        "unfinished": ["session-capture", "browser-capture"],
    }


async def run_pipeline_stream(
    targets: list[str],
    cfg: PipelineConfig | None = None,
    parallel: int = 3,
):
    """Like run_pipeline_many but yields each result as it completes.

    Allows the caller to write/append results incrementally so a partial
    run is not lost on interrupt.
    """
    cfg = cfg or PipelineConfig()
    sem = asyncio.Semaphore(parallel)
    shared_sink = sink_mod.ResponseSink(cfg.save_responses) if cfg.save_responses else None

    async def _bounded(t: str) -> dict[str, Any]:
        async with sem:
            return await run_pipeline(t, cfg, _sink=shared_sink)

    tasks = [asyncio.create_task(_bounded(t)) for t in targets]
    try:
        for fut in asyncio.as_completed(tasks):
            yield await fut
    finally:
        for t in tasks:
            t.cancel()
        if shared_sink is not None:
            shared_sink.close()


async def run_pipeline_many(
    targets: list[str],
    cfg: PipelineConfig | None = None,
    parallel: int = 3,
) -> list[dict[str, Any]]:
    """Run the pipeline across a list of targets with bounded concurrency.

    A single ResponseSink is shared across all targets so the global body
    SHA1 dedup set spans the entire bulk run — CDN-identical assets served
    by multiple sites only appear once in the output.
    """
    results = []
    async for result in run_pipeline_stream(targets, cfg, parallel):
        results.append(result)
    return results
