"""Uniform §7a detection funnel: stage protocol + shared helpers.

The funnel is six stages, each rule-driven from ``lab.db`` and free of
tech-specific code. Concrete stage implementations live in this module
and consume / extend a single ``StageContext`` instance.

    Stage 0  Discovery       collect URLs + bodies (root, katana, evidence)
    Stage 1  URL extract     lab_url_patterns over the URL pool
    Stage 2  Body extract    banner regexes over fetched .css / .js bodies
    Stage 3  Inline extract  banner regexes over inline <style> / <script>
    Stage 4  Bundle scan     class / glyph signatures over JS bundle bodies
    Stage 5  Browser tier    re-run discovery via CloakBrowser when blocked

Each stage emits Detection-shaped dicts (the same shape ``reconcile()``
consumes). Adding a new technology is a rule INSERT into ``lab.db`` -- it
never requires editing this file.
"""

from __future__ import annotations

import json
import re
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Stage context
# ---------------------------------------------------------------------------


@dataclass
class StageContext:
    """Shared funnel state. Stages read accumulated content and contribute
    new detections; the orchestrator merges the returns back into ``ctx``
    before invoking the next stage.

    Attributes are write-once-by-Stage-0 (target, fetcher params, lab_db)
    plus accumulators (detections, url_pool, html_bodies, js_bodies). The
    accumulators are populated by Stage 0 and may be appended to by later
    stages that discover new URLs / bodies along the way (e.g. Stage 2
    fetches CSS / JS bodies it then files in ``js_bodies`` so Stage 4 can
    re-use them without re-fetching).
    """

    target: str
    lab_db: str | None
    ua: str
    timeout: int = 10
    verify_ssl: bool = False
    detections: list[dict] = field(default_factory=list)
    url_pool: list[str] = field(default_factory=list)
    # url -> body text. Two-bucket split mirrors how downstream stages
    # treat them: html for inline extract, js/css for body extract +
    # bundle scan.
    html_bodies: dict[str, str] = field(default_factory=dict)
    js_bodies: dict[str, str] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Stage ABC
# ---------------------------------------------------------------------------


class Stage(ABC):
    """One stage of the §7a detection funnel.

    Concrete stages override ``name`` and ``apply``. ``apply`` returns the
    list of Detection-shaped dicts this stage emits. The orchestrator owns
    merging them into ``ctx.detections`` and propagating any newly
    discovered URLs / bodies into ``ctx.url_pool`` / ``ctx.{html,js}_bodies``.
    """

    name: str = ""

    @abstractmethod
    async def apply(self, ctx: StageContext) -> list[dict]:
        ...


# ---------------------------------------------------------------------------
# lab.db helpers -- single rule loader used by every stage
# ---------------------------------------------------------------------------


def load_rules(
    lab_db: str, section: str, *, tech_slug: str | None = None,
) -> list[dict]:
    """Load and compile rules from ``lab_src_rules`` for one section.

    Returns one dict per row::

        {
          "tech_slug": "font-awesome",
          "rule_id": "fa-banner-v4",
          "pattern": <re.Pattern>,
          "version_group": 1 | None,
          "extracts": {...},
          "raw_pattern": "Font Awesome (\\d+\\.\\d+...",
        }

    Patterns that fail to compile are silently dropped (logged via the
    rule's id elsewhere if a caller cares). ``tech_slug`` filters when
    given; otherwise every row in the section is returned.
    """
    sql = (
        "SELECT tech_slug, rule_id, pattern, extracts_json "
        "FROM lab_src_rules WHERE section = ?"
    )
    args: tuple[Any, ...] = (section,)
    if tech_slug:
        sql += " AND tech_slug = ?"
        args += (tech_slug,)
    conn = sqlite3.connect(lab_db)
    try:
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    out: list[dict] = []
    for slug, rule_id, pat, extracts_json in rows:
        try:
            compiled = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        extracts = json.loads(extracts_json) if extracts_json else {}
        vspec = extracts.get("version") if isinstance(extracts, dict) else None
        vgroup = vspec.get("g") if isinstance(vspec, dict) else None
        out.append({
            "tech_slug": slug,
            "rule_id": rule_id,
            "pattern": compiled,
            "raw_pattern": pat,
            "version_group": int(vgroup) if vgroup else None,
            "extracts": extracts if isinstance(extracts, dict) else {},
        })
    return out


def lookup_canonical_name(lab_db: str, slug: str) -> str:
    """Slug -> canonical display name via ``lab_pkg_aliases``.

    The lab authors the slug -> canonical mapping; this is the read-side.
    Falls back to a title-cased version of the slug when no row exists --
    the only way a stage emits a non-canonical name is if the lab hasn't
    seeded the alias yet.
    """
    conn = sqlite3.connect(lab_db)
    try:
        row = conn.execute(
            "SELECT tech FROM lab_pkg_aliases WHERE alias = ? AND tech IS NOT NULL "
            "ORDER BY id LIMIT 1",
            (slug,),
        ).fetchone()
    finally:
        conn.close()
    if row and row[0]:
        return row[0]
    return slug.replace("-", " ").title()


# ---------------------------------------------------------------------------
# Detection helper
# ---------------------------------------------------------------------------


_DOTTED_VER_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")


def is_dotted_version(s: str | None) -> bool:
    """True iff ``s`` looks like a real dotted version (rejects hashes,
    single integers, alpha tokens). Shared by every stage that extracts
    a version from a regex group so the dotted-version contract is one
    line of code, not duplicated."""
    return bool(s) and bool(_DOTTED_VER_RE.match(s))


def make_detection(
    *,
    source: str,
    tech_name: str,
    version: str | None,
    url: str,
    rule_id: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Build a Detection-shaped dict in the schema ``reconcile()`` expects.

    Stages call this instead of constructing dicts inline so the schema
    has one definition point. ``extra`` merges in last for stage-specific
    fields (e.g. ``evidence_url``).
    """
    d = {
        "source": source,
        "template_id": f"{source}:{rule_id}" if rule_id else source,
        "name": tech_name,
        "product": tech_name,
        "url": url,
        "evidence_url": url,
        "version": version,
        "matcher_name": rule_id,
    }
    if extra:
        d.update(extra)
    return d


# ---------------------------------------------------------------------------
# Inline content extraction (Stage 3 helpers)
# ---------------------------------------------------------------------------

_INLINE_STYLE_RE = re.compile(
    r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL,
)
_INLINE_SCRIPT_RE = re.compile(
    # Inline <script> only (no src= attribute). Negative lookahead in the
    # tag body keeps URL-loaded scripts out -- those are Stage 4's job.
    r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)


def extract_inline_blocks(html: str) -> list[str]:
    """Pull text content out of inline <style> / <script> tags from an HTML
    body. Returns one string per block. Empty results are dropped.
    """
    out: list[str] = []
    for m in _INLINE_STYLE_RE.finditer(html):
        block = m.group(1)
        if block.strip():
            out.append(block)
    for m in _INLINE_SCRIPT_RE.finditer(html):
        block = m.group(1)
        if block.strip():
            out.append(block)
    return out


# ---------------------------------------------------------------------------
# Stage 1 -- URL extract
# ---------------------------------------------------------------------------


class UrlExtractStage(Stage):
    """Apply ``lab_url_patterns`` proximity + query rules over the URL pool.

    Delegates the actual regex work to ``fp.url_ver`` (which already loads
    those rules from lab.db). Wraps it as a Stage so the funnel has a
    single named entry point per channel, not two.
    """

    name = "url-extract"

    async def apply(self, ctx: StageContext) -> list[dict]:
        if not ctx.url_pool:
            return []
        # Local import: url_ver lazy-loads its lab.db catalog at module
        # init, which we don't want triggered when stages.py is imported
        # by tests that don't need it.
        from . import url_ver as _uv
        hits = _uv.extract_ver_params(ctx.url_pool)
        return [h.to_detection_dict() for h in hits]


# ---------------------------------------------------------------------------
# Stage 2 -- Body extract (banner regexes over fetched CSS / JS bodies)
# ---------------------------------------------------------------------------


_ASSET_URL_RE = re.compile(r"\.(css|js)(\?|$|#)", re.IGNORECASE)


def _versioned_techs(detections: list[dict]) -> set[str]:
    """Slug-ish set of tech names already known to have a version.
    Used to avoid wasting a fetch on a tech whose version we already have.
    """
    out: set[str] = set()
    for d in detections:
        if not isinstance(d, dict):
            continue
        if d.get("version"):
            name = (d.get("name") or d.get("product") or "").strip().lower()
            if name:
                out.add(name)
    return out


def _resolve_against(base: str, url: str) -> str:
    """RFC 3986 urljoin wrapper. Returns the input unchanged when it is
    already absolute. Used by every fetching stage so relative / root-
    relative href values from HTML (`catalog/view/...`, `/path/x.css`,
    `//cdn.example.com/x.js`) become fetchable URLs."""
    from urllib.parse import urljoin as _uj
    return _uj(base, url)


def _candidate_asset_urls(ctx: StageContext) -> list[str]:
    """Asset URLs worth fetching for banner rescue. Pulls from the URL pool
    and from evidence_url of unversioned detections, **resolving any
    relative URL against the originating page URL** (or ctx.target as a
    fallback) so the fetch step in BodyExtractStage can issue them as-is.
    Dedup preserves order.

    Scanner emits evidence_url verbatim from HTML (often relative); stages
    that fetch are responsible for resolution.
    """
    seen: set[str] = set()
    out: list[str] = []
    versioned = _versioned_techs(ctx.detections)

    def _maybe(url: str | None, base: str, tech_hint: str = "") -> None:
        if not url:
            return
        resolved = _resolve_against(base, url)
        if resolved in seen:
            return
        if not _ASSET_URL_RE.search(resolved):
            return
        if tech_hint and tech_hint.strip().lower() in versioned:
            return
        seen.add(resolved)
        out.append(resolved)

    for d in ctx.detections:
        if not isinstance(d, dict) or d.get("version"):
            continue
        # The detection's own `url` field is the page URL the matcher fired
        # on (always absolute from scanner). evidence_url is the asset href
        # the matcher pointed at (often relative). Resolve the latter
        # against the former.
        page_url = d.get("url") or ctx.target
        _maybe(
            d.get("evidence_url") or d.get("url"),
            page_url,
            d.get("product") or d.get("name") or "",
        )
    for url in ctx.url_pool:
        # url_pool entries have no per-URL base -- ctx.target is the only
        # sensible fallback. Absolute URLs pass through urljoin unchanged.
        _maybe(url, ctx.target)
    return out


class BodyExtractStage(Stage):
    """Fetch unversioned .css / .js asset URLs and run ``banner_rules``
    against the body. Caches fetched bodies in ``ctx.js_bodies`` so
    Stage 4 can re-use them without a second round trip.

    No tech-specific code: regex + canonical-name lookup both come from
    ``lab.db`` rows. Adding a new tech is two INSERTs (one banner rule
    in ``lab_src_rules``, one alias in ``lab_pkg_aliases``).
    """

    name = "body-extract"

    async def apply(self, ctx: StageContext) -> list[dict]:
        if not ctx.lab_db:
            return []
        rules = load_rules(ctx.lab_db, "banner_rules")
        if not rules:
            return []
        candidates = _candidate_asset_urls(ctx)
        if not candidates:
            return []

        from curl_cffi.requests import AsyncSession as _CurlSession
        from fetchlib import build_request_headers

        out: list[dict] = []
        async with _CurlSession(
            impersonate="chrome120",
            headers=build_request_headers(ua=ctx.ua),
            timeout=ctx.timeout,
            verify=ctx.verify_ssl,
        ) as session:
            for url in candidates:
                if url in ctx.js_bodies:
                    body = ctx.js_bodies[url]
                else:
                    try:
                        r = await session.get(url, allow_redirects=True)
                        if r.status_code != 200 or not r.text:
                            continue
                        body = r.text[: 1024 * 1024]
                    except Exception:  # noqa: BLE001
                        continue
                    ctx.js_bodies[url] = body
                for hit in _apply_banner_rules(rules, body[:8192], ctx.lab_db, url):
                    out.append(hit)
                    break  # one rule per URL is enough
        return out


def _apply_banner_rules(
    rules: list[dict], body: str, lab_db: str, source_url: str,
) -> list[dict]:
    """Apply already-compiled banner rules to a body chunk. Yields a single
    Detection dict per matched rule (rules with a version group whose match
    is dotted-numeric)."""
    out: list[dict] = []
    for rule in rules:
        vgroup = rule["version_group"]
        if vgroup is None:
            continue
        m = rule["pattern"].search(body)
        if not m:
            continue
        try:
            ver = m.group(vgroup)
        except IndexError:
            continue
        if not is_dotted_version(ver):
            continue
        out.append(make_detection(
            source="banner",
            tech_name=lookup_canonical_name(lab_db, rule["tech_slug"]),
            version=ver,
            url=source_url,
            rule_id=rule["rule_id"],
        ))
    return out


# ---------------------------------------------------------------------------
# Stage -- Slug+Readme (URL-shape carries slug, body carries version)
# ---------------------------------------------------------------------------


# 2-4 dotted parts. WordPress plugins routinely ship X.Y.Z.W versions
# (wpforms-lite=1.8.1.2). Stricter than is_dotted_version, more permissive
# than the SemVer 3-part rule used for JS libs.
_PLUGIN_VER_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")


def _load_slug_url_rules(lab_db: str) -> list[dict]:
    """Load rules from ``lab_src_rules`` section ``slug_url_rules``.

    Each rule encodes a URL-shape that discloses both a tech slug
    (captured group from the URL) and a path to a body containing the
    version. ``extracts_json`` carries the structural fields:

        {
          "slug":    {"g": 1, "from": "url"},
          "version": {"g": 1, "from": "body",
                      "body_pattern": "(?im)^Stable\\s+tag:\\s*(\\S+)"},
          "name_template": "{slug}"
        }

    The URL pattern goes in ``pattern`` and is matched against each
    detection's ``evidence_url``. The body_pattern is fetched-and-applied
    by ``SlugReadmeStage``. Generic by design -- WordPress plugins are
    the first user; Drupal modules / Composer vendor dirs / etc. can
    land as additional rows with no code change.
    """
    conn = sqlite3.connect(lab_db)
    try:
        rows = conn.execute(
            "SELECT tech_slug, rule_id, pattern, extracts_json "
            "FROM lab_src_rules WHERE section = 'slug_url_rules'"
        ).fetchall()
    finally:
        conn.close()
    out: list[dict] = []
    for slug_field, rule_id, pat, extracts_json in rows:
        try:
            url_re = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        extracts = json.loads(extracts_json) if extracts_json else {}
        body_spec = (extracts.get("version") or {})
        body_pat_str = body_spec.get("body_pattern")
        if not body_pat_str:
            continue
        try:
            body_re = re.compile(body_pat_str)
        except re.error:
            continue
        out.append({
            "tech_slug": slug_field,
            "rule_id": rule_id,
            "url_pattern": url_re,
            "slug_group": int((extracts.get("slug") or {}).get("g", 1)),
            "body_pattern": body_re,
            "version_group": int(body_spec.get("g", 1)),
            "name_template": extracts.get("name_template") or "{slug}",
        })
    return out


class SlugReadmeStage(Stage):
    """For every detection whose ``evidence_url`` matches a rule in
    ``slug_url_rules``: extract a slug from the URL, fetch the URL, run
    the rule's body pattern, emit a versioned detection named after the
    slug.

    Uniform across techs. WordPress plugins (`/wp-content/plugins/<slug>
    /readme.txt` -> `Stable tag:`) are the canonical example. No tech-
    specific code lives here -- all signal definitions live in lab.db.
    """

    name = "slug-readme"

    async def apply(self, ctx: StageContext) -> list[dict]:
        if not ctx.lab_db:
            return []
        rules = _load_slug_url_rules(ctx.lab_db)
        if not rules:
            return []

        # Gather (url, slug, rule) tuples from BOTH sources: detection
        # evidence_urls (script-src matches that already carry the asset URL)
        # AND ctx.url_pool (katana page+js URLs and html-asset-walk harvested
        # links). The url_pool source matters for rules whose channel is a
        # <link href> rather than a <script src> -- e.g. WordPress theme
        # style.css references that never flow through Wappalyzer's
        # scriptSrc evidence_url. Each url is fetched at most once.
        candidates: list[tuple[str, str, dict]] = []
        seen_urls: set[str] = set()

        def _consider(url: str) -> None:
            url = (url or "").strip()
            if not url or url in seen_urls:
                return
            for rule in rules:
                m = rule["url_pattern"].search(url)
                if not m:
                    continue
                try:
                    slug = m.group(rule["slug_group"])
                except IndexError:
                    continue
                if not slug:
                    continue
                seen_urls.add(url)
                candidates.append((url, slug, rule))
                return

        for d in ctx.detections:
            if not isinstance(d, dict):
                continue
            _consider(d.get("evidence_url") or d.get("url") or "")
        for url in ctx.url_pool:
            _consider(url)

        if not candidates:
            return []

        from curl_cffi.requests import AsyncSession as _CurlSession
        from fetchlib import build_request_headers

        out: list[dict] = []
        emitted: set[tuple[str, str]] = set()
        async with _CurlSession(
            impersonate="chrome120",
            headers=build_request_headers(ua=ctx.ua),
            timeout=ctx.timeout,
            verify=ctx.verify_ssl,
        ) as session:
            for url, slug, rule in candidates:
                try:
                    r = await session.get(url, allow_redirects=True)
                    if r.status_code != 200 or not r.text:
                        continue
                    body = r.text[: 8 * 1024]
                except Exception:  # noqa: BLE001
                    continue
                bm = rule["body_pattern"].search(body)
                if not bm:
                    continue
                try:
                    ver = bm.group(rule["version_group"]).strip()
                except IndexError:
                    continue
                if not _PLUGIN_VER_RE.match(ver):
                    continue
                # name_template == "{slug}" means "use bare slug; consult
                # lab_pkg_aliases for the canonical display name (Yoast SEO
                # vs raw wordpress-seo)". A template with any prefix /
                # suffix (e.g. "wp-theme:{slug}") preserves the prefix and
                # skips alias lookup -- the prefix is the explicit
                # disambiguator (theme slugs collide with plugin slugs).
                tech_name = rule["name_template"].format(slug=slug)
                if rule["name_template"] == "{slug}":
                    canonical = lookup_canonical_name(ctx.lab_db, slug)
                    # lookup_canonical_name's fallback is title-cased slug;
                    # if it returned that fallback (no real alias row), keep
                    # the slug as-is so we don't fabricate a name.
                    fallback = slug.replace("-", " ").title()
                    if canonical and canonical != fallback:
                        tech_name = canonical
                key = (tech_name.lower(), ver)
                if key in emitted:
                    continue
                emitted.add(key)
                out.append(make_detection(
                    source="readme",
                    tech_name=tech_name,
                    version=ver,
                    url=url,
                    rule_id=rule["rule_id"],
                ))
        return out


# ---------------------------------------------------------------------------
# Stage 3 -- Inline extract (banner regexes over inline <style>/<script>)
# ---------------------------------------------------------------------------


class InlineExtractStage(Stage):
    """Apply ``banner_rules`` over inline ``<style>`` and ``<script>`` blocks
    pulled from ``ctx.html_bodies``. Same rule set as Stage 2, different
    content channel. No fetch -- bodies are already in the context.

    Many CMSes inline a small framework banner into the HTML head as part
    of build pipelines; without this stage that signal is invisible.
    """

    name = "inline-extract"

    async def apply(self, ctx: StageContext) -> list[dict]:
        if not ctx.lab_db or not ctx.html_bodies:
            return []
        rules = load_rules(ctx.lab_db, "banner_rules")
        if not rules:
            return []
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()  # (tech_slug, version) dedup
        for url, html in ctx.html_bodies.items():
            for block in extract_inline_blocks(html):
                for hit in _apply_banner_rules(rules, block[:8192], ctx.lab_db, url):
                    key = (hit["name"], hit["version"])
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(hit)
        return out


# ---------------------------------------------------------------------------
# Stage 4 -- Bundle scan (class / glyph signatures over JS bundles)
# ---------------------------------------------------------------------------


class BundleScanStage(Stage):
    """Apply ``css_class_rules`` and ``kit_rules`` over JS / CSS bundle
    bodies already in ``ctx.js_bodies``. These rules typically detect
    presence (no version) -- they're the fall-through for techs whose
    bundles strip banner comments at build time but still embed
    recognisable class prefixes or kit identifiers.
    """

    name = "bundle-scan"

    async def apply(self, ctx: StageContext) -> list[dict]:
        if not ctx.lab_db or not ctx.js_bodies:
            return []
        rules = load_rules(ctx.lab_db, "css_class_rules") + \
                load_rules(ctx.lab_db, "kit_rules")
        if not rules:
            return []
        # Slugs we've already attributed a (versioned) detection to -- no
        # point emitting a duplicate presence-only hit.
        present: set[str] = set()
        for d in ctx.detections:
            if isinstance(d, dict):
                slug = (d.get("name") or d.get("product") or "").strip().lower()
                if slug:
                    present.add(slug)

        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for url, body in ctx.js_bodies.items():
            for rule in rules:
                slug = rule["tech_slug"]
                canon = lookup_canonical_name(ctx.lab_db, slug)
                if canon.strip().lower() in present:
                    continue
                m = rule["pattern"].search(body[: 256 * 1024])
                if not m:
                    continue
                # Versioned bundle rules: try to extract; presence-only
                # otherwise.
                version: str | None = None
                vgroup = rule["version_group"]
                if vgroup is not None:
                    try:
                        cand = m.group(vgroup)
                    except IndexError:
                        cand = None
                    if cand and is_dotted_version(cand):
                        version = cand
                key = (canon, version or "")
                if key in seen:
                    continue
                seen.add(key)
                out.append(make_detection(
                    source="bundle",
                    tech_name=canon,
                    version=version,
                    url=url,
                    rule_id=rule["rule_id"],
                ))
        return out
