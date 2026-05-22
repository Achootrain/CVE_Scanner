"""Mine version and tech signals from katana-discovered URLs.

Three detection methods, tried in priority order per URL:

  1. **CDN URL** -- version embedded in CDN path.
        cdn.jsdelivr.net/npm/jquery@3.7.1/ -> jQuery 3.7.1
        cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/ -> Bootstrap 5.3.0
        code.jquery.com/jquery-3.7.1.min.js -> jQuery 3.7.1
     Zero extra cost: katana surfaces these during crawl.

  2. **Query-param version** -- ?ver= or ?v= (the original method).
        wp-content/plugins/woocommerce/js/woo.min.js?ver=8.0.0 -> WooCommerce 8.0.0
        assets/js/app.js?v=2.3.1 -> (skipped -- unknown stem)

  3. **Versioned filename** -- version embedded in the filename stem.
        jquery-3.6.3.min.js -> jQuery 3.6.3
        bootstrap-5.3.0.bundle.min.js -> Bootstrap 5.3.0
     Sites that vendor libraries locally and rely on filename versioning
     instead of query params (common for XenForo installs and legacy PHP
     CMSes).

  4. **Framework URL pattern** -- tech detected from URL shape alone
        (no version available). Emits version=None hits.
        /_next/static/ -> Next.js
        /static/chunks/*-<16-hex>.js -> Next.js (custom base path)
        /_nuxt/ -> Nuxt.js
        /_app/immutable/ -> SvelteKit
        /page-data/ -> Gatsby

All results are deduplicated by (tech_lower, version_or_empty) so the same
library appearing at many CDN URLs or in many WP plugin paths collapses to
one canonical hit (first-seen URL is kept as evidence).

Version validation for methods 1-3: must be dotted-numeric (6.4, 7.0.1.1,
3.7.1). Single integers, hashes, and alpha tokens are dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Matches ?ver=X or ?v=X or &ver=X or &v=X (case-insensitive).
_VER_RE = re.compile(r"[?&]v(?:er)?=([0-9][^&#\s\"']*)", re.IGNORECASE)

# Version must be dotted numeric (e.g. "6.4", "7.0.1.1", "3.7.1").
# Rejects pure hashes, single integers, and alpha cache tokens.
_DOTTED_VER_RE = re.compile(r"^\d+(?:\.\d+)+$")

# Webpack 5 / Next.js content-hash suffix: <name>-<16-hex>.js
_NEXT_CHUNK_RE = re.compile(r"-[0-9a-f]{16}\.js$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Catalog (loaded from lab.db at module init -- see _load_from_lab_db below).
#
# The literal contents of WP_PLUGIN_MAP / _JS_LIB_MAP / _CDN_PKG_MAP /
# _SKIP_STEMS / _CDN_PATTERNS / _FRAMEWORK_PATTERNS / _JS_LIB_STEMS_SORTED
# used to live here. Per CLAUDE.md section 5, lab.db is the single source
# of truth; adding a new tech is now `INSERT INTO lab_pkg_aliases ...` then
# `url_ver.reload()` (or a scanner restart). No code commit.
#
# See lab/url_ver_lab/README.md for the seeder + parity test.
# ---------------------------------------------------------------------------

import os as _os
import sqlite3 as _sqlite3
from pathlib import Path as _Path

_LAB_DB_ENV = "FP_LAB_DB"
_DEFAULT_LAB_DB = _Path(__file__).resolve().parent.parent / "lab.db"


def _lab_db_path() -> _Path:
    """Resolve lab.db path. Env var FP_LAB_DB overrides; else fingerprinter/lab.db."""
    env = _os.environ.get(_LAB_DB_ENV)
    return _Path(env) if env else _DEFAULT_LAB_DB


def _load_from_lab_db(db_path: _Path) -> dict:
    """Read all url_ver catalogs from lab.db. Returns a dict of the constants."""
    conn = _sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT alias, tech, context FROM lab_pkg_aliases"
        ).fetchall()
        js_lib: dict[str, str] = {}
        cdn_specific: dict[str, str] = {}
        wp_plugin: dict[str, str] = {}
        skip_stems: set[str] = set()
        for alias, tech, context in rows:
            if context == "js-lib" and tech:
                js_lib[alias] = tech
            elif context == "cdn-pkg" and tech:
                cdn_specific[alias] = tech
            elif context == "wp-plugin" and tech:
                wp_plugin[alias] = tech
            elif context == "skip-stem":
                skip_stems.add(alias)
        # CDN map = js-lib base + cdn-specific overrides (matches old construction)
        cdn_map = {**js_lib, **cdn_specific}

        pattern_rows = conn.execute(
            """SELECT pattern, tech, pkg_group, version_group, kind, family, note
               FROM lab_url_patterns ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()

    cdn_patterns: list[tuple] = []
    framework_patterns: list[tuple] = []
    for pattern, tech, pkg_group, version_group, kind, family, note in pattern_rows:
        if kind == "cdn":
            cdn_patterns.append((re.compile(pattern), pkg_group, version_group, tech))
        elif kind == "framework":
            slug = None
            if note and note.startswith("slug="):
                slug = note[len("slug="):]
            elif family and family.startswith("framework: "):
                slug = family[len("framework: "):]
            framework_patterns.append((re.compile(pattern, re.IGNORECASE), tech, slug))

    return {
        "WP_PLUGIN_MAP": wp_plugin,
        "_JS_LIB_MAP": js_lib,
        "_CDN_PKG_MAP": cdn_map,
        "_SKIP_STEMS": frozenset(skip_stems),
        "_CDN_PATTERNS": cdn_patterns,
        "_FRAMEWORK_PATTERNS": framework_patterns,
    }


def reload(db_path: _Path | str | None = None) -> None:
    """Re-read catalogs from lab.db without restarting the scanner.

    Call after editing lab_pkg_aliases / lab_url_patterns to pick up changes.
    """
    global WP_PLUGIN_MAP, _JS_LIB_MAP, _CDN_PKG_MAP, _SKIP_STEMS
    global _CDN_PATTERNS, _FRAMEWORK_PATTERNS, _JS_LIB_STEMS_SORTED
    path = _Path(db_path) if db_path else _lab_db_path()
    data = _load_from_lab_db(path)
    WP_PLUGIN_MAP = data["WP_PLUGIN_MAP"]
    _JS_LIB_MAP = data["_JS_LIB_MAP"]
    _CDN_PKG_MAP = data["_CDN_PKG_MAP"]
    _SKIP_STEMS = data["_SKIP_STEMS"]
    _CDN_PATTERNS = data["_CDN_PATTERNS"]
    _FRAMEWORK_PATTERNS = data["_FRAMEWORK_PATTERNS"]
    _JS_LIB_STEMS_SORTED = sorted(_JS_LIB_MAP.items(), key=lambda kv: -len(kv[0]))


# Module-init load. Fails loudly if lab.db is unseeded.
reload()


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class UrlVerHit:
    """One tech (+ optional version) signal extracted from a URL."""
    tech: str           # canonical tech name
    version: str | None # dotted-numeric version, or None for pattern-only hits
    url: str            # originating URL
    slug: str           # raw slug/stem/pkg used for template_id

    def to_detection_dict(self) -> dict:
        """Serialize to a Detection-compatible dict for pipeline.reconcile()."""
        return {
            "source": "url-ver",
            "product": self.tech,
            "version": self.version,
            "url": self.url,
            "template_id": f"url-ver:{self.slug}",
            "matcher_name": None,
            "name": self.tech,
            "tags": [],
            "extracted": {},
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _js_stem(filename: str) -> str:
    """Strip common JS/CSS asset extensions; return lowercase stem.

    CSS extensions are included because tail-of-path classification (see
    _classify_path) needs to recognize 'font-awesome.min.css' as the
    font-awesome lib even when the URL sits under a WP plugin slug.
    """
    fname = filename.lower()
    for ext in (".bundle.min.js", ".chunk.min.js", ".min.js", ".bundle.js",
                ".chunk.js", ".umd.js", ".prod.js", ".esm.js", ".mjs", ".cjs", ".js",
                ".min.css", ".css"):
        if fname.endswith(ext):
            fname = fname[: -len(ext)]
            break
    return fname


def _wp_segment(path: str, kind: str) -> str | None:
    """Return the slug after /wp-content/<kind>/ in ``path``, or None."""
    needle = f"/wp-content/{kind}/"
    idx = path.lower().find(needle)
    if idx == -1:
        return None
    rest = path[idx + len(needle):]
    slug = rest.split("/")[0]
    return slug if slug else None


def _classify_path(url: str) -> tuple[str, str] | None:
    """Map a URL path to ``(tech_name, slug)`` for use with the ?ver= method.

    Priority (tail-first):
      1. Known JS/CSS lib filename stem (e.g. font-awesome.min.css -> Font Awesome)
      2. WP plugin slug
      3. WP theme slug
      Returns None for unknown/generic paths.

    Rationale: a URL like
      /wp-content/plugins/contact-widgets/.../font-awesome.min.css?ver=4.7.0
    is the contact-widgets plugin LOADING font-awesome -- the ?ver= belongs
    to font-awesome, not to contact-widgets. Filename (tail) is the truthful
    attribution.
    """
    path = urlsplit(url).path

    # Tail: filename stem against known JS/CSS lib map.
    filename = path.rstrip("/").rsplit("/", 1)[-1] if "/" in path else path
    if filename:
        stem = _js_stem(filename)
        if stem and stem not in _SKIP_STEMS and len(stem) >= 2:
            known = _JS_LIB_MAP.get(stem)
            if known is not None:
                return known, stem

    # Head: WP plugin > WP theme fallback.
    plugin_slug = _wp_segment(path, "plugins")
    if plugin_slug:
        name = WP_PLUGIN_MAP.get(
            plugin_slug,
            plugin_slug.replace("-", " ").title(),
        )
        return name, plugin_slug

    theme_slug = _wp_segment(path, "themes")
    if theme_slug:
        return f"WP Theme: {theme_slug.replace('-', ' ').title()}", theme_slug

    return None


def _extract_from_filename(filename: str) -> tuple[str, str, str] | None:
    """Extract ``(tech, version, stem)`` from a versioned filename.

    Handles ``jquery-3.7.1.min.js``, ``bootstrap-5.3.0.bundle.min.js``,
    ``vue.3.4.15.esm.js``, etc.  Tries each known library stem as a prefix
    (longer stems first) to avoid ``react`` matching before ``react-dom``.
    """
    fname = filename.lower()
    for stem, canonical in _JS_LIB_STEMS_SORTED:
        if fname.startswith(stem + "-") or fname.startswith(stem + "."):
            rest = fname[len(stem) + 1:]  # skip the separator char
            m = re.match(r"(\d+\.\d+(?:\.\d+)*)", rest)
            if m:
                version = m.group(1)
                if _DOTTED_VER_RE.match(version) and len(version) <= 20:
                    return canonical, version, stem
    return None


# ---------------------------------------------------------------------------
# Per-URL extraction methods (each returns (tech, version|None, slug) or None)
# ---------------------------------------------------------------------------


def _try_cdn_url(url: str) -> tuple[str, str, str] | None:
    """Extract tech + version from well-known CDN URL patterns."""
    for pattern, pkg_grp, ver_grp, fixed_name in _CDN_PATTERNS:
        m = pattern.search(url)
        if not m:
            continue
        version = m.group(ver_grp)
        if not _DOTTED_VER_RE.match(version) or len(version) > 20:
            continue
        if fixed_name:
            return fixed_name, version, fixed_name.lower().replace(" ", "-")
        pkg = m.group(pkg_grp)
        canonical = _CDN_PKG_MAP.get(pkg) or _CDN_PKG_MAP.get(pkg.lower())
        if canonical is None:
            continue
        return canonical, version, pkg
    return None


def _try_query_param(url: str) -> tuple[str, str, str] | None:
    """Extract tech + version from ?ver= or ?v= query parameters."""
    m = _VER_RE.search(url)
    if not m:
        return None
    version = m.group(1)
    if len(version) > 20 or not _DOTTED_VER_RE.match(version):
        return None
    classified = _classify_path(url)
    if classified is None:
        return None
    name, slug = classified
    return name, version, slug


def _try_filename_version(url: str) -> tuple[str, str, str] | None:
    """Extract tech + version from a versioned filename in the URL path.

    Handles sites that vendor libraries locally and use filename-based
    versioning (``jquery-3.6.3.min.js``) instead of query params.
    """
    path = urlsplit(url).path
    filename = path.rstrip("/").rsplit("/", 1)[-1] if "/" in path else path
    if not filename:
        return None
    result = _extract_from_filename(filename)
    if result is None:
        return None
    name, version, stem = result
    return name, version, stem


def _try_framework_pattern(url: str) -> tuple[str, None, str] | None:
    """Detect framework from URL path shape alone (no version available).

    Returns ``(tech, None, slug)`` so the hit flows into reconcile as a
    tech-only signal that confirms the framework without pinning a version.
    """
    path = urlsplit(url).path
    for pattern, tech, slug in _FRAMEWORK_PATTERNS:
        if pattern.search(path):
            return tech, None, slug
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_ver_params(urls: list[str]) -> list[UrlVerHit]:
    """Mine tech and version signals from a list of URLs.

    Each URL is tested against four extraction methods in priority order:
    CDN > query-param > filename-version > framework-pattern. The first
    matching method wins; the URL is not re-tested after a match.

    Deduplicates by ``(tech_lower, version_or_empty)`` -- the first URL
    that produces each (tech, version) pair is kept as evidence.

    Returns :class:`UrlVerHit` objects with ``version=None`` for tech-only
    (framework pattern) hits and a dotted-numeric string for versioned hits.
    """
    seen: set[tuple[str, str]] = set()
    hits: list[UrlVerHit] = []

    for url in urls:
        result = (
            _try_cdn_url(url)
            or _try_query_param(url)
            or _try_filename_version(url)
            or _try_framework_pattern(url)
        )
        if result is None:
            continue
        tech_name, version, slug = result

        key = (tech_name.lower(), version or "")
        if key in seen:
            continue
        seen.add(key)
        hits.append(UrlVerHit(tech=tech_name, version=version, url=url, slug=slug))

    return hits
