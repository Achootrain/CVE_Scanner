"""URL & path discovery from web responses.

Independent module shared by the fp scanner and the lab back-test (peer of
``fetchlib/``). Two complementary extractors live here because both crawl
URLs out of fetched responses; callers pick the one matching their intent.

Surface:

- :data:`HTML_LINK_URL_RE` -- compiled regex matching
  ``<link|script|img|a|source|iframe href|src=URL>``. Public so callers
  can `findall` directly when they want a different scan window.
- :func:`looks_like_html` -- 1-KiB content sniff.
- :func:`extract_html_link_urls` -- returns **all** URLs (absolute +
  relative, including cross-host CDN refs and static assets) from an
  HTML body. Used by the lab back-test's cross-host walk.
- :func:`extract_inline_scripts` -- text content of inline ``<script>``
  blocks.
- :func:`extract_paths` -- three-tier regex over a JS body for API
  endpoint paths. Returns :class:`ExtractedPath` with confidence tags.
- :func:`extract_paths_from_html` -- HTML-attribute endpoint scan
  (``form action=``, ``data-href=``, ``hx-get``, ``:action`` ...) + inline
  ``<script>`` recursion. Filters static assets via :data:`_STATIC_EXTS`.
- :class:`ExtractedPath` -- dataclass returned by the endpoint extractors.

Endpoint extractors vs. link-URL extractor
------------------------------------------
``extract_paths*`` finds **server API endpoints** -- paths starting with
``/`` from API-shaped attributes, with static assets (``.css``/``.js``/
images/fonts/maps) dropped. ``extract_html_link_urls`` finds **all
referenced URLs** -- intended for asset/CDN discovery where the version
sits in the URL path itself (``use.fontawesome.com/releases/v6.6.0/``).
The two have opposite filtering policies on purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ExtractedPath:
    path: str
    confidence: str   # "call" | "api" | "template" | "form" | "data-href" | ...
    source_url: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "confidence": self.confidence,
            "source_url": self.source_url,
        }


# ---------------------------------------------------------------------------
# JS body extractors -- three tiers
# ---------------------------------------------------------------------------

_CALL_PATTERNS: list[re.Pattern] = [
    # fetch('/path') / await fetch('/path')
    re.compile(r"""fetch\s*\(\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # axios('/path') or axios.get('/path'), axios.post, etc.
    re.compile(r"""axios(?:\s*\.\s*\w+)?\s*\(\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # $.get/$.post/$.put/$.patch/$.delete/$.ajax
    re.compile(r"""\$\s*\.\s*(?:get|post|put|patch|delete|ajax)\s*\(\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # xhr.open('GET', '/path', ...) -- standard XMLHttpRequest
    re.compile(r"""\.open\s*\(\s*['"][A-Za-z]+['"]\s*,\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # url: '/path' inside option object (fetch init, axios config, etc.)
    re.compile(r"""[{,;]\s*url\s*:\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # baseURL: '/...' or baseUrl: '/...' (axios instance config)
    re.compile(r"""base[Uu][Rr][Ll]\s*:\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # endpoint: '/...' or apiEndpoint: '/...'
    re.compile(r"""[Ee]ndpoint\s*:\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # path: '/...' inside route definition or request config
    re.compile(r"""(?:^|[{,;])\s*path\s*:\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # href: '/...' -- programmatic navigation (router.push, Link href, etc.)
    re.compile(r"""href\s*:\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # request('/path') -- generic named HTTP helper
    re.compile(r"""request\s*\(\s*['"](/[^'"\s]{2,400}?)['"]"""),
    # .get('/path'), .post('/path'), ... -- chained HTTP client methods
    re.compile(r"""\.(?:get|post|put|patch|delete|head|options)\s*\(\s*['"](/[^'"\s]{2,400}?)['"]"""),
]


# Tier 2: API-segment pattern
_API_SEG_RE = re.compile(
    r"""['"](/(?:api|v\d+|rest|graphql|gql|rpc|ws|webhooks?|oauth|auth|token|login"""
    r"""|logout|register|signup|user|users|account|accounts|admin|internal|private"""
    r"""|data|query|mutation|search|upload|download|media|files?|image|images|avatar"""
    r"""|dashboard|settings|profile|me|self|current|health|ping|status|metrics"""
    r"""|analytics)[^'"\s]{0,500})['"]""",
    re.IGNORECASE,
)


# Tier 3: template literal prefix (`/api/${userId}` -> /api/)
_TEMPLATE_RE = re.compile(r"""`(/[a-zA-Z0-9/_\-\.]{2,200})\$\{""")


# ---------------------------------------------------------------------------
# Inline <script> block extractor
# ---------------------------------------------------------------------------

_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)


def extract_inline_scripts(html: str | bytes) -> list[str]:
    """Return the text content of all inline <script> blocks (no src attr)."""
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    return [m.group(1) for m in _INLINE_SCRIPT_RE.finditer(html)]


# ---------------------------------------------------------------------------
# Broad <tag href|src=URL> extractor -- the cross-host walk regex
# ---------------------------------------------------------------------------

HTML_LINK_URL_RE = re.compile(
    r"""<(?:link|script|img|a|source|iframe)\b[^>]*?\b(?:href|src)=["']([^"'\s>]+)["']""",
    re.IGNORECASE,
)


def looks_like_html(body: str | bytes) -> bool:
    """Cheap content-sniff: does the first 1 KiB look like an HTML document?"""
    if isinstance(body, bytes):
        head = body[:1024].decode("utf-8", errors="replace").lower()
    else:
        head = (body or "")[:1024].lower()
    return ("<html" in head) or ("<!doctype html" in head) or ("<head" in head)


def extract_html_link_urls(html: str | bytes, *, scan_bytes: int = 256 * 1024) -> list[str]:
    """Pull every `<tag href|src=URL>` from the first ``scan_bytes`` of HTML.

    Includes cross-host CDN URLs, static-asset refs (.css, .js, images, fonts),
    and same-origin links. No filtering -- the caller decides what to keep.
    Use ``extract_paths_from_html`` instead if you want server API endpoints
    with static assets dropped.
    """
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    return HTML_LINK_URL_RE.findall(html[:scan_bytes])


# ---------------------------------------------------------------------------
# HTML attribute endpoint patterns -- for server-rendered API endpoints
# ---------------------------------------------------------------------------

_HTML_PATTERNS: list[tuple[str, re.Pattern]] = [
    # <form action="/..."> -- definite POST/PUT endpoint
    ("form", re.compile(
        r"""<form\b[^>]*\baction\s*=\s*['"](/[^'"\s>]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
    # data-href="/..." -- most frameworks (XenForo, Turbo, htmx) use this for AJAX triggers
    ("data-href", re.compile(
        r"""data-href\s*=\s*['"](/[^'"\s]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
    # data-url="/..." -- generic AJAX endpoint marker
    ("data-url", re.compile(
        r"""data-url\s*=\s*['"](/[^'"\s]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
    # data-api="/...", data-endpoint="/...", data-action="/..."
    ("data-api", re.compile(
        r"""data-(?:api|endpoint|action|src)\s*=\s*['"](/[^'"\s]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
    # hx-get/hx-post/hx-put/hx-delete="/..." (htmx)
    ("htmx", re.compile(
        r"""hx-(?:get|post|put|patch|delete)\s*=\s*['"](/[^'"\s]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
    # Alpine.js x-bind:action or @submit.prevent with URLs
    ("alpine", re.compile(
        r"""(?:x-bind:action|:action)\s*=\s*['"](/[^'"\s]{2,400}?)['"]""",
        re.IGNORECASE,
    )),
]


# ---------------------------------------------------------------------------
# Noise filter (used only by the endpoint extractors, NOT the link-URL one)
# ---------------------------------------------------------------------------

_STATIC_EXTS: frozenset[str] = frozenset({
    "js", "mjs", "cjs", "jsx", "ts", "tsx",
    "css", "scss", "sass", "less",
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif", "bmp",
    "woff", "woff2", "ttf", "eot", "otf",
    "map", "wasm",
})

_INTERNAL_SUBSTRINGS: tuple[str, ...] = (
    "__webpack", "__vite", "node_modules", "hot-update", "/@fs/", "/@id/",
)


def _is_noise(path: str) -> bool:
    if len(path) < 4:
        return True
    low = path.lower()
    for s in _INTERNAL_SUBSTRINGS:
        if s in low:
            return True
    bare = low.split("?")[0]
    if "." in bare.rsplit("/", 1)[-1]:
        ext = bare.rsplit(".", 1)[1]
        if ext in _STATIC_EXTS:
            return True
    return False


# ---------------------------------------------------------------------------
# Public endpoint extractors (JS bodies + HTML pages)
# ---------------------------------------------------------------------------


def extract_paths(body: str | bytes, source_url: str = "") -> list[ExtractedPath]:
    """Extract API path strings from a JavaScript source body.

    Returns a deduplicated list of ExtractedPath. When the same path appears
    in multiple tiers, the highest-confidence match (call > api > template)
    is kept.
    """
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")

    seen: dict[str, str] = {}  # path -> confidence; first write wins (tiers run in order)

    def _add(raw: str, confidence: str) -> None:
        path = raw.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/") or _is_noise(path):
            return
        if path not in seen:
            seen[path] = confidence

    for pat in _CALL_PATTERNS:
        for m in pat.finditer(body):
            _add(m.group(1), "call")

    for m in _API_SEG_RE.finditer(body):
        _add(m.group(1), "api")

    for m in _TEMPLATE_RE.finditer(body):
        _add(m.group(1), "template")

    return [
        ExtractedPath(path=p, confidence=c, source_url=source_url)
        for p, c in seen.items()
    ]


def extract_paths_from_html(body: str | bytes, source_url: str = "") -> list[ExtractedPath]:
    """Extract endpoint paths from an HTML page.

    Two passes:

    1. **Attribute scan** -- form action=, data-href=, data-url=, htmx
       directives, etc. Catches server-rendered sites (XenForo, WordPress,
       Django, Rails) where API routes live in HTML markup.

    2. **Inline script scan** -- runs the same JS extractor over every inline
       <script> block (no src attribute). Catches jQuery $.get/$.post/fetch
       calls embedded directly in the page template.
    """
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")

    seen: dict[str, str] = {}

    def _add(raw: str, confidence: str) -> None:
        path = raw.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/") or _is_noise(path):
            return
        if path not in seen:
            seen[path] = confidence

    # Pass 1: HTML attribute patterns
    for confidence, pat in _HTML_PATTERNS:
        for m in pat.finditer(body):
            _add(m.group(1), confidence)

    # Pass 2: inline <script> blocks treated as JS
    for script_text in extract_inline_scripts(body):
        if not script_text.strip():
            continue
        for ep in extract_paths(script_text, source_url=source_url):
            _add(ep.path, ep.confidence)

    return [
        ExtractedPath(path=p, confidence=c, source_url=source_url)
        for p, c in seen.items()
    ]


__all__ = [
    "ExtractedPath",
    "HTML_LINK_URL_RE",
    "looks_like_html",
    "extract_html_link_urls",
    "extract_inline_scripts",
    "extract_paths",
    "extract_paths_from_html",
]
