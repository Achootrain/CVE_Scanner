"""Config-blob leak extraction.

SPA frameworks inline a JSON config blob into the page HTML:

  - Nuxt:  ``window.__NUXT__={config:{...}}``
  - Next:  ``<script id="__NEXT_DATA__" type="application/json">{...}</script>``
  - Remix: ``window.__remixContext = {...}``
  - Generic: ``window.ENV = {...}`` / ``window.__INITIAL_STATE__`` / etc.

These blobs routinely contain absolute backend URLs (BASE_URL, *_ENDPOINT),
auth-model identifiers (Cognito user pool / client IDs, OAuth client IDs),
API keys (Stripe pk_live_*) and feature flags -- all sitting in plain text.
The line-level fetch/axios regex tiers in ``jsextract.py`` cannot match
these because the values are JSON string properties, not call sites.

Output schema is ``ConfigLeak(framework, key_path, value, leak_class)``
where ``leak_class`` is one of:

  - ``backend_url``   value is an absolute http(s):// URL
  - ``api_key``       value matches a known credential prefix
                      (Stripe pk_/sk_, AWS AKIA, Google AIza, etc.)
  - ``auth_id``       key implies an auth-model identifier
                      (Cognito pool/client, OAuth client, project_id)
  - ``feature_flag``  any other key matching the curated suffix list
                      (_URL/_ENDPOINT/_BASE/_HOST/_KEY/_ID/_REGION/...)

Reference fixture (verified 2026-04-30): ``window.__NUXT__`` on
wappalyzer.com homepage exposes ``BASE_URL=https://api.wappalyzer.com/v2/``,
two further backend hosts, a Cognito user pool ID, and a Stripe public key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterator


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ConfigLeak:
    framework: str   # nuxt | next | remix | window-env
    key_path: str    # e.g. "config.BASE_URL" or "props.pageProps.apiUrl"
    value: str
    leak_class: str  # backend_url | api_key | auth_id | feature_flag

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "key_path": self.key_path,
            "value": self.value,
            "leak_class": self.leak_class,
        }


# ---------------------------------------------------------------------------
# Framework entry-point patterns
# ---------------------------------------------------------------------------

# Patterns marking the start of a JS-object-literal blob. We match up to the
# opening "{" and then snip the rest by scanning forward to the next
# </script> tag, since balanced-brace parsing in regex is brittle and the
# downstream key:"value" extraction is robust to extra trailing content.
_NUXT_START = re.compile(
    r"window\s*\.\s*__NUXT__\s*=\s*\{",
)
_REMIX_START = re.compile(
    r"window\s*\.\s*__remixContext\s*=\s*\{",
)
# Generic alternatives; ordered by specificity (curated names first).
_GENERIC_START = re.compile(
    r"window\s*\.\s*("
    r"__ENV__|ENV|env|__CONFIG__|CONFIG|config|appConfig|APP_CONFIG"
    r"|__INITIAL_STATE__|__PRELOADED_STATE__|__APOLLO_STATE__"
    r")\s*=\s*\{",
)

# Next: <script id="__NEXT_DATA__" type="application/json">{...}</script>
# Strict JSON inside the script tag -- json.loads handles it.
_NEXT_TAG_RE = re.compile(
    r'<script[^>]*\bid\s*=\s*["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Key/value extraction (JS object literal blobs)
# ---------------------------------------------------------------------------

# Match KEY:"VALUE" pairs where:
#   - KEY may be unquoted (Nuxt) or double/single-quoted (mixed bundles)
#   - VALUE is a double-quoted string with standard JS escape sequences
# Single-quoted values are out of scope; minified Nuxt/Next/Remix bundles
# emit double-quoted values regardless of source style.
_KEY_VALUE_RE = re.compile(
    r'(["\']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"',
)


def _unescape_js_string(s: str) -> str:
    """Best-effort JS-string-literal unescape for the values we surface.

    Only the common escapes are handled (\\\\, \\\", \\n, \\t, \\/). Sufficient
    for URLs and identifiers; we do not interpret \\u#### because the values
    that matter (URLs, Cognito IDs, Stripe keys) are ASCII-only in practice.
    """
    return (
        s.replace(r"\\", "\x00")  # placeholder so the next replaces don't double-process
         .replace(r"\"", '"')
         .replace(r"\/", "/")
         .replace(r"\n", "\n")
         .replace(r"\t", "\t")
         .replace("\x00", "\\")
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

# Credential-prefix patterns. Matching here promotes the value to api_key
# regardless of the key name.
_API_KEY_PREFIX_RE = re.compile(
    r"^("
    r"pk_(?:live|test)_[A-Za-z0-9]{16,}"          # Stripe public
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"         # Stripe secret (rare in HTML)
    r"|rk_(?:live|test)_[A-Za-z0-9]{16,}"         # Stripe restricted
    r"|AKIA[0-9A-Z]{16}"                          # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{20,}"                   # Google API key
    r"|ya29\.[0-9A-Za-z_\-]+"                     # Google OAuth token
    r"|sntrys_[A-Za-z0-9_]+"                      # Sentry sntrys_*
    r"|xox[abprs]-[A-Za-z0-9-]+"                  # Slack tokens
    r")",
)

# Key names that imply an auth-model identifier.
_AUTH_ID_KEY_RE = re.compile(
    r"(COGNITO|USER_POOL|CLIENT_ID|TENANT_ID|AUTH0|OAUTH|FIREBASE|PROJECT_ID|APP_ID)",
    re.IGNORECASE,
)

# Curated suffix/keyword list for "interesting" config keys -- catches
# misc URL/host/region values not already classified as backend_url.
_KEY_INTEREST_RE = re.compile(
    r"(?:_URL|_ENDPOINT|_BASE|_HOST|_KEY|_ID|_REGION|_POOL|_TOKEN"
    r"|_DOMAIN|_API|_BUCKET|_DSN|_ARN)$",
    re.IGNORECASE,
)


def _classify(key: str, value: str) -> str | None:
    """Return the leak_class for (key, value), or None if uninteresting."""
    if not value:
        return None
    if _API_KEY_PREFIX_RE.match(value):
        return "api_key"
    if _URL_RE.match(value):
        return "backend_url"
    if _AUTH_ID_KEY_RE.search(key):
        return "auth_id"
    if _KEY_INTEREST_RE.search(key):
        return "feature_flag"
    return None


# ---------------------------------------------------------------------------
# Helpers: scope extraction + tree walk
# ---------------------------------------------------------------------------


def _scope_after(html: str, match_end: int) -> str:
    """Return text from match_end up to the next ``</script>`` (or EOS).

    The scope spans from just after the opening ``{`` of the matched
    ``window.X = {`` literal to the first script-tag close. Trailing content
    beyond the literal is harmless: the key:"value" extractor only matches
    well-formed pairs and the classifier drops uninteresting ones.
    """
    end = html.find("</script>", match_end)
    if end == -1:
        end = len(html)
    return html[match_end:end]


def _walk_json(node, path: str = "") -> Iterator[tuple[str, str]]:
    """Walk a parsed JSON tree, yielding (key_path, value) for string values."""
    if isinstance(node, dict):
        for k, v in node.items():
            kp = f"{path}.{k}" if path else str(k)
            yield from _walk_json(v, kp)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            kp = f"{path}[{i}]" if path else f"[{i}]"
            yield from _walk_json(item, kp)
    elif isinstance(node, str):
        if path:
            yield path, node


# ---------------------------------------------------------------------------
# Per-framework extractors
# ---------------------------------------------------------------------------


def _extract_kv_pairs(blob: str, framework: str) -> Iterator[ConfigLeak]:
    """Regex-extract key:"value" pairs from a JS-object-literal scope."""
    for m in _KEY_VALUE_RE.finditer(blob):
        key = m.group(2)
        value = _unescape_js_string(m.group(3))
        klass = _classify(key, value)
        if klass is None:
            continue
        yield ConfigLeak(framework, key, value, klass)


def _extract_next(html: str) -> Iterator[ConfigLeak]:
    """Parse the strict JSON inside ``<script id="__NEXT_DATA__">``."""
    for m in _NEXT_TAG_RE.finditer(html):
        blob = m.group(1).strip()
        if not blob:
            continue
        try:
            data = json.loads(blob)
        except (ValueError, json.JSONDecodeError):
            # Malformed Next blob (rare). Fall back to the regex pass so we
            # still surface anything we can recognise.
            yield from _extract_kv_pairs(blob, "next")
            continue
        for key_path, value in _walk_json(data):
            leaf = key_path.rsplit(".", 1)[-1].split("[", 1)[0]
            klass = _classify(leaf, value)
            if klass is None:
                continue
            yield ConfigLeak("next", key_path, value, klass)


def _extract_jsobj(html: str, start_re: re.Pattern, framework: str) -> Iterator[ConfigLeak]:
    """Extract from each JS-object-literal blob matched by ``start_re``."""
    for m in start_re.finditer(html):
        scope = _scope_after(html, m.end())
        yield from _extract_kv_pairs(scope, framework)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_config_leaks(html: str | bytes) -> list[ConfigLeak]:
    """Extract all config-blob leaks from an HTML body.

    Runs each framework-specific entry-point pattern and collects classified
    (key, value) pairs. Output is deduplicated by ``(framework, key_path,
    value)`` so the same leak appears at most once per body.
    """
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    if not html:
        return []

    out: list[ConfigLeak] = []
    seen: set[tuple[str, str, str]] = set()

    sources: list[Iterator[ConfigLeak]] = [
        _extract_next(html),
        _extract_jsobj(html, _NUXT_START, "nuxt"),
        _extract_jsobj(html, _REMIX_START, "remix"),
        _extract_jsobj(html, _GENERIC_START, "window-env"),
    ]
    for it in sources:
        for leak in it:
            key = (leak.framework, leak.key_path, leak.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(leak)
    return out
