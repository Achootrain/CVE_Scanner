"""Bundle-leak detection and reflective backend probing.

Modern SPAs hardcode their backend hostnames in JS bundles or HTML — Supabase,
Firebase, Hasura, AWS API Gateway, third-party APIs (Stripe, OpenAI, …). Our
existing nuclei + Wappalyzer + retire.js sources don't follow these references,
so the entire backend stack is invisible to them on a JAMstack site whose
homepage is a Vite shell.

This module fills that gap in two passes:

1. **Bundle-leak sweep.** For each response body the scanner has already
   fetched (root HTML + same-host scripts), regex-match a curated list of
   known provider host patterns. Each hit becomes a low-cost
   ``Detection(source="bundle-leak")`` identifying the provider and the
   referenced host. No additional HTTP traffic.

2. **Reflective probe.** A subset of providers ship distinctive 4xx response
   shapes when hit on canonical paths — Supabase PostgREST returns 401 with a
   ``"hint"`` field, Supabase Edge Functions tags responses with
   ``x-served-by: supabase-edge-runtime``, Hasura GraphQL has a recognisable
   error shape on missing-Authorization. For each candidate host (provider-
   matched OR same-registrable-domain as the target) we fire that provider's
   probes and emit ``Detection(source="backend-probe")`` on signature match.
   Probe traffic is bounded by ``MAX_BACKEND_HOSTS`` × ``MAX_PROBES_PER_HOST``.

Same-registrable-domain matching uses the naive last-two-labels heuristic
rather than the public suffix list — good enough to catch ``chai.masterji.co``
referenced from ``www.masterji.co``, with the documented limit that targets
on a multi-label public suffix (``co.uk``) will see false positives in the
candidate set. Probes always require a positive provider signature, so a
false-positive candidate just costs a few wasted HTTP requests.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

import aiohttp

LOG = logging.getLogger("fp.backend_leaks")

MAX_BACKEND_HOSTS = 5
MAX_PROBES_PER_HOST = 3
PROBE_TIMEOUT = aiohttp.ClientTimeout(total=8)
# Cloudflare/Akamai bot management routinely 403s the scanner's honest UA
# on cross-host probes against BaaS providers (Supabase, Firebase, …).
# Backend probes are benign unauthenticated GETs whose value is the WAF-
# transparent provider response shape, so override the UA per-probe with a
# generic browser string. The per-target nuclei/Wappalyzer scan keeps the
# scanner's honest UA — that is only blocked at the same rate as any other
# crawler and the cost there is just one extra detection-source miss.
#
# Single source of truth: fetchlib.CHROME_UA. The lab back-test sources
# the same string so fp + lab present an identical fetch identity.
from fetchlib import CHROME_UA as PROBE_USER_AGENT  # noqa: E402
from fetchlib import build_request_headers as _build_request_headers  # noqa: E402

# Match function signature: (status, headers_lc, body) -> Optional[dict].
# The returned dict carries category, evidence string, and any extracted
# metadata to surface on the resulting Detection.
MatchFn = Callable[[int, dict, bytes], dict | None]


# Stable identity headers Supabase emits on every component (Kong/PostgREST,
# Storage, Edge Functions, Auth). Excluded on purpose: `sb-request-id`,
# `x-envoy-attempt-count`, `x-envoy-upstream-service-time` — all per-request
# noise that would pollute Detection.extracted across scans.
_SB_IDENTITY_HEADERS = ("sb-project-ref", "sb-gateway-version", "sb-gateway-mode")


def _extract_sb_metadata(headers_lc: dict) -> dict[str, list[str]]:
    """Pull the stable Supabase identity headers into the extracted-metadata
    shape used by Detection.extracted (`{key: [value, ...]}`)."""
    out: dict[str, list[str]] = {}
    for h in _SB_IDENTITY_HEADERS:
        if (v := headers_lc.get(h)):
            out[h] = [v]
    return out


# ---------------------------------------------------------------------------
# Probe matchers
# ---------------------------------------------------------------------------


def _match_supabase_kong_gateway(status: int, headers_lc: dict, body: bytes) -> dict | None:
    # Earlier this matcher was named `_match_supabase_postgrest`. That was
    # wrong: this 401 is emitted by Kong's Supabase plugin *in front of*
    # PostgREST, not by PostgREST itself. PostgREST's own error envelope is
    # 4-field (`code`, `details`, `hint`, `message`) and only fires once a
    # request gets past the gateway. Verified live against masterji.co
    # (2026-04-26): unauthenticated `/rest/v1/` returns Kong's shape;
    # authenticated requests with a syntactic error return PostgREST's
    # 4-field shape with PG SQLSTATE in `code`.
    #
    # The shape is still highly diagnostic of a Supabase project — Kong
    # alone elsewhere does not emit this exact `hint`/`apikey` envelope —
    # but the label must reflect what we are actually matching.
    if status != 401:
        return None
    if b'"hint"' not in body or b"apikey" not in body:
        return None
    return {
        "category": "Backend (BaaS)",
        "evidence": "Kong gateway 401 (Supabase plugin)",
        "extracted": _extract_sb_metadata(headers_lc),
    }


def _match_supabase_storage_version(status: int, headers_lc: dict, body: bytes) -> dict | None:
    # GET /storage/v1/version on a Supabase project returns the storage-api
    # semver as a plain-text body (Content-Type: text/plain). No auth needed,
    # no apikey needed — it is a public health/version endpoint.
    # Verified live against masterji.co (2026-04-26): returned `1.54.0`.
    #
    # Other Supabase services (auth, realtime, rest) gate behind apikey, so
    # this probe is the only unauthenticated cross-component version pin
    # we get without auth-level plumbing.
    if status != 200:
        return None
    ct = headers_lc.get("content-type", "").lower()
    if "text/plain" not in ct:
        return None
    text = body.decode("utf-8", "ignore").strip()
    # Defensive: storage-api emits a bare semver (e.g. "1.54.0"). Reject
    # anything that does not parse as one to avoid matching a generic 200.
    if not _SEMVER_RE.fullmatch(text):
        return None
    extracted = _extract_sb_metadata(headers_lc)
    extracted["version"] = [text]
    return {
        "category": "Backend (BaaS)",
        "evidence": f"Supabase Storage version {text}",
        "extracted": extracted,
    }


# Bare semver only (1.54.0 / 2.188.1 / 0.10.3). Looser semver grammar (with
# pre-release / build metadata) is unnecessary — storage-api emits a clean
# triple. Strict matching is what makes this safe to fire on a 200.
_SEMVER_RE = re.compile(r"\d+\.\d+\.\d+")


def _match_supabase_edge_functions(status: int, headers_lc: dict, body: bytes) -> dict | None:
    # Edge Functions gateway tags every response with `x-served-by:
    # supabase-edge-runtime`. Non-existent function paths return 404
    # plus structured `sb-*` headers that leak project ref + region.
    served_by = headers_lc.get("x-served-by", "").lower()
    if "supabase-edge-runtime" not in served_by:
        return None
    extracted = _extract_sb_metadata(headers_lc)
    if (region := headers_lc.get("x-sb-edge-region")):
        extracted["region"] = [region]
    return {
        "category": "Backend (BaaS)",
        "evidence": "x-served-by: supabase-edge-runtime",
        "extracted": extracted,
    }


def _match_hasura(status: int, headers_lc: dict, body: bytes) -> dict | None:
    # Hasura GraphQL endpoints return an error JSON of shape
    #   {"errors":[{"extensions":{"path":"$","code":"..."}, ...}]}
    # on malformed/empty queries. The `extensions.path` + `code` combo is
    # distinctively hasura-shaped (Apollo and Yoga errors look different).
    if b'"extensions"' not in body or b'"code"' not in body:
        return None
    if b'"path":"$"' not in body and b'"path": "$"' not in body:
        return None
    return {
        "category": "Backend (GraphQL)",
        "evidence": "Hasura error shape on /v1/graphql",
    }


# ---------------------------------------------------------------------------
# Probe specs
# ---------------------------------------------------------------------------


@dataclass
class Probe:
    method: str
    path_template: str  # may contain "{uuid}" for cache-busting / 404 paths
    name: str
    matcher: MatchFn
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def resolve_path(self) -> str:
        if "{uuid}" in self.path_template:
            return self.path_template.replace("{uuid}", uuid.uuid4().hex[:12])
        return self.path_template


# Provider catalog. host_patterns identifies the provider from a referenced
# URL; probes confirm the provider via response shape.
PROVIDERS: dict[str, dict] = {
    "Supabase": {
        "category": "Backend (BaaS)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9][a-z0-9-]*\.supabase\.(?:co|com))", re.I),
        ],
        "probes": [
            Probe("GET", "/rest/v1/", "Supabase Kong Gateway", _match_supabase_kong_gateway),
            Probe("GET", "/storage/v1/version", "Supabase Storage",
                  _match_supabase_storage_version),
            Probe("GET", "/functions/v1/__fp_{uuid}", "Supabase Edge Functions",
                  _match_supabase_edge_functions),
        ],
    },
    "Firebase": {
        "category": "Backend (BaaS)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9-]+\.firebaseio\.com)", re.I),
            re.compile(r"https?://([a-z0-9-]+\.firebasestorage\.googleapis\.com)", re.I),
            re.compile(r"https?://([a-z0-9-]+\.firebaseapp\.com)", re.I),
            re.compile(r"https?://([a-z0-9-]+\.web\.app)", re.I),
        ],
        "probes": [],
    },
    "Hasura": {
        "category": "Backend (GraphQL)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9-]+\.hasura\.app)", re.I),
        ],
        "probes": [
            Probe(
                "POST", "/v1/graphql", "Hasura GraphQL", _match_hasura,
                body=b'{"query":"{__schema{types{name}}}"}',
                headers={"Content-Type": "application/json"},
            ),
        ],
    },
    "Auth0": {
        "category": "Auth",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9-]+\.(?:eu|us|au)\.auth0\.com)", re.I),
            re.compile(r"https?://([a-z0-9-]+\.auth0\.com)", re.I),
        ],
        "probes": [],
    },
    "Stripe API": {
        "category": "Payments",
        "host_patterns": [
            re.compile(r"https?://(api\.stripe\.com|js\.stripe\.com|m\.stripe\.com|checkout\.stripe\.com)", re.I),
        ],
        "probes": [],
    },
    "OpenAI API": {
        "category": "AI",
        "host_patterns": [re.compile(r"https?://(api\.openai\.com)", re.I)],
        "probes": [],
    },
    "Anthropic API": {
        "category": "AI",
        "host_patterns": [re.compile(r"https?://(api\.anthropic\.com)", re.I)],
        "probes": [],
    },
    "AWS API Gateway": {
        "category": "Backend (PaaS)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)", re.I),
        ],
        "probes": [],
    },
    "AWS Lambda Function URL": {
        "category": "Backend (PaaS)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws)", re.I),
        ],
        "probes": [],
    },
    "Cloudflare Workers": {
        "category": "Backend (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.workers\.dev)", re.I)],
        "probes": [],
    },
    "Vercel": {
        "category": "Hosting (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.vercel\.app)", re.I)],
        "probes": [],
    },
    "Netlify": {
        "category": "Hosting (PaaS)",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9-]+\.netlify\.app)", re.I),
            re.compile(r"https?://([a-z0-9-]+\.netlify\.com)", re.I),
        ],
        "probes": [],
    },
    "Heroku": {
        "category": "Hosting (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.herokuapp\.com)", re.I)],
        "probes": [],
    },
    "Render": {
        "category": "Hosting (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.onrender\.com)", re.I)],
        "probes": [],
    },
    "Fly.io": {
        "category": "Hosting (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.fly\.dev)", re.I)],
        "probes": [],
    },
    "Railway": {
        "category": "Hosting (PaaS)",
        "host_patterns": [re.compile(r"https?://([a-z0-9-]+\.up\.railway\.app)", re.I)],
        "probes": [],
    },
    "Algolia": {
        "category": "Search",
        "host_patterns": [
            re.compile(r"https?://([a-z0-9]+(?:-dsn)?\.algolia\.net)", re.I),
            re.compile(r"https?://([a-z0-9]+(?:-dsn)?\.algolianet\.com)", re.I),
        ],
        "probes": [],
    },
    "Sentry": {
        "category": "Observability",
        "host_patterns": [
            re.compile(r"https?://(o\d+\.ingest\.[a-z0-9-]+\.sentry\.io)", re.I),
            re.compile(r"https?://(sentry\.io)", re.I),
        ],
        "probes": [],
    },
    "PostHog": {
        "category": "Analytics",
        "host_patterns": [
            re.compile(r"https?://(app\.posthog\.com|eu\.posthog\.com|us\.posthog\.com)", re.I),
        ],
        "probes": [],
    },
    "Razorpay": {
        "category": "Payments",
        "host_patterns": [
            re.compile(r"https?://(api\.razorpay\.com|checkout\.razorpay\.com)", re.I),
        ],
        "probes": [],
    },
}

# Generic absolute-URL extractor — used to discover same-registrable-domain
# hosts that don't match any known provider pattern. Bounded to
# `[a-zA-Z0-9._-]+` hostnames; we don't follow IP literals or punycode here.
_HOST_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9._-]+)(?::\d+)?(?=[/\s'\"`)<])")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class BundleLeak:
    """A backend host referenced in a fetched body. The provider is set when
    the host matches a known catalog pattern; otherwise the leak originates
    from same-registrable-domain heuristic and provider is None."""
    host: str
    provider: str | None
    category: str | None
    found_in_url: str  # the script body or HTML where the host was referenced


@dataclass
class BackendProbeHit:
    host: str
    provider: str
    signature: str  # e.g. "Supabase PostgREST"
    category: str
    evidence: str
    extracted: dict[str, list[str]] = field(default_factory=dict)
    probe_url: str = ""


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _registrable(host: str) -> str:
    """Naive eTLD+1 — last two labels of the hostname. Treats `co.uk` as if
    it were a registrable, which is wrong for multi-label TLDs but only
    affects the candidate set, not detection accuracy: probes still require
    a positive provider signature."""
    parts = host.lower().rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _same_registrable(host_a: str, host_b: str) -> bool:
    return _registrable(host_a) == _registrable(host_b) and host_a.lower() != host_b.lower()


def extract_leaks(body: str, source_url: str) -> list[BundleLeak]:
    """Sweep `body` for known provider host patterns. Returns one BundleLeak
    per (provider, host) discovered, deduped within the call."""
    if not body:
        return []
    out: list[BundleLeak] = []
    seen: set[tuple[str, str]] = set()
    for provider, spec in PROVIDERS.items():
        for pat in spec["host_patterns"]:
            for m in pat.finditer(body):
                host = m.group(1).lower()
                key = (provider, host)
                if key in seen:
                    continue
                seen.add(key)
                out.append(BundleLeak(
                    host=host, provider=provider,
                    category=spec["category"], found_in_url=source_url,
                ))
    return out


def discover_candidate_hosts(
    bodies: list[tuple[str, str]],   # (source_url, body) pairs
    target_host: str,
) -> list[BundleLeak]:
    """Return candidate hosts to probe.

    Candidates are:
      * Provider-matched hosts (set provider/category)
      * Hosts in the same registrable domain as `target_host` whose
        provider is initially unknown (provider=None) — these get probed
        with every catalog probe to discover what they actually are.

    Capped at MAX_BACKEND_HOSTS, with provider-matched hosts ranked first
    (they have the highest signal-to-noise)."""
    by_host: dict[str, BundleLeak] = {}

    # First pass: provider-matched leaks.
    for source_url, body in bodies:
        for leak in extract_leaks(body, source_url):
            # Don't probe ourselves.
            if leak.host == target_host.lower():
                continue
            by_host.setdefault(leak.host, leak)

    # Second pass: same-registrable hosts not already provider-matched.
    for source_url, body in bodies:
        for m in _HOST_RE.finditer(body or ""):
            host = m.group(1).lower()
            if host in by_host or host == target_host.lower():
                continue
            if _same_registrable(host, target_host):
                by_host[host] = BundleLeak(
                    host=host, provider=None, category=None,
                    found_in_url=source_url,
                )

    # Provider-matched first, then unknowns; cap to MAX_BACKEND_HOSTS.
    matched = [v for v in by_host.values() if v.provider is not None]
    unknown = [v for v in by_host.values() if v.provider is None]
    return (matched + unknown)[:MAX_BACKEND_HOSTS]


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


def _probes_for(leak: BundleLeak) -> list[tuple[str, Probe]]:
    """Return [(provider, Probe)] to fire against `leak.host`. If the leak
    is provider-tagged, only that provider's probes run; otherwise every
    catalog probe is tried (cheap — at most a handful of providers ship
    probes today)."""
    pairs: list[tuple[str, Probe]] = []
    if leak.provider is not None:
        spec = PROVIDERS.get(leak.provider, {})
        pairs.extend((leak.provider, p) for p in spec.get("probes", []))
        return pairs[:MAX_PROBES_PER_HOST]
    for provider, spec in PROVIDERS.items():
        pairs.extend((provider, p) for p in spec.get("probes", []))
    return pairs[:MAX_PROBES_PER_HOST]


async def _send_probe(
    session: aiohttp.ClientSession, host: str, probe: Probe,
) -> tuple[int, dict, bytes] | None:
    url = f"https://{host}{probe.resolve_path()}"
    # Per-request headers merge over session headers; the full Chrome 121
    # header shape (UA + sec-ch-ua + Sec-Fetch-* + Accept-Language) overrides
    # the session's scanner-honest UA. Probe-specific headers (Content-Type,
    # Origin) win on conflict via the `extra` arg.
    headers = _build_request_headers(ua=PROBE_USER_AGENT, extra=probe.headers)
    try:
        async with session.request(
            probe.method, url, data=probe.body,
            headers=headers, allow_redirects=True,
            ssl=False,
        ) as r:
            body = await r.read()
            headers_lc = {k.lower(): v for k, v in r.headers.items()}
            return (r.status, headers_lc, body)
    except Exception as exc:  # noqa: BLE001
        LOG.debug("probe failed %s %s: %s", probe.method, url, exc)
        return None


async def probe_host(
    session: aiohttp.ClientSession, leak: BundleLeak,
) -> list[BackendProbeHit]:
    """Run the appropriate probe set against `leak.host` and return any
    matched signatures. Multiple signatures may match a single host — e.g.
    a Supabase project exposes both PostgREST and Edge Functions."""
    hits: list[BackendProbeHit] = []
    for provider, probe in _probes_for(leak):
        result = await _send_probe(session, leak.host, probe)
        if result is None:
            continue
        status, headers_lc, body = result
        match = probe.matcher(status, headers_lc, body)
        if not match:
            continue
        hits.append(BackendProbeHit(
            host=leak.host,
            provider=provider,
            signature=probe.name,
            category=match.get("category", PROVIDERS[provider]["category"]),
            evidence=match.get("evidence", ""),
            extracted=match.get("extracted", {}),
            probe_url=f"https://{leak.host}{probe.resolve_path()}",
        ))
    return hits


def target_host_of(url: str) -> str:
    return urlsplit(url).netloc.split(":")[0]
