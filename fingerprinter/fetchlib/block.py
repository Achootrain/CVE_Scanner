"""Bot-block / challenge-page detection.

Pure function over (status_code, body_snippet, headers_lc) - returns a
short vendor label or None. Used by the lab back-test runner; can also
be called from fp's async scanner side after a fetch completes.

Coverage: Cloudflare (multiple variants), Akamai, Sucuri, DataDome,
Imperva Incapsula, PerimeterX. Same set crawl4ai's 3-tier detector
checks at the "vendor identification" stage.
"""

from __future__ import annotations


# (substring, label) - first match wins. Snippet checked is the first
# 8 KiB of the response body. Order chosen so the most specific labels
# come first (so e.g. 'cloudflare:challenge-platform' wins over a
# generic 'Cloudflare Ray ID' co-occurrence).
BLOCK_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("Just a moment...", "cloudflare:interstitial"),
    ("Attention Required! | Cloudflare", "cloudflare:block-page"),
    ("/cdn-cgi/challenge-platform", "cloudflare:challenge-platform"),
    ("__cf_chl_", "cloudflare:challenge-param"),
    ("cf-mitigated", "cloudflare:mitigated"),
    ("Cloudflare Ray ID", "cloudflare:ray-id-page"),
    ("Akamai", "akamai:page"),
    ("AKAM_REF", "akamai:ref"),
    ("Sucuri WebSite Firewall", "sucuri:waf"),
    ("DataDome", "datadome"),
    ("Imperva Incapsula", "imperva:incapsula"),
    ("/_Incapsula_Resource", "imperva:resource"),
    ("PerimeterX", "perimeterx"),
)


def detect_block(status: int | None, body: str, *, cf_ray: bool = False) -> str | None:
    """Return a vendor label if this response looks like a bot-block, else None.

    A 200 with a Cloudflare signature happens (some configs serve a
    challenge page with 200). A 403/503 with a `cf-ray` header is itself
    a block signal even when the body is empty.
    """
    snippet = (body or "")[:8192]
    for sig, label in BLOCK_SIGNATURES:
        if sig in snippet:
            return label
    if status in (403, 503) and cf_ray:
        return "cloudflare:block-status"
    return None
