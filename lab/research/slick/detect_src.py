"""Source-grounded slick detector.

Loads rules_src.json (authored from slick release source) and applies them to
a given scan record's evidence URLs and optionally fetched JS/CSS bodies.

Output:
- exact `version` if any rule extracts one (banner / version-in-URL)
- detection-only signals (filename match, webfont match) when no version recoverable

No URL is fetched unless callers pass a fetcher; the detector operates on
already-acquired evidence URLs whenever possible.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
RULES_FILE = HERE / "rules_src.json"

sys.path.insert(0, str(REPO / "fingerprinter"))
import fetchlib  # noqa: E402


# HTML extractors
RE_LINK_HREF = re.compile(r'<link[^>]*\bhref=["\']([^"\']*)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]*\bsrc=["\']([^"\']*)["\']', re.I)


def _looks_slick(url: str) -> bool:
    """Quick filter: does the URL reference slick?"""
    return bool(re.search(r"slick", url, re.I))


@dataclass
class Detection:
    version: str | None = None
    sources: list[dict] = field(default_factory=list)
    slick_urls: list[str] = field(default_factory=list)
    filename_matches: list[str] = field(default_factory=list)
    webfont_matches: list[str] = field(default_factory=list)

    def absorb(self, rule_id: str, extracted: dict, evidence_url: str | None = None, evidence_kind: str = "") -> None:
        for k, v in extracted.items():
            if v is None:
                continue
            if k == "version" and not self.version:
                self.version = v
        self.sources.append({"rule": rule_id, "kind": evidence_kind, "url": evidence_url})

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "sources": self.sources,
            "slick_urls": self.slick_urls,
            "filename_matches": self.filename_matches,
            "webfont_matches": self.webfont_matches,
        }


def load_rules(path: Path = RULES_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_extracts(extracts: dict, m: re.Match | None) -> dict:
    """Resolve {'g':N}/{'l':V} into concrete values."""
    out: dict = {}
    for key, spec in extracts.items():
        if not isinstance(spec, dict):
            out[key] = spec
            continue
        if "g" in spec and m is not None:
            try:
                out[key] = m.group(spec["g"])
            except IndexError:
                pass
        elif "l" in spec:
            out[key] = spec["l"]
    return out


def _apply_url_rules(rules: dict, urls: list[str], det: Detection) -> None:
    """Apply url_version / url_filename / webfont rules to URLs."""
    for section in ("url_version_in_path_rules", "url_filename_rules", "webfont_rules"):
        for rule in rules.get(section, []):
            pat = re.compile(rule["pattern"], re.I)
            for u in urls:
                m = pat.search(u)
                if not m:
                    continue
                extracted = _resolve_extracts(rule["extracts"], m)
                det.absorb(rule["id"], extracted, evidence_url=u, evidence_kind=section)
                if section == "url_filename_rules":
                    det.filename_matches.append(rule["id"])
                elif section == "webfont_rules":
                    det.webfont_matches.append(rule["id"])


def _apply_body_rules(rules: dict, body: str, source_url: str | None, det: Detection) -> None:
    """Apply banner rules to a JS body."""
    snippet = body[:16384]  # slick banner is at the top
    for rule in rules.get("banner_rules", []):
        pat = re.compile(rule["pattern"], re.I)
        m = pat.search(snippet)
        if not m:
            continue
        extracted = _resolve_extracts(rule["extracts"], m)
        det.absorb(rule["id"], extracted, evidence_url=source_url, evidence_kind="banner")


def _extract_urls(html: str, origin: str) -> list[str]:
    """Pull URLs from HTML that look slick-related."""
    out: list[str] = []
    seen: set[str] = set()
    for rx in (RE_LINK_HREF, RE_SCRIPT_SRC):
        for raw in rx.findall(html):
            raw = raw.strip()
            if not raw or not _looks_slick(raw):
                continue
            # normalize
            if raw.startswith("//"):
                full = "https:" + raw
            elif raw.startswith("/"):
                u = urlparse(origin)
                full = f"{u.scheme}://{u.netloc}{raw}"
            elif not raw.startswith(("http://", "https://")):
                full = f"{origin.rstrip('/')}/{raw}"
            else:
                full = raw
            if full not in seen:
                seen.add(full)
                out.append(full)
    return out


def detect_from_record(rec: dict, *, rules: dict | None = None, fetcher=None, throttle=None) -> Detection:
    """Run detection against a scan record (from scan_results JSONL).

    Uses:
    - evidence URLs from the record's techs[].evidence[].url
    - endpoints from the record's endpoints[].url
    - HTML body extraction for additional URLs (if HTML was captured)
    """
    if rules is None:
        rules = load_rules()

    det = Detection()
    target = rec.get("target") or rec.get("url") or ""
    origin = target if target.startswith(("http://", "https://")) else f"https://{target}"

    # Collect all URLs from evidence and endpoints
    all_urls: list[str] = []
    seen: set[str] = set()

    for tech in rec.get("techs", []) or []:
        for ev in tech.get("evidence", []) or []:
            u = (ev.get("url") or "").strip()
            if u and u not in seen:
                seen.add(u)
                all_urls.append(u)

    for ep in rec.get("endpoints", []) or []:
        u = (ep.get("url") or "").strip()
        if u and u not in seen:
            seen.add(u)
            all_urls.append(u)

    # Filter to slick-relevant URLs for filename/webfont rules,
    # but also apply version-in-path rules to all URLs
    slick_urls = [u for u in all_urls if _looks_slick(u)]
    det.slick_urls = slick_urls

    # Stage 1: URL rules (cheap, no HTTP)
    _apply_url_rules(rules, all_urls, det)

    # Stage 1b: if no slick URLs surfaced in the record (scanner discarded the
    # matcher URL, only root remains) and a fetcher is provided, fetch root
    # HTML and extract slick-related URLs from <link>/<script> tags.
    if fetcher is not None and not slick_urls:
        host = urlparse(origin).netloc
        if throttle:
            throttle.acquire(host)
        try:
            res = fetcher.fetch(origin, timeout=10.0, verify_ssl=False, extra_headers={})
        except Exception:
            res = None
        if res is not None and res.is_ok and res.body:
            extra = _extract_urls(res.body, origin)
            for u in extra:
                if u not in seen:
                    seen.add(u)
                    all_urls.append(u)
            slick_urls = [u for u in all_urls if _looks_slick(u)]
            det.slick_urls = slick_urls
            _apply_url_rules(rules, extra, det)

    # Stage 2: if no version yet and fetcher provided, fetch JS bodies for banner
    if fetcher is not None and not det.version:
        for u in slick_urls:
            if not re.search(r"slick(?:\.min)?\.js(?:\?|$)", u, re.I):
                continue
            host = urlparse(u).netloc
            if throttle:
                throttle.acquire(host)
            try:
                res = fetcher.fetch(u, timeout=10.0, verify_ssl=False, extra_headers={})
            except Exception:
                continue
            if not res.is_ok or not res.body:
                continue
            _apply_body_rules(rules, res.body, u, det)
            if det.version:
                break

    return det


def make_default_fetcher_throttle(*, strategy: str = "curl_cffi", min_host_gap: float = 0.3):
    return fetchlib.make_fetcher(strategy), fetchlib.HostThrottle(min_delay_s=min_host_gap)
