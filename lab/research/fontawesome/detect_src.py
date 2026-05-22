"""Source-grounded FA detector.

Loads rules_src.json (authored from FA release tarballs) and applies them to
a given HTML body + optionally to linked CSS/JS bodies.

Output combines the strongest evidence:
- exact `version` if any rule extracts one (banner / version-in-URL)
- `generation` (major) if structural rules (filename, font, class) place it
- `edition` ("free" | "pro" | "legacy_kit") when banner or host indicates
- `kit_only` flag if all FA references are unrecoverable kit URLs

No URL is fetched here unless callers pass a fetcher; the detector operates on
already-acquired HTML/CSS bodies whenever possible.
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


# HTML extractors (lenient, regex-based; FA URLs land in <link> / <script> / @import)
RE_LINK_HREF = re.compile(r'<link[^>]*\bhref=["\'](.*?)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]*\bsrc=["\'](.*?)["\']', re.I)
RE_CSS_URL = re.compile(r'url\(["\']?(.*?)["\']?\)', re.I)
RE_CLASS_ATTR = re.compile(r'class=["\']([^"\']*)["\']', re.I)


def _normalize(url: str, origin: str) -> str:
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        u = urlparse(origin)
        return f"{u.scheme}://{u.netloc}{url}"
    if not url.startswith(("http://", "https://")):
        return f"{origin.rstrip('/')}/{url}"
    return url


def _looks_fa(url: str) -> bool:
    return bool(re.search(r"font-?awesome|fontawesome|fortawesome", url, re.I))


@dataclass
class Detection:
    version: str | None = None
    generation: int | None = None
    generation_at_least: int | None = None
    edition: str | None = None
    sources: list[dict] = field(default_factory=list)
    fa_urls: list[str] = field(default_factory=list)
    kit_only: bool = False

    def absorb(self, rule_id: str, extracted: dict, evidence_url: str | None = None, evidence_kind: str = "") -> None:
        for k, v in extracted.items():
            if v is None:
                continue
            if k == "version" and not self.version:
                self.version = v
            elif k == "generation" and not self.generation:
                self.generation = v
                if self.generation_at_least is None or v > self.generation_at_least:
                    self.generation_at_least = v
            elif k == "generation_at_least":
                if self.generation_at_least is None or v > self.generation_at_least:
                    self.generation_at_least = v
            elif k == "edition" and not self.edition:
                self.edition = v
        self.sources.append({"rule": rule_id, "kind": evidence_kind, "url": evidence_url})

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "generation": self.generation,
            "generation_at_least": self.generation_at_least,
            "edition": self.edition,
            "kit_only": self.kit_only,
            "sources": self.sources,
            "fa_urls": self.fa_urls,
        }


def load_rules(path: Path = RULES_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_rules_from_db(db_path: Path, tech_slug: str = "font-awesome") -> dict:
    """Read rules from lab.db's lab_src_rules table.

    Returns the same shape as load_rules() so the rest of the detector is
    indifferent to whether rules came from JSON or the DB.
    """
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    from import_rules import load_rules_from_db as _impl
    return _impl(db_path, tech_slug)


def _resolve_extracts(extracts: dict, m: re.Match | None, url: str | None) -> dict:
    """Resolve {'g':N}/{'l':V}/{'from_host':{...}} into concrete values."""
    out: dict = {}
    for key, spec in extracts.items():
        if not isinstance(spec, dict):
            out[key] = spec  # tolerate bare literals for safety
            continue
        if "g" in spec and m is not None:
            try:
                out[key] = m.group(spec["g"])
            except IndexError:
                pass
        elif "l" in spec:
            out[key] = spec["l"]
        elif "from_host" in spec and url:
            host = urlparse(url).netloc
            if host in spec["from_host"]:
                out[key] = spec["from_host"][host]
    return out


def _apply_url_rules(rules: dict, urls: list[str], det: Detection) -> None:
    """Apply url_filename / webfont / url_version / kit rules to URLs."""
    for section in ("url_version_in_path_rules", "url_filename_rules", "webfont_rules", "kit_rules"):
        for rule in rules.get(section, []):
            pat = re.compile(rule["pattern"], re.I)
            for u in urls:
                m = pat.search(u)
                if not m:
                    continue
                extracted = _resolve_extracts(rule["extracts"], m, u)
                if "generation_from_version" in rule and extracted.get("version"):
                    major_str = str(extracted["version"]).split(".")[0]
                    mapping = rule["generation_from_version"]
                    if major_str in mapping:
                        extracted["generation"] = mapping[major_str]
                det.absorb(rule["id"], extracted, evidence_url=u, evidence_kind=section)


def _apply_body_rules(rules: dict, body: str, source_url: str | None, det: Detection) -> None:
    """Apply banner rules to a CSS/JS body."""
    snippet = body[: 8192]  # FA banner is always at the top
    for rule in rules.get("banner_rules", []):
        pat = re.compile(rule["pattern"], re.I)
        m = pat.search(snippet)
        if not m:
            continue
        extracted = _resolve_extracts(rule["extracts"], m, source_url)
        if "generation_from_version" in rule and extracted.get("version"):
            major_str = str(extracted["version"]).split(".")[0]
            mapping = rule["generation_from_version"]
            if major_str in mapping:
                extracted["generation"] = mapping[major_str]
        det.absorb(rule["id"], extracted, evidence_url=source_url, evidence_kind="banner")


def _apply_class_rules(rules: dict, html: str, det: Detection) -> None:
    """Apply css_class rules to HTML body."""
    classes_concat = " ".join(RE_CLASS_ATTR.findall(html)[:200])
    for rule in rules.get("css_class_rules", []):
        pat = re.compile(rule["pattern"], re.I)
        m = pat.search(classes_concat)
        if not m:
            continue
        extracted = _resolve_extracts(rule["extracts"], m, None)
        det.absorb(rule["id"], extracted, evidence_kind="class")


def _extract_urls(html: str, origin: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for rx in (RE_LINK_HREF, RE_SCRIPT_SRC, RE_CSS_URL):
        for raw in rx.findall(html):
            if not _looks_fa(raw):
                continue
            full = _normalize(raw.strip(), origin)
            if full not in seen:
                seen.add(full)
                out.append(full)
    return out


KIT_URL = re.compile(r"(?:use|kit)\.fontawesome\.com/[0-9a-f]{8,}\.js", re.I)


def detect(target: str, html: str, *, fetcher=None, throttle=None) -> Detection:
    """Run source-grounded detection on a target's root HTML."""
    rules = load_rules()
    origin = target if target.startswith(("http://", "https://")) else f"https://{target}"
    det = Detection()
    urls = _extract_urls(html, origin)
    det.fa_urls = urls

    # Stage 1: URL rules (cheap, no HTTP)
    _apply_url_rules(rules, urls, det)

    # Stage 2: CSS class rules in HTML body
    _apply_class_rules(rules, html, det)

    # Stage 3: optional body fetch for banner-bearing CSS/JS files
    if fetcher is not None and not det.version:
        for u in urls:
            if KIT_URL.search(u):
                continue
            if not re.search(r"\.(css|js)(?:\?|$)", u, re.I):
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

    # Compute kit_only: every FA URL we saw is a legacy kit
    if urls and all(KIT_URL.search(u) for u in urls):
        det.kit_only = True

    return det


def make_default_fetcher_throttle(*, strategy: str = "curl_cffi", min_host_gap: float = 0.3):
    return fetchlib.make_fetcher(strategy), fetchlib.HostThrottle(min_delay_s=min_host_gap)
