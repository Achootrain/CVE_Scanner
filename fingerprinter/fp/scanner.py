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
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp

try:  # mmh3 is optional — favicon DSL matching is a nice-to-have.
    import mmh3  # type: ignore

    _HAVE_MMH3 = True
except ImportError:  # pragma: no cover
    _HAVE_MMH3 = False

LOG = logging.getLogger("fp.scanner")

DEFAULT_UA = "Mozilla/5.0 (compatible; NucleiFpScanner/0.1)"
DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 20


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

    def to_dict(self) -> dict[str, Any]:
        return {
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
            "path": self.path,
            "extracted": self.extracted,
        }


@dataclass
class FetchedResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    error: str | None = None

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
    return resp.body_text  # safest default


def _word_match(matcher: dict, resp: FetchedResponse) -> bool:
    text = _part_text(resp, matcher["part"]).lower()
    values: list[str] = matcher["values"]
    if not values:
        return False
    hits = (v in text for v in values)
    ok = all(hits) if matcher["condition"] == "and" else any(hits)
    return not ok if matcher["negative"] else ok


def _regex_match(matcher: dict, resp: FetchedResponse) -> bool:
    text = _part_text(resp, matcher["part"])
    values: list[str] = matcher["values"]
    if not values:
        return False
    try:
        hits = [bool(re.search(v, text, re.MULTILINE | re.DOTALL)) for v in values]
    except re.error as exc:
        LOG.debug("bad regex in matcher %s: %s", matcher.get("name"), exc)
        return False
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
                try:
                    for m in re.finditer(pat, part_text, re.MULTILINE | re.DOTALL):
                        try:
                            matches.append(m.group(group))
                        except IndexError:
                            matches.append(m.group(0))
                except re.error:
                    continue
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
            detections.append(_make_detection(template, m["name"], url, path, extracted))
    return detections


def _make_detection(
    template: dict, matcher_name: str | None, url: str, path: str, extracted: dict
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
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_UA,
        verify_ssl: bool = False,
    ) -> None:
        self.cache = cache
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers = {"User-Agent": user_agent, "Accept": "*/*"}
        self.ssl_ctx: ssl.SSLContext | bool
        if verify_ssl:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = False  # disable cert verification for broad coverage

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str
    ) -> FetchedResponse:
        async with self.sem:
            try:
                async with session.get(url, allow_redirects=True, ssl=self.ssl_ctx) as r:
                    body = await r.read()
                    return FetchedResponse(
                        url=str(r.url),
                        status=r.status,
                        headers={k: v for k, v in r.headers.items()},
                        body=body,
                    )
            except Exception as exc:  # noqa: BLE001
                return FetchedResponse(url=url, status=0, headers={}, body=b"", error=str(exc))

    async def scan(self, target: str) -> list[Detection]:
        base = _normalise_target(target)
        detections: list[Detection] = []

        async with aiohttp.ClientSession(
            headers=self.headers, timeout=self.timeout
        ) as session:
            paths = list(self.cache["by_path"].keys())
            tasks = [self._fetch(session, urljoin(base + "/", p.lstrip("/"))) for p in paths]
            responses = await asyncio.gather(*tasks)

        requests_table = self.cache["requests"]
        templates = self.cache["templates"]

        for path, resp in zip(paths, responses):
            if resp.error or resp.status == 0:
                continue
            for req_pk in self.cache["by_path"][path]:
                # JSON-loaded caches have string keys; in-memory ones have int.
                req = requests_table.get(req_pk) or requests_table.get(str(req_pk))
                if not req:
                    continue
                template = templates.get(req["template_pk"]) or templates.get(str(req["template_pk"]))
                if not template:
                    continue
                req_detections = _evaluate_request(req, template, resp.url, path, resp)
                if req_detections:
                    detections.extend(req_detections)
                    if req["stop_at_first_match"]:
                        # Nuclei's stop-at-first-match is per request block.
                        break
        return detections


async def scan_targets(cache: dict, targets: list[str], **kwargs: Any) -> dict[str, list[dict]]:
    scanner = Scanner(cache, **kwargs)
    out: dict[str, list[dict]] = {}
    for target in targets:
        dets = await scanner.scan(target)
        out[target] = [d.to_dict() for d in dets]
    return out
