"""Hand-curated version-disclosure probe catalog.

Covers the long tail of self-hosted apps + BaaS components whose version
sits behind a specific path that nuclei/Wappalyzer don't probe by default.
Each entry is a small, target-agnostic record:

    Probe(name, path, method, regex, version_group, ok_status, content_hint)

The scanner runs every probe against the target host once. Probes that 404
silently drop (cheap; we expect most to miss). Probes that hit emit a
``Detection(source="version-probe", template_id="vp:<name>", version=...)``.

Curated for techs whose version disclosure was identified during lab Phase 3
mining or in the api_collection_strategy memory:

  - WordPress, Drupal, Joomla, phpMyAdmin (CMS classics)
  - Grafana, Jenkins, GitLab, Mattermost, Sentry self-hosted (self-hosted apps)
  - Spring Boot Actuator (the canonical Java backend disclosure surface)
  - Supabase Storage + GoTrue (BaaS components, anon-allowed surfaces)
  - Generic /api/info, /api/version, /version.json (custom-app surface)

Adding new probes is a one-line table edit -- keep the catalog flat.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import aiohttp

LOG = logging.getLogger("fp.version_probes")

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=8)
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)
MAX_BODY_BYTES = 256 * 1024


@dataclass
class Probe:
    name: str           # canonical tech name -- becomes vp:<name> template id
    path: str           # path to probe (will be appended to target origin)
    regex: str          # regex run against (status, headers, body) per ``part``
    method: str = "GET"
    version_group: int = 1
    ok_status: tuple[int, ...] = (200,)
    part: str = "body"  # "body" | "header" | "status" -- what the regex matches
    content_hint: str | None = None  # optional: substring required in body to fire
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeHit:
    probe: Probe
    version: str
    status: int
    url: str

    def to_dict(self) -> dict:
        return {
            "name": self.probe.name,
            "version": self.version,
            "path": self.probe.path,
            "url": self.url,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Catalog (loaded from lab.db at module init)
# ---------------------------------------------------------------------------
#
# The literal list of Probe entries used to live here. Per CLAUDE.md section 5,
# lab.db is the single source of truth. Adding a new probe is now
# `INSERT INTO lab_version_probes ...` + `version_probes.reload()`.
#
# See lab/url_ver_lab/README.md for the seeder + parity test.
# ---------------------------------------------------------------------------

import json as _json
import os as _os
import sqlite3 as _sqlite3
from pathlib import Path as _Path

_LAB_DB_ENV = "FP_LAB_DB"
_DEFAULT_LAB_DB = _Path(__file__).resolve().parent.parent / "lab.db"


def _lab_db_path() -> _Path:
    env = _os.environ.get(_LAB_DB_ENV)
    return _Path(env) if env else _DEFAULT_LAB_DB


def _load_from_lab_db(db_path: _Path) -> list[Probe]:
    conn = _sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT name, path, regex, method, version_group, ok_status,
                      part, content_hint, headers_json
               FROM lab_version_probes ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()
    out: list[Probe] = []
    for (name, path, regex, method, version_group, ok_status,
         part, content_hint, headers_json) in rows:
        ok_tuple = tuple(int(s) for s in ok_status.split(",") if s.strip())
        headers = _json.loads(headers_json) if headers_json else {}
        out.append(Probe(
            name=name, path=path, regex=regex, method=method,
            version_group=version_group, ok_status=ok_tuple, part=part,
            content_hint=content_hint, headers=headers,
        ))
    return out


def reload(db_path: _Path | str | None = None) -> None:
    """Re-read catalog from lab.db without restarting the scanner."""
    global CATALOG
    path = _Path(db_path) if db_path else _lab_db_path()
    CATALOG = _load_from_lab_db(path)


CATALOG: list[Probe] = []
reload()


# ---------------------------------------------------------------------------
# Match
# ---------------------------------------------------------------------------


def _match(probe: Probe, status: int, headers_lc: dict, body: str) -> str | None:
    """Run the probe's regex over the chosen part. Return captured version
    or None if no match / content_hint missing."""
    if status not in probe.ok_status:
        return None
    if probe.content_hint and probe.content_hint not in body:
        return None
    if probe.part == "body":
        target = body
    elif probe.part == "header":
        target = "\r\n".join(f"{k}: {v}" for k, v in headers_lc.items())
    else:
        target = str(status)
    try:
        m = re.search(probe.regex, target, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        LOG.debug("bad regex in probe %s: %s", probe.name, exc)
        return None
    if not m:
        return None
    try:
        return m.group(probe.version_group).strip()
    except IndexError:
        return None


# ---------------------------------------------------------------------------
# Probe one host
# ---------------------------------------------------------------------------


def _origin(target_url: str) -> str:
    """Reduce a target URL to its origin (scheme://host[:port])."""
    p = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
    if not p.netloc:
        return f"https://{target_url}"
    return urlunsplit((p.scheme or "https", p.netloc, "", "", ""))


async def _send(
    session: aiohttp.ClientSession, origin: str, probe: Probe,
) -> ProbeHit | None:
    url = origin.rstrip("/") + probe.path
    try:
        async with session.request(
            probe.method, url, headers=probe.headers,
            allow_redirects=True, ssl=False,
        ) as r:
            raw = await r.content.read(MAX_BODY_BYTES)
            headers_lc = {k.lower(): v for k, v in r.headers.items()}
            body = raw.decode("utf-8", errors="replace")
            version = _match(probe, r.status, headers_lc, body)
            if version is None:
                return None
            return ProbeHit(probe=probe, version=version, status=r.status, url=url)
    except Exception as exc:  # noqa: BLE001
        LOG.debug("probe %s failed: %s", probe.name, exc)
        return None


async def run_catalog(
    target_url: str,
    *,
    catalog: list[Probe] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: aiohttp.ClientTimeout = DEFAULT_TIMEOUT,
    concurrency: int = 5,
) -> list[ProbeHit]:
    """Fire every catalog probe against ``target_url`` and return the hits.

    Probes run concurrently with bounded concurrency. 404/timeout/connection
    errors are silently dropped -- the long tail is expected to miss.
    """
    probes = catalog if catalog is not None else CATALOG
    origin = _origin(target_url)
    sem = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as sess:
        async def _bounded(p: Probe) -> ProbeHit | None:
            async with sem:
                return await _send(sess, origin, p)

        results = await asyncio.gather(*[_bounded(p) for p in probes])

    return [r for r in results if r is not None]
