"""Subdomain enumeration from Certificate Transparency logs via crt.sh.

One HTTP call per apex domain, no API key, no installation. crt.sh returns a
JSON array of certificate rows whose ``name_value`` field contains one or more
newline-separated SANs. We dedupe, filter wildcards, and keep only names under
the queried apex.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable

import aiohttp

LOG = logging.getLogger("fp.subdomains")

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def crt_sh(domain: str, *, timeout: int = 60) -> list[str]:
    """Query crt.sh for hostnames seen in certificates for ``domain``."""
    apex = domain.strip().lower().lstrip(".")
    url = CRTSH_URL.format(domain=apex)
    async with aiohttp.ClientSession() as s:
        async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            r.raise_for_status()
            body = await r.read()

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        # crt.sh occasionally returns newline-delimited JSON under high load.
        rows = []
        for line in body.decode("utf-8", errors="replace").splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return _extract_names(rows, apex)


def _extract_names(rows: Iterable[dict], apex: str) -> list[str]:
    seen: set[str] = set()
    for row in rows:
        raw = row.get("name_value") or ""
        for candidate in raw.split("\n"):
            name = candidate.strip().lower().rstrip(".")
            if not name or name.startswith("*"):
                continue
            if name == apex or name.endswith("." + apex):
                seen.add(name)
    return sorted(seen)


async def enumerate_all(domains: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for d in domains:
        try:
            out[d] = await crt_sh(d)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("crt.sh %s failed: %s", d, exc)
            out[d] = []
    return out
