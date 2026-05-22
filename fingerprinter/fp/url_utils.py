"""URL utility functions shared across the scanner.

Extracted from ``browser_capture.py`` when that module was removed.
These are pure functions with no browser/Camoufox dependency.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .backend_leaks import _registrable


# ---------------------------------------------------------------------------
# Same-host filter
# ---------------------------------------------------------------------------


def is_same_registrable(url: str, target_host: str) -> bool:
    """True iff ``url``'s hostname shares an eTLD+1 with ``target_host``.

    Uses the naive last-two-labels heuristic from ``backend_leaks._registrable`` —
    treats ``co.uk`` as a registrable, which is wrong for multi-label TLDs
    but only affects which traffic gets recorded, not detection accuracy.
    """
    host = urlsplit(url).hostname or ""
    if not host:
        return False
    return _registrable(host) == _registrable(target_host)


# ---------------------------------------------------------------------------
# Path-template collapsing (URL dedup for crawl saturation tracking)
# ---------------------------------------------------------------------------


_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{12,}$", re.I)


def path_template(url: str) -> str:
    """Collapse identifier-bearing segments to placeholders so different
    instances of the same route hit the same saturation key."""
    path = urlsplit(url).path or "/"
    parts = path.split("/")
    out = []
    for part in parts:
        if not part:
            out.append(part)
        elif _UUID_SEGMENT.match(part):
            out.append("{uuid}")
        elif _NUMERIC_SEGMENT.match(part):
            out.append("{n}")
        elif _HEX_SEGMENT.match(part):
            out.append("{hex}")
        else:
            out.append(part)
    return "/".join(out)
