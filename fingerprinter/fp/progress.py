"""Live progress reporter for ``fp pipeline``.

Streams short status lines to stderr while a pipeline run is in flight
so the user sees what's happening without having to wait for the final
text/JSON dump. Output is wall-clock-timestamped and stage-tagged so
tee'ing to a log file gives you something readable.

Stage events emitted (per target):

    [14:32:05] target: https://example.com (est max ~120s)
    [14:32:05] scan: started (concurrent)
    [14:32:05] katana: started (concurrent)
    [14:32:05] version-probes: started (concurrent)
    [14:32:16] scan: done (17 detections)
    [14:32:35] katana: done (501 records, pages=492 js=7) [BUDGET HIT]
    [14:32:35] version-probes: done (0 hits)
    [14:32:35] cross-page rescan: started (30 URLs from katana)
    [14:32:49] cross-page rescan: done (30/30 fetched, wap=136 retire=3)
    [14:32:49] reconcile: 8 techs, 2 versioned

A periodic heartbeat (every ``HEARTBEAT_SECS``) prints the still-running
stage names so the user knows the run hasn't hung when one stage takes
much longer than its peers (typical: katana on Cloudflare-throttled
hosts where the homepage fetches in 200ms but the body-sweep waits 30s
on each rate-limited follow-up).

This module is stderr-only on purpose: the CLI's ``--json`` output goes
to stdout, so progress lines never pollute machine-parsed output.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime

# Default heartbeat interval. 10s is short enough to feel responsive on
# normal targets and long enough that katana stuck on a single slow body
# fetch doesn't spam the log.
HEARTBEAT_SECS = 10

# Rough est-max budget shown at header. Sum of typical worst-cases:
# scanner ~30s, katana ~60s, version-probes ~15s (concurrent so max
# wins), then cross-page ~30s sequential. 120s is a sane upper-bound
# for a single target. Well-behaved targets finish much faster; this is
# the "should I wait or kill it" budget.
DEFAULT_EST_MAX_SECS = 120


class ProgressLogger:
    """Stderr-only timestamped event stream.

    ``enabled=False`` makes every method a no-op so callers can wire it
    in unconditionally and let a single flag (``--quiet``) control the
    output. The reference time is captured at construction so all events
    share the same zero point -- relative timestamps survive a long
    multi-target run without resetting per target.
    """

    def __init__(self, stream=None, enabled: bool = True):
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = enabled
        self.t0 = time.monotonic()

    def elapsed(self) -> float:
        return time.monotonic() - self.t0

    def event(self, msg: str) -> None:
        if not self.enabled:
            return
        # Right-justify the elapsed-time prefix so stage names line up
        # at the same column whether the run is on second 9 or second 99.
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=self.stream, flush=True)

    def header(self, target: str, est_max: int = DEFAULT_EST_MAX_SECS) -> None:
        self.event(f"target: {target} (est max ~{est_max}s)")

    def start(self, stage: str, detail: str = "") -> None:
        d = f" ({detail})" if detail else ""
        self.event(f"{stage}: started{d}")

    def done(self, stage: str, detail: str = "") -> None:
        d = f" ({detail})" if detail else ""
        self.event(f"{stage}: done{d}")

    def skip(self, stage: str, reason: str) -> None:
        self.event(f"{stage}: skipped ({reason})")

    def error(self, stage: str, exc: BaseException) -> None:
        self.event(f"{stage}: ERROR ({exc!r})")

    def detect(self, target: str, tech: str, version: str | None, url: str | None) -> None:
        """Emit one machine-parseable line per detected tech.

        Format::

            [HH:MM:SS] [detect] target=<t> | tech=<name> | version=<v> | url=<u>

        Pipe-delimited with explicit ``key=value`` fields. Dashboards parse
        this with a single regex to render a per-detection table without
        having to wait for the pipeline's final JSON dump.
        """
        v = version or "-"
        u = url or "-"
        self.event(f"[detect] target={target} | tech={tech} | version={v} | url={u}")


async def heartbeat(
    prog: ProgressLogger,
    tasks: dict[str, asyncio.Task],
    *,
    interval: float = HEARTBEAT_SECS,
) -> None:
    """Periodically log which named tasks are still running.

    Usage::

        hb = asyncio.create_task(progress.heartbeat(prog, {...}))
        try:
            ... await all the named tasks ...
        finally:
            hb.cancel()

    The body intentionally swallows ``CancelledError`` so the caller's
    ``cancel()`` is a clean no-op shutdown rather than an exception
    propagating out of the cancellation site.
    """
    if not prog.enabled or not tasks:
        return
    try:
        while True:
            await asyncio.sleep(interval)
            still = sorted(name for name, t in tasks.items() if not t.done())
            if not still:
                return
            prog.event(f"still running: {', '.join(still)}")
    except asyncio.CancelledError:
        return
