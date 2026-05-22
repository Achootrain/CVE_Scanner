"""Per-host minimum-gap scheduler with random jitter.

Without a browser, the cheapest practical bot-detection defense is to
look like a slow, polite client - one request to a given host at a time,
with a jittered inter-request gap. Requests to different hosts run fully
in parallel - the gating is per-host only.
"""

from __future__ import annotations

import random
import threading
import time


class HostThrottle:
    def __init__(self, min_delay_s: float = 0.25, jitter_s: float = 0.15):
        self.min_delay = max(0.0, float(min_delay_s))
        self.jitter = max(0.0, float(jitter_s))
        self._lock = threading.Lock()
        self._next_at: dict[str, float] = {}

    def acquire(self, host: str) -> None:
        """Block until the caller is cleared to send a request to `host`."""
        if not host:
            return
        with self._lock:
            now = time.monotonic()
            scheduled = max(self._next_at.get(host, 0.0), now)
            wait = scheduled - now
            slot_jitter = random.uniform(0, self.jitter)
            # Reserve this host's next slot so concurrent waiters serialize.
            self._next_at[host] = scheduled + self.min_delay + slot_jitter
        if wait > 0:
            time.sleep(wait + slot_jitter)
        elif slot_jitter > 0:
            time.sleep(slot_jitter)
