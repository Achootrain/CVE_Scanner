"""Wall-clock safe regex search with hang diagnostics.

Defeats catastrophic backtracking in upstream rule corpora (nuclei
templates, Wappalyzer rules, retire.js patterns). Python's ``re``
module cannot be interrupted from another thread, so each search runs
in a daemon thread and the caller abandons it on timeout. The pattern
is then blacklisted so subsequent calls return ``None`` instantly.

Daemon threads leak (the C-level regex keeps running until natural
exit). The blacklist guarantees at most one leaked thread per
pathological pattern *per process*. Across many targets in series
threads can still accumulate -- ``stats_snapshot()`` exposes the
counters so a caller can decide to recycle the worker process.

Why this module instead of inlining in scanner.py:
    nuclei matchers, retire.js scan_body, and wappalyzer _match_pattern
    each call ``re.search``. All three have hung on real targets. Sharing
    one wrapper across them keeps the blacklist global and gives a single
    place to instrument hang signals.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import threading
import time

LOG = logging.getLogger("fp.safe_regex")

DEFAULT_TIMEOUT = 2.0
SLOW_PATTERN_THRESHOLD = 0.5

# Sibling file holding hand-curated pattern strings that should never run.
# See ``regex_blocklist.txt`` header for the format. Loaded once at module
# import; the file is small and the read cost is negligible. Errors are
# swallowed -- a missing or malformed blocklist must not break scanning.
_BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), "regex_blocklist.txt")
# Append-only log of patterns that Layer 2 auto-promoted to the in-memory
# blacklist. Each line: ``<iso-utc>\t<text_len>\t<elapsed_s>\t<pattern>``.
# Cross-session: the user runs the pipeline, this file accumulates;
# next session they ``sort -u`` it and copy candidates into
# ``regex_blocklist.txt`` for permanent eviction. Lossless format
# (TSV-ish) so awk/cut/sort work.
_AUTO_LOG_FILE = os.path.join(os.path.dirname(__file__), "regex_blocklist.auto.log")
# Module-level guard: each pattern is logged once per process even if
# multiple threads hit it concurrently before the blacklist short-circuits.
_AUTO_LOG_LOCK = threading.Lock()
_AUTO_LOG_WRITTEN: set[str] = set()


def _load_persistent_blocklist() -> set[str]:
    out: set[str] = set()
    try:
        with open(_BLOCKLIST_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                out.add(line)
    except OSError:
        pass
    return out


_BLACKLIST: set[str] = _load_persistent_blocklist()
_PERSISTENT_BLOCKLIST_SIZE = len(_BLACKLIST)


def _append_auto_log(pattern: str, elapsed: float, text_len: int) -> None:
    """Append one auto-promoted pattern to the audit log.

    Best-effort: any IOError silently dropped. Each pattern is written
    at most once per process so the log size grows by at most one line
    per genuinely-new bad pattern.
    """
    with _AUTO_LOG_LOCK:
        if pattern in _AUTO_LOG_WRITTEN:
            return
        _AUTO_LOG_WRITTEN.add(pattern)
    try:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Strip newlines from pattern so the TSV stays parseable.
        clean_pattern = pattern.replace("\n", " ").replace("\r", " ")
        line = f"{ts}\t{text_len}\t{elapsed:.2f}\t{clean_pattern}\n"
        with open(_AUTO_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
_stats_lock = threading.Lock()
_stats: dict[str, int] = {
    "calls": 0,
    "blacklist_hits": 0,
    "timeouts": 0,
    "slow_calls": 0,
    "errors": 0,
    "leaked_threads": 0,
}
_slow_log: list[tuple[float, str, int]] = []  # (elapsed, pattern[:120], text_len)
_SLOW_LOG_CAP = 50


def _key(pattern) -> str:
    if isinstance(pattern, str):
        return pattern
    return getattr(pattern, "pattern", repr(pattern))


def safe_search(pattern, text: str, flags: int = 0,
                timeout: float = DEFAULT_TIMEOUT):
    """re.search with a hard wall-clock timeout. Returns None on timeout/error.

    ``pattern`` may be a string or a pre-compiled ``re.Pattern``. When
    compiled, ``flags`` is ignored.
    """
    key = _key(pattern)
    with _stats_lock:
        _stats["calls"] += 1
        if key in _BLACKLIST:
            _stats["blacklist_hits"] += 1
            return None

    result: list = [None]
    err: list = [None]

    def _runner() -> None:
        try:
            if isinstance(pattern, str):
                result[0] = re.search(pattern, text, flags)
            else:
                result[0] = pattern.search(text)
        except re.error as exc:
            err[0] = exc

    t0 = time.monotonic()
    t = threading.Thread(target=_runner, daemon=True, name="regex-eval")
    t.start()
    t.join(timeout)
    elapsed = time.monotonic() - t0

    if t.is_alive():
        with _stats_lock:
            _stats["timeouts"] += 1
            _stats["leaked_threads"] += 1
            _BLACKLIST.add(key)
        LOG.warning(
            "regex timeout (>%.1fs); blacklisting: %r ; text_len=%d",
            timeout, key[:120], len(text),
        )
        return None

    if elapsed >= SLOW_PATTERN_THRESHOLD:
        # Auto-promote to blacklist on the FIRST slow call. Necessary
        # because Thread.join(timeout) is leaky on GIL-holding regex --
        # a pathological pattern can take 100+s without the watchdog
        # ever firing (CPython holds the GIL through C-level
        # backtracking, so the timeout only fires after the regex
        # completes naturally). Once a pattern crosses 0.5s without
        # matching the body it is statistically not worth retrying;
        # the next target with a similar body would burn the same time.
        was_new = False
        with _stats_lock:
            _stats["slow_calls"] += 1
            _slow_log.append((elapsed, key[:120], len(text)))
            if len(_slow_log) > _SLOW_LOG_CAP:
                _slow_log.pop(0)
            if key not in _BLACKLIST:
                _BLACKLIST.add(key)
                was_new = True
        LOG.warning(
            "slow regex (%.2fs, did not time out); auto-blacklisting: %r ; "
            "text_len=%d", elapsed, key[:120], len(text),
        )
        if was_new:
            # Persist to the audit log so the user can re-curate the
            # static blocklist file without grepping stderr later.
            _append_auto_log(key, elapsed, len(text))

    if err[0] is not None:
        with _stats_lock:
            _stats["errors"] += 1
        return None
    return result[0]


def stats_snapshot() -> dict:
    """Read-only copy of the diagnostic counters plus live thread count."""
    with _stats_lock:
        snap = dict(_stats)
    snap["blacklist_size"] = len(_BLACKLIST)
    snap["persistent_blocklist_size"] = _PERSISTENT_BLOCKLIST_SIZE
    snap["leaked_threads_alive"] = sum(
        1 for t in threading.enumerate() if t.name == "regex-eval"
    )
    return snap


def reset_call_stats() -> None:
    """Clear per-call counters between targets. Blacklist + cumulative
    leak counter are intentionally preserved across targets."""
    with _stats_lock:
        leaked = _stats["leaked_threads"]
        _stats.update({
            "calls": 0, "blacklist_hits": 0, "timeouts": 0,
            "slow_calls": 0, "errors": 0,
        })
        _stats["leaked_threads"] = leaked
        _slow_log.clear()


def slow_top(n: int = 10) -> list[tuple[float, str, int]]:
    """Up to N slowest non-timeout calls observed since last reset."""
    with _stats_lock:
        return sorted(_slow_log, key=lambda x: -x[0])[:n]


def blacklist_size() -> int:
    return len(_BLACKLIST)
