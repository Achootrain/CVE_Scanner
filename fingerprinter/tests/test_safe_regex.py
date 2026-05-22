"""Tests for fp.safe_regex -- the shared timeout-bounded regex wrapper."""

import re
import time

from fp import safe_regex as sre


def setup_function(_):
    sre._BLACKLIST.clear()
    sre.reset_call_stats()


def test_persistent_blocklist_loads_at_import():
    # The shipping regex_blocklist.txt has at least the OJS pattern in it.
    # _PERSISTENT_BLOCKLIST_SIZE captures the count at import time.
    assert sre._PERSISTENT_BLOCKLIST_SIZE >= 1


def test_load_persistent_blocklist_parses_comments_and_blanks(tmp_path, monkeypatch):
    f = tmp_path / "bl.txt"
    f.write_text(
        "# header comment\n"
        "\n"
        "pattern_one\n"
        "  # not a comment, leading whitespace -- kept verbatim\n"
        "pattern_two\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sre, "_BLOCKLIST_FILE", str(f))
    out = sre._load_persistent_blocklist()
    assert "pattern_one" in out
    assert "pattern_two" in out
    assert "# header comment" not in out


def test_load_persistent_blocklist_missing_file_returns_empty(monkeypatch):
    monkeypatch.setattr(sre, "_BLOCKLIST_FILE", "/no/such/file/here.txt")
    assert sre._load_persistent_blocklist() == set()


def test_slow_call_promotes_to_blacklist(monkeypatch):
    # Fake the elapsed time by stubbing time.monotonic so the call
    # appears to have crossed the SLOW_PATTERN_THRESHOLD without
    # actually waiting. Cheaper than crafting a real catastrophic
    # backtrack pattern in CI.
    times = iter([100.0, 100.0 + sre.SLOW_PATTERN_THRESHOLD + 0.1])
    monkeypatch.setattr(sre.time, "monotonic", lambda: next(times))
    sre.safe_search(r"slowish", "slowish text matched here")
    assert "slowish" in sre._BLACKLIST
    snap = sre.stats_snapshot()
    assert snap["slow_calls"] == 1


def test_normal_fast_call_does_not_promote_to_blacklist():
    sre.safe_search(r"\d+", "abc 123 def")
    snap = sre.stats_snapshot()
    assert snap["slow_calls"] == 0
    # Persistent blocklist entries are still present (we only cleared in setup)
    # but '\d+' should not be among them.
    assert r"\d+" not in sre._BLACKLIST


def test_auto_promote_appends_to_auto_log_file(tmp_path, monkeypatch):
    log_file = tmp_path / "regex_blocklist.auto.log"
    monkeypatch.setattr(sre, "_AUTO_LOG_FILE", str(log_file))
    sre._AUTO_LOG_WRITTEN.clear()
    times = iter([100.0, 100.0 + sre.SLOW_PATTERN_THRESHOLD + 0.1])
    monkeypatch.setattr(sre.time, "monotonic", lambda: next(times))
    sre.safe_search(r"slowpat", "slowpat in body here")
    assert log_file.exists()
    contents = log_file.read_text(encoding="utf-8")
    # iso-utc<TAB>text_len<TAB>elapsed<TAB>pattern
    assert "\tslowpat\n" in contents
    assert "Z\t" in contents  # iso-utc has Z suffix


def test_auto_log_writes_each_pattern_once_per_process(tmp_path, monkeypatch):
    log_file = tmp_path / "regex_blocklist.auto.log"
    monkeypatch.setattr(sre, "_AUTO_LOG_FILE", str(log_file))
    sre._AUTO_LOG_WRITTEN.clear()
    # Two slow calls of the SAME pattern. After the first call the
    # pattern is in _BLACKLIST so the second call short-circuits and
    # never reaches the slow-call branch -- but even if it did, the
    # _AUTO_LOG_WRITTEN guard should prevent a duplicate log line.
    sre._append_auto_log("dup_pattern", 1.0, 100)
    sre._append_auto_log("dup_pattern", 1.0, 100)
    contents = log_file.read_text(encoding="utf-8")
    assert contents.count("dup_pattern") == 1


def test_auto_log_handles_unwritable_file_gracefully(monkeypatch):
    # Point the log at a path that cannot be opened. The slow call must
    # still complete cleanly -- the audit log is best-effort.
    monkeypatch.setattr(sre, "_AUTO_LOG_FILE", "/nonexistent_dir_xyz/x.log")
    sre._AUTO_LOG_WRITTEN.clear()
    sre._append_auto_log("any_pattern", 1.0, 100)  # should not raise


def test_basic_match_returns_match_object():
    m = sre.safe_search(r"hello (\w+)", "hello world")
    assert m is not None
    assert m.group(1) == "world"


def test_no_match_returns_none():
    assert sre.safe_search(r"^xyz$", "abcdef") is None


def test_compiled_pattern_supported():
    pat = re.compile(r"v(\d+\.\d+)")
    m = sre.safe_search(pat, "version v1.23 here")
    assert m is not None
    assert m.group(1) == "1.23"


def test_invalid_pattern_returns_none_and_increments_errors():
    assert sre.safe_search(r"(unclosed", "text") is None
    assert sre.stats_snapshot()["errors"] == 1


def test_blacklist_short_circuits_subsequent_calls():
    # Inject a pattern into the blacklist directly (avoids needing a real
    # pathological regex in the test, which would slow CI).
    sre._BLACKLIST.add("forbidden")
    assert sre.safe_search("forbidden", "forbidden") is None
    snap = sre.stats_snapshot()
    assert snap["blacklist_hits"] == 1


def test_stats_snapshot_includes_thread_count():
    snap = sre.stats_snapshot()
    assert "leaked_threads_alive" in snap
    assert "blacklist_size" in snap
    assert snap["calls"] == 0


def test_reset_call_stats_preserves_blacklist_and_leak_total():
    sre._BLACKLIST.add("pat1")
    sre._stats["leaked_threads"] = 5
    sre._stats["calls"] = 100
    sre.reset_call_stats()
    snap = sre.stats_snapshot()
    assert snap["calls"] == 0
    assert snap["leaked_threads"] == 5
    assert snap["blacklist_size"] == 1


def test_slow_top_returns_largest_first():
    sre._slow_log.extend([
        (0.6, "fast", 100),
        (3.4, "slow", 200),
        (1.1, "med", 150),
    ])
    top = sre.slow_top(2)
    assert len(top) == 2
    assert top[0][1] == "slow"
    assert top[1][1] == "med"


def test_normal_call_does_not_blacklist():
    sre.safe_search(r"\d+", "abc 123 def")
    snap = sre.stats_snapshot()
    assert snap["timeouts"] == 0
    assert snap["slow_calls"] == 0


def test_short_simulated_timeout_blacklists(monkeypatch):
    # Force a timeout by patching the timeout to 0 and the runner to sleep
    # past it. Avoids depending on real catastrophic-backtrack input.
    import threading

    real_thread = threading.Thread

    class StuckThread(real_thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def run(self):  # never actually runs the target
            time.sleep(0.5)

    monkeypatch.setattr("fp.safe_regex.threading.Thread", StuckThread)
    result = sre.safe_search(r"anything", "text", timeout=0.05)
    assert result is None
    snap = sre.stats_snapshot()
    assert snap["timeouts"] == 1
    assert snap["blacklist_size"] == 1
    assert "anything" in sre._BLACKLIST
