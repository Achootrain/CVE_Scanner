"""Tests for fp.progress (live progress logger + async heartbeat)."""

from __future__ import annotations

import asyncio
import io
import re
import time

from fp import progress as prog_mod


def _capture(enabled: bool = True) -> tuple[prog_mod.ProgressLogger, io.StringIO]:
    buf = io.StringIO()
    return prog_mod.ProgressLogger(stream=buf, enabled=enabled), buf


# ---------------------------------------------------------------------------
# Format
# ---------------------------------------------------------------------------


class TestFormat:
    def test_event_has_timestamp_prefix(self):
        p, buf = _capture()
        p.event("hello")
        out = buf.getvalue()
        # Expected shape: "[HH:MM:SS] hello\n"
        assert re.match(r"\[\d{2}:\d{2}:\d{2}\] hello\n$", out), repr(out)

    def test_header_includes_target_and_est_max(self):
        p, buf = _capture()
        p.header("https://t.test", est_max=42)
        assert "target: https://t.test" in buf.getvalue()
        assert "est max ~42s" in buf.getvalue()

    def test_start_done_pair(self):
        p, buf = _capture()
        p.start("scan", "concurrent")
        p.done("scan", "17 detections")
        lines = buf.getvalue().splitlines()
        assert "scan: started" in lines[0]
        assert "(concurrent)" in lines[0]
        assert "scan: done" in lines[1]
        assert "(17 detections)" in lines[1]

    def test_skip_and_error(self):
        p, buf = _capture()
        p.skip("katana", "binary not on PATH")
        p.error("scan", RuntimeError("boom"))
        out = buf.getvalue()
        assert "katana: skipped (binary not on PATH)" in out
        assert "scan: ERROR" in out
        assert "boom" in out


# ---------------------------------------------------------------------------
# Disabled mode is silent
# ---------------------------------------------------------------------------


class TestDisabled:
    def test_no_output_when_disabled(self):
        p, buf = _capture(enabled=False)
        p.header("https://t.test")
        p.start("scan")
        p.done("scan")
        p.event("anything")
        assert buf.getvalue() == ""


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class TestHeartbeat:
    def test_heartbeat_logs_running_tasks(self):
        async def run():
            p, buf = _capture()
            # A task that won't finish on its own within the test window.
            slow = asyncio.create_task(asyncio.sleep(5))
            try:
                hb = asyncio.create_task(
                    prog_mod.heartbeat(p, {"slow": slow}, interval=0.05)
                )
                # Let the heartbeat tick at least twice.
                await asyncio.sleep(0.15)
                hb.cancel()
                try:
                    await hb
                except asyncio.CancelledError:
                    pass
            finally:
                slow.cancel()
                try:
                    await slow
                except asyncio.CancelledError:
                    pass
            return buf.getvalue()

        out = asyncio.run(run())
        # At least one heartbeat tick should have fired.
        assert "still running: slow" in out

    def test_heartbeat_returns_when_all_done(self):
        async def run():
            p, buf = _capture()
            done = asyncio.create_task(asyncio.sleep(0))
            await done  # already complete
            hb = asyncio.create_task(
                prog_mod.heartbeat(p, {"done": done}, interval=0.02)
            )
            # Heartbeat should observe the task is done at first tick and
            # return without emitting "still running".
            await asyncio.sleep(0.1)
            assert hb.done()
            return buf.getvalue()

        out = asyncio.run(run())
        assert "still running" not in out

    def test_heartbeat_disabled_returns_immediately(self):
        async def run():
            p, _ = _capture(enabled=False)
            slow = asyncio.create_task(asyncio.sleep(5))
            try:
                t0 = time.monotonic()
                await prog_mod.heartbeat(p, {"slow": slow}, interval=10)
                # Should return immediately, not wait for the 10s tick.
                assert time.monotonic() - t0 < 0.1
            finally:
                slow.cancel()
                try:
                    await slow
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())

    def test_heartbeat_swallows_cancellation(self):
        async def run():
            p, _ = _capture()
            slow = asyncio.create_task(asyncio.sleep(5))
            try:
                hb = asyncio.create_task(
                    prog_mod.heartbeat(p, {"slow": slow}, interval=10)
                )
                await asyncio.sleep(0.01)
                hb.cancel()
                # Awaiting after cancel must NOT raise CancelledError --
                # heartbeat catches it and returns cleanly.
                try:
                    await hb
                except asyncio.CancelledError:
                    raise AssertionError("CancelledError leaked from heartbeat")
            finally:
                slow.cancel()
                try:
                    await slow
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
