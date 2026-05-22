"""Tests for the regex refiner (lab/rag/refiner.py).

Mocked Gemini client; no network. Verifies the four structural
guardrails:

  G1 monotonic coverage (no regression on original cited spans)
  G2 counter-examples must match
  G3 capture-group arity preserved (extracts.g still valid)
  G4 pattern actually changed (no no-op)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from lab.rag import refiner as rf
from lab.rag.llm import Message


class _ScriptedClient:
    """Returns a queue of canned response strings."""
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls = 0

    def generate(self, messages: list[Message], *, system: str | None = None,
                 json_schema: dict | None = None) -> str:
        if self.calls >= len(self.responses):
            raise RuntimeError(f"_ScriptedClient exhausted at call {self.calls}")
        out = self.responses[self.calls]
        self.calls += 1
        return out


def _ce(text: str, file_path: str = "snap/x.js") -> rf.CounterExample:
    return rf.CounterExample(
        file_path=file_path, line_start=1, line_end=10,
        content_hash=hashlib.sha256(text.encode()).hexdigest(),
        text=text,
    )


def _base_rule(pattern: str = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)") -> dict:
    return {
        "id": "x_v1",
        "section": "banner_rules",
        "kind": "banner",
        "pattern": pattern,
        "extracts": {"version": {"g": 1}},
        "applies_to": "js body",
        "confidence": "high",
        "source": {"principle": "test", "citations": []},
    }


# ---------------------------------------------------------------------------
# G4: no-op rejected
# ---------------------------------------------------------------------------

def test_refiner_rejects_no_op_pattern():
    original = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)"
    client = _ScriptedClient([
        # Turn 0: returns the SAME pattern (no-op).
        json.dumps({"tool": "refine", "rule": {
            "pattern": original,
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "no change", "signal_shape": "x"},
        }}),
        # Turn 1: returns a real widening.
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"Owl[\s\-]?Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "separator", "signal_shape": "x"},
        }}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(original),
        original_cited_texts=["Owl Carousel v2.3.4"],
        counter_examples=[_ce("OwlCarousel v1.3.3")],
    )
    assert out.get("_aborted") is None, out
    assert out["pattern"] == r"Owl[\s\-]?Carousel\s+v(\d+\.\d+\.\d+)"
    # The history of failed attempts should include the no-op.
    history = (out.get("_drafter_meta") or {}).get("pattern_history") or []
    assert any("no-op" in (h.get("failed_because") or "").lower() for h in history)


# ---------------------------------------------------------------------------
# G1: monotonic coverage on original spans
# ---------------------------------------------------------------------------

def test_refiner_rejects_pattern_that_breaks_original_match():
    original = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)"
    # The model proposes a pattern that matches the counter but DROPS the original.
    # E.g. removing the "Carousel" token entirely.
    client = _ScriptedClient([
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"OwlCarousel\s+v(\d+\.\d+\.\d+)",  # only matches v1 form
            "_drafter_meta": {"refined_from": original, "widening_summary": "x",
                              "signal_shape": "y"},
        }}),
        # Eventually gives up.
        json.dumps({"tool": "refine", "rule": None,
                    "_abort_reason": "cannot widen monotonically"}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(original),
        original_cited_texts=["Owl Carousel v2.3.4"],   # this MUST keep matching
        counter_examples=[_ce("OwlCarousel v1.3.3")],
    )
    assert "_aborted" in out
    assert "monotonic" in out["_aborted"].lower() or "widen" in out["_aborted"].lower()


# ---------------------------------------------------------------------------
# G2: counter-examples must match
# ---------------------------------------------------------------------------

def test_refiner_rejects_pattern_that_still_misses_counter():
    original = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)"
    # Adds noise that doesn't actually help the counter (still requires the space).
    client = _ScriptedClient([
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"(?:jQuery\s+)?Owl\s+Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "noise", "signal_shape": "x"},
        }}),
        # Try again with the actual fix.
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"Owl[\s\-]?Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "separator", "signal_shape": "x"},
        }}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(original),
        original_cited_texts=["Owl Carousel v2.3.4"],
        counter_examples=[_ce("OwlCarousel v1.3.3")],
    )
    assert out.get("_aborted") is None, out
    # Second attempt won; history should record the first failure.
    history = (out["_drafter_meta"] or {}).get("pattern_history") or []
    assert any("counter unmatched" in (h.get("failed_because") or "").lower()
               for h in history)


# ---------------------------------------------------------------------------
# G3: capture-group arity preserved
# ---------------------------------------------------------------------------

def test_refiner_rejects_pattern_with_wrong_capture_arity():
    original = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)"
    # Adds an EXTRA capturing group, shifting the version to g=2; extracts.g=1
    # would now point at the wrong thing.
    client = _ScriptedClient([
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"(Owl)\s+Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original, "widening_summary": "x",
                              "signal_shape": "y"},
        }}),
        json.dumps({"tool": "refine", "rule": None,
                    "_abort_reason": "couldn't widen without breaking arity"}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(original),  # extracts.version.g = 1
        original_cited_texts=["Owl Carousel v2.3.4"],
        counter_examples=[_ce("OwlCarousel v1.3.3")],
    )
    assert "_aborted" in out


# ---------------------------------------------------------------------------
# Happy path: drafter returns abort -> bubble through
# ---------------------------------------------------------------------------

def test_refiner_returns_abort_when_drafter_aborts():
    client = _ScriptedClient([
        json.dumps({"tool": "refine", "rule": None,
                    "_abort_reason": "counter shape too divergent"}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(),
        original_cited_texts=["Owl Carousel v2.3.4"],
        counter_examples=[_ce("Foundation v5.2.2")],
    )
    assert out == {"_aborted": "counter shape too divergent"}


# ---------------------------------------------------------------------------
# Pattern history is appended across turns
# ---------------------------------------------------------------------------

def test_refiner_appends_pattern_history_across_failed_turns():
    original = r"Owl\s+Carousel\s+v(\d+\.\d+\.\d+)"
    client = _ScriptedClient([
        # Attempt 1: no-op
        json.dumps({"tool": "refine", "rule": {"pattern": original,
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "n", "signal_shape": "s"}}}),
        # Attempt 2: still doesn't match counter
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"(?:jQuery\s+)?Owl\s+Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "p", "signal_shape": "s"}}}),
        # Attempt 3: success
        json.dumps({"tool": "refine", "rule": {
            "pattern": r"Owl[\s\-]?Carousel\s+v(\d+\.\d+\.\d+)",
            "_drafter_meta": {"refined_from": original,
                              "widening_summary": "sep", "signal_shape": "s"}}}),
    ])
    out = rf.refine_rule(
        client,
        _base_rule(original),
        original_cited_texts=["Owl Carousel v2.3.4"],
        counter_examples=[_ce("OwlCarousel v1.3.3")],
    )
    assert out.get("_aborted") is None
    history = (out["_drafter_meta"] or {}).get("pattern_history") or []
    assert len(history) == 2
