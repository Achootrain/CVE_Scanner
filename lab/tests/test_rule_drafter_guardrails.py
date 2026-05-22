"""Tests for the new Item 2 guardrails (CLAUDE.md §12):
  - Multi-phrased §9 gate (>=2 distinct phrasings of retrieve_rules)
  - Post-draft duplicate check (anchor-token overlap vs claimed outcome)

All tests stub the LLM client and the retrieve_rules function -- no
network, no FTS index, no API quota burn.
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

from lab.rag import rule_drafter as rd
from lab.rag import retrieval as rt
from lab.rag.llm import Message


# ---------------------------------------------------------------------------
# Helpers: build fake spans (for citing) and a scripted LLM client.
# ---------------------------------------------------------------------------

def _make_span(text: str, *, file_path: str = "lab/research/x/out/source/v1/a.css",
               source: str = "source", tech: str = "fake") -> rt.Span:
    """Build a Span and compute the matching content_hash for the text.

    The bounded-citation guardrail re-hashes file regions on disk, so we
    can't fake citations for the on-disk path -- but for the multi-phrased
    gate and dup-check tests we don't need to pass the bounded-citation
    guardrail. We give each span a unique hash derived from its text so
    spans_seen membership works.
    """
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return rt.Span(
        source=source, tech=tech, file_path=file_path,
        line_start=1, line_end=1,
        content_hash=h, text=text, score=1.0,
    )


class _ScriptedClient:
    """Returns a pre-baked sequence of JSON strings on .generate() calls.

    The drafter calls .generate() once per turn; this lets us drive the
    full loop deterministically without an API key."""
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls = 0

    def generate(self, history: list[Message], *, system: str | None = None,
                 json_schema: dict | None = None) -> str:
        if self.calls >= len(self.responses):
            raise RuntimeError(f"_ScriptedClient exhausted at call {self.calls}")
        out = self.responses[self.calls]
        self.calls += 1
        return out


# ---------------------------------------------------------------------------
# _are_distinct_phrasings
# ---------------------------------------------------------------------------

def test_distinct_phrasings_requires_symmetric_difference():
    # Same tokens, different order -> NOT distinct.
    assert not rd._are_distinct_phrasings(
        ["banner header version", "version banner header"]
    )
    # Pure-prefix extension -> NOT distinct (no symmetric diff).
    assert not rd._are_distinct_phrasings(
        ["jQuery banner", "jQuery banner header"]
    )
    # One has 'css', other has 'javascript' -> distinct.
    assert rd._are_distinct_phrasings(
        ["jQuery banner CSS comment", "jQuery banner JavaScript header"]
    )


def test_distinct_phrasings_ignores_stopwords():
    # Only difference is stopwords ('the', 'for', 'rule'/'rules') -> NOT distinct.
    assert not rd._are_distinct_phrasings(
        ["banner version", "the banner version rule"]
    )


def test_distinct_phrasings_needs_two_queries_minimum():
    assert not rd._are_distinct_phrasings([])
    assert not rd._are_distinct_phrasings(["banner version css"])


# ---------------------------------------------------------------------------
# _literal_anchors_of_pattern
# ---------------------------------------------------------------------------

def test_literal_anchors_strips_metacharacters():
    pattern = r"/font-awesome/(\d+\.\d+(?:\.\d+)?)/css/fontawesome\.css"
    anchors = rd._literal_anchors_of_pattern(pattern)
    assert "font-awesome" in anchors or "font" in anchors
    assert "fontawesome" in anchors
    assert "css" in anchors


def test_literal_anchors_drops_escape_classes():
    pattern = r"\bversion\s*[:=]\s*(\d+\.\d+\.\d+)\b"
    anchors = rd._literal_anchors_of_pattern(pattern)
    # \b, \s, \d, \. should not leak literal 'b'/'s'/'d' tokens
    assert "b" not in anchors and "s" not in anchors and "d" not in anchors
    assert "version" in anchors


def test_literal_anchors_drops_url_stopwords():
    pattern = r"https?://cdn\.example\.com/jquery@(\d+\.\d+\.\d+)/jquery\.min\.js"
    anchors = rd._literal_anchors_of_pattern(pattern)
    # http/https/com are URL noise, not anchors.
    assert "http" not in anchors and "https" not in anchors
    assert "com" not in anchors
    # The actual signal anchors remain.
    assert "jquery" in anchors


# ---------------------------------------------------------------------------
# _post_draft_dup_check
# ---------------------------------------------------------------------------

def test_post_draft_dup_flags_no_near_match_when_existing_rule_overlaps():
    drafted = {
        "pattern": r"/jquery-(\d+\.\d+\.\d+)/jquery\.min\.js",
        "_drafter_meta": {"ninth_gate_outcome": "no_near_match"},
    }
    # Fake existing rule with overlapping anchors ('jquery', 'min', 'js')
    fake_hit = _make_span(
        "[rule jquery_url_v1] pattern=`/jquery-(\\d+\\.\\d+\\.\\d+)/jquery\\.min\\.js`",
        file_path="lab.db:lab_src_rules#jquery/jquery_url_v1",
        source="rule", tech="jquery",
    )
    def fake_retrieve(query, tech=None, k=5):
        return [fake_hit]
    errs = rd._post_draft_dup_check(drafted, "jquery", retrieve_fn=fake_retrieve)
    assert errs, "expected violation when no_near_match but anchors overlap"
    assert "no_near_match" in errs[0]
    assert "jquery_url_v1" in errs[0]


def test_post_draft_dup_passes_when_generalised_claim_matches():
    drafted = {
        "pattern": r"/(?:jquery|jq)[-@/](\d+\.\d+\.\d+)/jquery\.min\.js",
        "_drafter_meta": {"ninth_gate_outcome":
                          "generalised_from_jquery/jquery_url_v1"},
    }
    fake_hit = _make_span(
        "[rule jquery_url_v1] pattern=`/jquery-(\\d+\\.\\d+\\.\\d+)/jquery\\.min\\.js`",
        file_path="lab.db:lab_src_rules#jquery/jquery_url_v1",
        source="rule", tech="jquery",
    )
    def fake_retrieve(query, tech=None, k=5):
        return [fake_hit]
    errs = rd._post_draft_dup_check(drafted, "jquery", retrieve_fn=fake_retrieve)
    assert errs == [], f"expected pass when generalisation claim aligns: {errs}"


def test_post_draft_dup_flags_unfalsifiable_generalisation_claim():
    drafted = {
        "pattern": r"/jquery-(\d+\.\d+\.\d+)/jquery\.min\.js",
        "_drafter_meta": {"ninth_gate_outcome":
                          "generalised_from_nonexistent_rule_id"},
    }
    # retrieve_rules returns NOTHING -- so the 'generalised_from' claim
    # can't be verified.
    def fake_retrieve(query, tech=None, k=5):
        return []
    errs = rd._post_draft_dup_check(drafted, "jquery", retrieve_fn=fake_retrieve)
    assert errs, "expected violation when generalisation target isn't surfaced"


def test_post_draft_dup_skips_when_index_missing():
    drafted = {
        "pattern": r"/jquery-(\d+\.\d+\.\d+)/jquery\.min\.js",
        "_drafter_meta": {"ninth_gate_outcome": "no_near_match"},
    }
    def fake_retrieve(query, tech=None, k=5):
        raise FileNotFoundError("index not built")
    errs = rd._post_draft_dup_check(drafted, "jquery", retrieve_fn=fake_retrieve)
    assert errs == [], "missing index must not block drafting"


# ---------------------------------------------------------------------------
# _verify_guardrails: multi-phrased §9 gate
# ---------------------------------------------------------------------------

def _minimal_rule(pattern: str = r"version (\d+\.\d+\.\d+)") -> dict:
    """A rule that passes everything EXCEPT what we're testing."""
    return {
        "id": "x_test",
        "section": "banner_rules",
        "kind": "banner",
        "pattern": pattern,
        "extracts": {"version": {"g": 1}},
        "applies_to": "css body",
        "confidence": "medium",
        "source": {"principle": "test", "citations": []},
        "_drafter_meta": {"ninth_gate_outcome": "no_near_match"},
    }


def test_guardrails_fail_with_zero_rule_queries():
    errs = rd._verify_guardrails(_minimal_rule(), {}, [], tech="x")
    assert any("§9 gate" in e for e in errs)


def test_guardrails_fail_with_one_rule_query():
    errs = rd._verify_guardrails(
        _minimal_rule(), {}, ["banner header version"], tech="x")
    assert any("multi-phrased gate" in e for e in errs)


def test_guardrails_fail_with_two_non_distinct_queries():
    errs = rd._verify_guardrails(
        _minimal_rule(), {},
        ["banner header version", "version banner header"],  # same tokens
        tech="x",
    )
    assert any("multi-phrased gate" in e for e in errs)


def test_guardrails_pass_multi_phrased_gate_when_distinct():
    # Citations are still empty so other guardrails fail -- we just check
    # the §9 multi-phrased gate is NOT among the violations.
    errs = rd._verify_guardrails(
        _minimal_rule(), {},
        ["banner header CSS comment", "JavaScript library version string"],
        tech="x",
    )
    assert not any("multi-phrased gate" in e for e in errs)
    assert not any("§9 gate" in e for e in errs)
