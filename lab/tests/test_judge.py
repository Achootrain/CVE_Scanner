"""Tests for the Sonnet judge (CLAUDE.md §12).

All tests stub the AnthropicClient and retrieve_rules; no network, no
API key required.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from lab.rag import judge


class _StubAnthropic:
    """Returns a canned response string on .generate_text().

    Named '_StubAnthropic' for historical reasons but the contract is
    provider-agnostic now: any client exposing generate_text(text, *, system)
    works. (GeminiClient and AnthropicClient both do.)
    """
    def __init__(self, response: str):
        self.response = response
        self.calls: list[dict] = []

    def generate_text(self, text: str, *, system: str | None = None) -> str:
        self.calls.append({"user": text, "system": system})
        return self.response

    # Back-compat: the old code path called .generate() directly.
    generate = generate_text


def _stub_retrieve(hits=None):
    def _fn(query, tech=None, k=5):
        return list(hits or [])
    return _fn


# ---------------------------------------------------------------------------
# judge_rule output normalization
# ---------------------------------------------------------------------------

def test_judge_returns_pass_when_client_says_pass():
    client = _StubAnthropic(json.dumps({
        "verdict": "PASS",
        "reasons": ["coherent banner signal"],
        "checks": {"signal_coherence": "PASS",
                   "inventory_matching": "PASS",
                   "channel_choice": "PASS"},
    }))
    rule = {"pattern": r"jquery (\d+\.\d+\.\d+)", "section": "banner_rules"}
    out = judge.judge_rule(rule, "jquery", client=client,
                           retrieve_fn=_stub_retrieve([]))
    assert out["verdict"] == "PASS"
    assert "coherent banner signal" in out["reasons"][0]


def test_judge_returns_flag_when_client_says_flag():
    client = _StubAnthropic(json.dumps({
        "verdict": "FLAG",
        "reasons": ["pattern is two CDN hosts glued with |"],
        "checks": {"signal_coherence": "FLAG",
                   "inventory_matching": "PASS",
                   "channel_choice": "PASS"},
    }))
    rule = {"pattern": r"(cdnjs|jsdelivr).*jquery (\d+\.\d+\.\d+)"}
    out = judge.judge_rule(rule, "jquery", client=client,
                           retrieve_fn=_stub_retrieve([]))
    assert out["verdict"] == "FLAG"
    assert "CDN" in out["reasons"][0]


def test_judge_flags_invalid_verdict_value():
    client = _StubAnthropic(json.dumps({"verdict": "MAYBE", "reasons": []}))
    rule = {"pattern": r"x"}
    out = judge.judge_rule(rule, "x", client=client,
                           retrieve_fn=_stub_retrieve([]))
    assert out["verdict"] == "FLAG"
    assert "invalid verdict" in out["reasons"][0]


def test_judge_flags_non_json_response():
    client = _StubAnthropic("Sure, here is my review: looks fine to me!")
    rule = {"pattern": r"x"}
    out = judge.judge_rule(rule, "x", client=client,
                           retrieve_fn=_stub_retrieve([]))
    assert out["verdict"] == "FLAG"
    assert "non-JSON" in out["reasons"][0]


# ---------------------------------------------------------------------------
# Nearby-rules retrieval is wired into the payload
# ---------------------------------------------------------------------------

def test_judge_includes_nearby_rules_in_payload():
    from lab.rag import retrieval as rt
    fake_hit = rt.Span(
        source="rule", tech="jquery",
        file_path="lab.db:lab_src_rules#jquery/jquery_url_v1",
        line_start=1, line_end=1, content_hash="x",
        text="[rule jquery_url_v1] pattern=`/jquery-(\\d+\\.\\d+\\.\\d+)/...`",
        score=2.5,
    )
    client = _StubAnthropic(json.dumps({
        "verdict": "PASS", "reasons": [], "checks": {}
    }))
    rule = {"pattern": r"/jquery-(\d+\.\d+\.\d+)/jquery\.min\.js",
            "section": "url_version_in_path_rules"}
    judge.judge_rule(rule, "jquery", client=client,
                     retrieve_fn=_stub_retrieve([fake_hit]))
    # The user_message sent to Anthropic must mention the surfaced rule.
    assert len(client.calls) == 1
    assert "jquery_url_v1" in client.calls[0]["user"]
    assert "nearby_rules_surfaced" in client.calls[0]["user"]


def test_judge_handles_missing_index_silently():
    """If the FTS index isn't built, nearby_rules is just empty -- the
    judge still runs."""
    def raising_retrieve(query, tech=None, k=5):
        raise FileNotFoundError("index missing")
    client = _StubAnthropic(json.dumps({
        "verdict": "PASS", "reasons": [], "checks": {}
    }))
    out = judge.judge_rule({"pattern": "x (\\d+)"}, "x",
                           client=client, retrieve_fn=raising_retrieve)
    assert out["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# System prompt mentions the three required checks
# ---------------------------------------------------------------------------

def test_judge_system_prompt_lists_three_checks():
    p = judge.JUDGE_SYSTEM_PROMPT
    assert "SIGNAL COHERENCE" in p
    assert "INVENTORY MATCHING" in p
    assert "CHANNEL CHOICE" in p
    # The verdict aggregation rule must be stated.
    assert "ANY check = FLAG" in p
