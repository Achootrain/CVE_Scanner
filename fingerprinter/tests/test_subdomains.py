"""Offline tests for crt.sh response parsing."""

from __future__ import annotations

from fp.subdomains import _extract_names


def test_extract_names_filters_wildcards_and_deduplicates():
    rows = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "www.example.com"},  # duplicate
        {"name_value": "unrelated.other.com"},  # off-apex
    ]
    assert _extract_names(rows, "example.com") == [
        "api.example.com",
        "www.example.com",
    ]


def test_extract_names_keeps_apex_when_present():
    rows = [{"name_value": "example.com\nwww.example.com"}]
    assert _extract_names(rows, "example.com") == ["example.com", "www.example.com"]


def test_extract_names_lowercases_and_strips_trailing_dot():
    rows = [{"name_value": "API.Example.COM.\nweb.example.com"}]
    assert _extract_names(rows, "example.com") == ["api.example.com", "web.example.com"]


def test_extract_names_handles_empty_input():
    assert _extract_names([], "example.com") == []
