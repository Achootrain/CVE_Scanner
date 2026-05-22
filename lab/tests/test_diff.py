"""Tests for the Phase 3 diff miner. No Docker, no network."""

from __future__ import annotations

import json
import re
from pathlib import Path

import diff


# ---------------------------------------------------------------------------
# Building synthetic recordings
# ---------------------------------------------------------------------------


def _rec(tmp: Path, fid: str, tech: str, version: str, responses: list[dict]) -> Path:
    d = tmp / fid
    d.mkdir(parents=True, exist_ok=True)
    f = d / "responses.json"
    f.write_text(
        json.dumps({
            "fixture": fid, "url": "http://t", "tech": tech,
            "version": version, "responses": responses,
        }),
        encoding="utf-8",
    )
    return f


# ---------------------------------------------------------------------------
# Unit: hit extraction
# ---------------------------------------------------------------------------


def test_find_hits_returns_pre_and_post_context():
    body = "before nginx/1.25.3 after; and again nginx/1.25.3 suffix"
    hits = diff.find_hits(body, "1.25.3", window=10)
    assert len(hits) == 2
    off1, pre1, post1 = hits[0]
    assert pre1.endswith("nginx/")
    assert post1.startswith(" after")
    off2, _, post2 = hits[1]
    assert off2 > off1
    assert post2.startswith(" suffix")


def test_find_hits_no_match_returns_empty():
    assert diff.find_hits("no version here", "9.9.9") == []


def test_find_hits_handles_empty_inputs():
    assert diff.find_hits("", "1.0") == []
    assert diff.find_hits("anything", "") == []


# ---------------------------------------------------------------------------
# Unit: version ordering
# ---------------------------------------------------------------------------


def test_version_key_numeric_order():
    assert diff._version_key("1.24.0") < diff._version_key("1.25.3")
    assert diff._version_key("10.2.3") > diff._version_key("9.9.9")


def test_pair_versions_sorts_and_pairs_adjacent():
    fx = [
        {"version": "1.25.3"},
        {"version": "1.24.0"},
        {"version": "1.26.1"},
    ]
    pairs = diff.pair_versions(fx)
    assert len(pairs) == 2
    assert pairs[0][0]["version"] == "1.24.0"
    assert pairs[0][1]["version"] == "1.25.3"
    assert pairs[1][0]["version"] == "1.25.3"
    assert pairs[1][1]["version"] == "1.26.1"


def test_pair_versions_single_fixture_returns_nothing():
    assert diff.pair_versions([{"version": "1.0.0"}]) == []


# ---------------------------------------------------------------------------
# Integration: compare_responses on a nginx-shaped pair
# ---------------------------------------------------------------------------


def _nginx_404_body(version: str) -> str:
    return (
        "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
        f"<hr><center>nginx/{version}</center>\r\n"
        "</body>\r\n</html>\r\n"
    )


def test_compare_responses_mines_nginx_server_header_and_footer():
    va, vb = "1.25.3", "1.24.0"
    a = {
        "version": va,
        "responses": [
            {"path": "/", "status": 200,
             "headers": {"server": f"nginx/{va}", "content-type": "text/html"},
             "body": "<html>welcome</html>"},
            {"path": "/__fp_lab_notfound_nrqc9s8__", "status": 404,
             "headers": {"server": f"nginx/{va}"},
             "body": _nginx_404_body(va)},
        ],
    }
    b = {
        "version": vb,
        "responses": [
            {"path": "/", "status": 200,
             "headers": {"server": f"nginx/{vb}", "content-type": "text/html"},
             "body": "<html>welcome</html>"},
            {"path": "/__fp_lab_notfound_nrqc9s8__", "status": 404,
             "headers": {"server": f"nginx/{vb}"},
             "body": _nginx_404_body(vb)},
        ],
    }

    cands = diff.dedup(diff.compare_responses("nginx", a, b))
    header_hits = [c for c in cands if c.source == "header"]
    body_hits = [c for c in cands if c.source == "body"]

    # After dedup, the Server header is ONE candidate (not one per path).
    server_hits = [c for c in header_hits if c.location == "server"]
    assert len(server_hits) == 1, f"expected single Server candidate after dedup, got {len(server_hits)}"
    s = server_hits[0]
    assert s.confidence == "high"
    assert re.escape("nginx/") in s.regex and "(\\S+)" in s.regex
    # Both probed paths produced the header, so both should be in paths.
    assert set(s.paths) == {"/", "/__fp_lab_notfound_nrqc9s8__"}

    # 404 footer body is also ONE candidate, observed on the 404 path.
    assert len(body_hits) == 1
    b_cand = body_hits[0]
    assert re.escape("nginx/") in b_cand.regex
    assert b_cand.paths == ["/__fp_lab_notfound_nrqc9s8__"]
    m = re.search(b_cand.regex, b_cand.example_a)
    assert m and m.group(1) == va
    m = re.search(b_cand.regex, b_cand.example_b)
    assert m and m.group(1) == vb


def test_compare_responses_skips_paths_with_different_status_classes():
    a = {"version": "1.0.0", "responses": [
        {"path": "/p", "status": 200, "headers": {"x-v": "app/1.0.0"},
         "body": "hello 1.0.0 world"},
    ]}
    b = {"version": "2.0.0", "responses": [
        {"path": "/p", "status": 500, "headers": {"x-v": "app/2.0.0"},
         "body": "hello 2.0.0 world"},
    ]}
    cands = diff.compare_responses("app", a, b)
    # Header candidate from "x-v" is fine (headers aren't status-gated in the
    # same way as bodies). But body candidates MUST be dropped across status
    # classes.
    assert not [c for c in cands if c.source == "body"]


def test_compare_responses_rejects_header_where_template_differs():
    # Both mention the version, but the surrounding literal text differs.
    # We must not emit a candidate — the template mismatch proves the
    # shared contents aren't a version disclosure pattern.
    a = {"version": "1.0", "responses": [
        {"path": "/", "status": 200,
         "headers": {"x-info": "frontend 1.0 build"}, "body": ""},
    ]}
    b = {"version": "2.0", "responses": [
        {"path": "/", "status": 200,
         "headers": {"x-info": "backend 2.0 build"}, "body": ""},
    ]}
    cands = diff.compare_responses("app", a, b)
    assert not [c for c in cands if c.location == "x-info"]


def test_dedup_collapses_same_regex_across_paths():
    # Same header+regex pair observed on three paths must collapse to one.
    base = dict(tech="nginx", version_a="1.24.0", version_b="1.25.3",
                source="header", location="server", regex=r"nginx/(\S+)",
                example_a="nginx/1.24.0", example_b="nginx/1.25.3",
                confidence="high")
    cands = [
        diff.Candidate(path="/", **base),
        diff.Candidate(path="/api/", **base),
        diff.Candidate(path="/nf", **base),
    ]
    out = diff.dedup(cands)
    assert len(out) == 1
    assert sorted(out[0].paths) == ["/", "/api/", "/nf"]


def test_dedup_merges_version_pairs_across_pairs():
    """Same regex surfacing from different version pairs should collapse
    into ONE candidate whose version_pairs list has all contributing pairs."""
    base = dict(source="header", location="server", regex=r"nginx/(\S+)",
                confidence="high", tech="nginx", path="/")
    # Two different version pairs both produced the same candidate.
    cands = [
        diff.Candidate(version_a="1.24.0", version_b="1.25.3",
                       example_a="nginx/1.24.0", example_b="nginx/1.25.3",
                       **base),
        diff.Candidate(version_a="1.25.3", version_b="1.26.0",
                       example_a="nginx/1.25.3", example_b="nginx/1.26.0",
                       **base),
    ]
    out = diff.dedup(cands, total_pairs=2)
    assert len(out) == 1
    assert len(out[0].version_pairs) == 2
    assert ("1.24.0", "1.25.3") in out[0].version_pairs
    assert ("1.25.3", "1.26.0") in out[0].version_pairs
    # Full coverage across all tested pairs → high confidence.
    assert out[0].confidence == "high"


def test_dedup_downgrades_confidence_on_partial_pair_coverage():
    """A candidate that fires on only 1 of 3 pairs is suspicious —
    downgrade from high to medium to make the weaker signal visible in
    the report."""
    base = dict(source="body", location="body", regex=r"foo=(\S+) ",
                tech="t", path="/x", example_a="foo=1.0 ", example_b="foo=2.0 ",
                confidence="high")
    cands = [diff.Candidate(version_a="1.0", version_b="2.0", **base)]
    out = diff.dedup(cands, total_pairs=3)
    assert len(out) == 1
    assert out[0].confidence == "medium"
    assert len(out[0].version_pairs) == 1


def test_dedup_preserves_confidence_when_only_one_pair_exists():
    """When total_pairs is 1, we can't cross-verify. Keep whatever
    confidence compare_responses produced (don't paradoxically downgrade
    everything in a 2-fixture setup)."""
    base = dict(source="header", location="server", regex=r"nginx/(\S+)",
                tech="nginx", path="/", example_a="nginx/1.0",
                example_b="nginx/2.0", confidence="high")
    cands = [diff.Candidate(version_a="1.0", version_b="2.0", **base)]
    out = diff.dedup(cands, total_pairs=1)
    assert out[0].confidence == "high"


# ---------------------------------------------------------------------------
# End-to-end: run_diff + write_reports
# ---------------------------------------------------------------------------


def test_run_diff_end_to_end(tmp_path: Path):
    va, vb = "1.25.3", "1.24.0"
    _rec(tmp_path, "nginx-a", "nginx", va, [
        {"path": "/nf", "status": 404,
         "headers": {"server": f"nginx/{va}"},
         "body": _nginx_404_body(va)},
    ])
    _rec(tmp_path, "nginx-b", "nginx", vb, [
        {"path": "/nf", "status": 404,
         "headers": {"server": f"nginx/{vb}"},
         "body": _nginx_404_body(vb)},
    ])
    # Orphan tech with only one version → no pairs → no candidates.
    _rec(tmp_path, "lonely-1", "lonely", "3.2.1", [
        {"path": "/", "status": 200, "headers": {}, "body": "just one"},
    ])

    by_tech = diff.run_diff(tmp_path)
    assert "nginx" in by_tech
    assert "lonely" not in by_tech
    assert by_tech["nginx"], "expected at least one nginx candidate"

    diff.write_reports(tmp_path, by_tech)
    cand_dir = tmp_path / "candidates"
    assert (cand_dir / "nginx.md").exists()
    rolled = json.loads((cand_dir / "candidates.json").read_text(encoding="utf-8"))
    assert "nginx" in rolled
    assert all("regex" in c for c in rolled["nginx"])


def test_run_diff_sweeps_three_versions_and_reports_all_pairs(tmp_path: Path):
    """With three versions of the same tech, run_diff should compare every
    adjacent pair and produce candidates whose version_pairs lists include
    all contributing pairs (for patterns that hold across the sweep)."""
    for v in ("1.24.0", "1.25.3", "1.26.0"):
        _rec(tmp_path, f"nginx-{v}", "nginx", v, [
            {"path": "/nf", "status": 404,
             "headers": {"server": f"nginx/{v}"},
             "body": _nginx_404_body(v)},
        ])
    by_tech = diff.run_diff(tmp_path)
    assert "nginx" in by_tech
    server = [c for c in by_tech["nginx"] if c.location == "server"]
    assert len(server) == 1
    # Both adjacent pairs (1.24↔1.25 and 1.25↔1.26) should contribute.
    assert len(server[0].version_pairs) == 2
    assert server[0].confidence == "high"


def test_run_diff_ignores_malformed_recordings(tmp_path: Path):
    # Good recording
    _rec(tmp_path, "good-a", "foo", "1.0", [{"path": "/", "status": 200, "headers": {}, "body": "x"}])
    _rec(tmp_path, "good-b", "foo", "2.0", [{"path": "/", "status": 200, "headers": {}, "body": "x"}])
    # Malformed recording — parser should warn, not crash.
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "responses.json").write_text("not-json", encoding="utf-8")

    by_tech = diff.run_diff(tmp_path)
    assert "foo" in by_tech
