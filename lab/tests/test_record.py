"""Structure tests for record.py. No network — just shape/contract checks."""

from __future__ import annotations

import record


def test_fuzz_probes_are_well_formed():
    assert record.FUZZ_PROBES, "FUZZ_PROBES must not be empty"
    seen_ids: set[str] = set()
    for p in record.FUZZ_PROBES:
        # Required keys
        assert "id" in p and "method" in p and "path" in p, f"missing keys in {p}"
        assert isinstance(p["id"], str) and p["id"].strip(), f"bad id: {p}"
        assert isinstance(p["method"], str) and p["method"].isupper(), f"bad method: {p}"
        assert isinstance(p["path"], str) and p["path"].startswith("/") or p["path"] == "*", \
            f"bad path: {p}"
        # ID must be unique (downstream diff uses it as the response key, so
        # collisions would silently drop probes during recording).
        assert p["id"] not in seen_ids, f"duplicate probe id: {p['id']}"
        seen_ids.add(p["id"])
        # Optional headers/body must have the right types if present.
        if "headers" in p:
            assert isinstance(p["headers"], dict)
            for k, v in p["headers"].items():
                assert isinstance(k, str) and isinstance(v, str)
        if "body" in p:
            assert isinstance(p["body"], (bytes, bytearray)) or p["body"] is None


def test_fuzz_probe_ids_do_not_collide_with_default_paths():
    # Path-probes use URL paths as keys ("/", "/index.html", ...). Fuzz
    # probes must use non-URL-shaped ids so response indexing in diff.py
    # never conflates the two.
    for p in record.FUZZ_PROBES:
        assert p["id"] not in record.DEFAULT_PROBE_PATHS, \
            f"fuzz id {p['id']!r} collides with a default path"


def test_fuzz_probes_cover_expected_surfaces():
    methods = {p["method"] for p in record.FUZZ_PROBES}
    # Regression canary: we intend to hit at least the major error surfaces.
    for required in ("PROPFIND", "TRACE", "OPTIONS", "DELETE"):
        assert required in methods, f"missing {required} probe"
    # At least one probe with a header override (so the header path works).
    assert any("headers" in p for p in record.FUZZ_PROBES)
    # At least one probe with a body.
    assert any("body" in p for p in record.FUZZ_PROBES)


# ---------------------------------------------------------------------------
# extract_refs — asset crawler
# ---------------------------------------------------------------------------


def test_extract_refs_finds_script_and_link_with_relative_urls():
    html = """
    <html><head>
      <link rel="stylesheet" href="/static/main.css?ver=1.2.3">
      <link rel="icon" href="favicon.ico">
      <script src="/wp-includes/js/wp-embed.min.js?ver=6.4.3"></script>
      <script src="./app.js"></script>
    </head><body></body></html>
    """
    refs = record.extract_refs(html, "http://t.local/")
    # Both link hrefs and both script srcs, relative resolved against base.
    assert "/static/main.css?ver=1.2.3" in refs
    assert "/favicon.ico" in refs
    assert "/wp-includes/js/wp-embed.min.js?ver=6.4.3" in refs
    assert "/app.js" in refs


def test_extract_refs_drops_external_and_scheme_only_urls():
    html = """
    <link href="https://cdn.example.com/lib.css">
    <script src="//cdn.example.com/lib.js"></script>
    <script src="data:text/javascript,alert(1)"></script>
    <script src="javascript:void(0)"></script>
    <a href="#top">top</a>
    <script src="/local.js"></script>
    """
    refs = record.extract_refs(html, "http://t.local/")
    assert refs == ["/local.js"]


def test_extract_refs_is_deduped_and_capped():
    # Same URL twice in document should appear once.
    html = '<script src="/a.js"></script><script src="/a.js"></script>'
    refs = record.extract_refs(html, "http://t.local/")
    assert refs == ["/a.js"]

    # Cap enforcement.
    many = "".join(f'<script src="/s{i}.js"></script>' for i in range(50))
    refs = record.extract_refs(many, "http://t.local/", max_refs=5)
    assert len(refs) == 5
    assert refs == [f"/s{i}.js" for i in range(5)]


def test_extract_refs_handles_empty_or_binary_body():
    assert record.extract_refs("", "http://t.local/") == []
    assert record.extract_refs("<binary:deadbeef>", "http://t.local/") == []


def test_extract_refs_preserves_query_string():
    # Query string is where many apps disclose version (?ver=6.4.3).
    html = '<script src="/lib.js?ver=1.2.3&build=20231201"></script>'
    refs = record.extract_refs(html, "http://t.local/")
    assert refs == ["/lib.js?ver=1.2.3&build=20231201"]
