"""Tests for fp.jsextract."""

from __future__ import annotations

import pytest

from fp.jsextract import ExtractedPath, extract_paths


def _paths(body: str, **kw) -> dict[str, str]:
    """Return {path: confidence} for all extracted paths."""
    return {ep.path: ep.confidence for ep in extract_paths(body, **kw)}


# ---------------------------------------------------------------------------
# Tier 1: call-site patterns
# ---------------------------------------------------------------------------


class TestFetch:
    def test_single_quote(self):
        r = _paths("fetch('/api/users')")
        assert r.get("/api/users") == "call"

    def test_double_quote(self):
        r = _paths('fetch("/api/products")')
        assert r.get("/api/products") == "call"

    def test_await_prefix(self):
        r = _paths("const res = await fetch('/api/orders')")
        assert "/api/orders" in r

    def test_with_options_arg(self):
        r = _paths("fetch('/api/login', { method: 'POST' })")
        assert "/api/login" in r

    def test_query_string_stripped(self):
        r = _paths("fetch('/api/users?page=1')")
        assert "/api/users" in r
        assert "/api/users?page=1" not in r

    def test_fragment_stripped(self):
        r = _paths("fetch('/api/users#section')")
        assert "/api/users" in r


class TestAxios:
    def test_get(self):
        r = _paths("axios.get('/v1/users')")
        assert r.get("/v1/users") == "call"

    def test_post(self):
        r = _paths("axios.post('/api/login', data)")
        assert "/api/login" in r

    def test_put(self):
        r = _paths("axios.put('/api/items/1', data)")
        assert "/api/items/1" in r

    def test_delete(self):
        r = _paths("axios.delete('/api/items/1')")
        assert "/api/items/1" in r

    def test_bare_function(self):
        r = _paths("axios('/api/data', { method: 'GET' })")
        assert "/api/data" in r

    def test_base_url_field(self):
        r = _paths("axios.create({ baseURL: '/api/v2' })")
        assert "/api/v2" in r


class TestJQuery:
    def test_dollar_get(self):
        r = _paths("$.get('/api/items')")
        assert r.get("/api/items") == "call"

    def test_dollar_post(self):
        r = _paths("$.post('/api/save', data)")
        assert "/api/save" in r

    def test_dollar_ajax(self):
        r = _paths("$.ajax('/api/load')")
        assert "/api/load" in r

    def test_dollar_put(self):
        r = _paths("$.put('/api/update')")
        assert "/api/update" in r


class TestXHR:
    def test_open_get(self):
        r = _paths("xhr.open('GET', '/api/users', true)")
        assert r.get("/api/users") == "call"

    def test_open_post(self):
        r = _paths('xhr.open("POST", "/api/login")')
        assert "/api/login" in r


class TestObjectFields:
    def test_url_field(self):
        r = _paths("{url: '/api/config'}")
        assert r.get("/api/config") == "call"

    def test_endpoint_field(self):
        r = _paths("{ endpoint: '/api/endpoint' }")
        assert "/api/endpoint" in r

    def test_href_field(self):
        r = _paths("router.push({ href: '/dashboard/settings' })")
        assert "/dashboard/settings" in r

    def test_base_url_camel(self):
        r = _paths("baseUrl: '/api/v3'")
        assert "/api/v3" in r


class TestChainedMethods:
    def test_http_client_get(self):
        r = _paths("http.get('/internal/health')")
        assert "/internal/health" in r

    def test_client_post(self):
        r = _paths("client.post('/api/submit')")
        assert "/api/submit" in r

    def test_generic_request(self):
        r = _paths("request('/api/data')")
        assert "/api/data" in r


# ---------------------------------------------------------------------------
# Tier 2: API-segment patterns
# ---------------------------------------------------------------------------


class TestApiSegment:
    def test_graphql(self):
        r = _paths('"/graphql"')
        assert "/graphql" in r

    def test_versioned(self):
        r = _paths('"/v2/products/list"')
        assert "/v2/products/list" in r

    def test_auth(self):
        r = _paths('"/auth/token"')
        assert "/auth/token" in r

    def test_admin(self):
        r = _paths('"/admin/users"')
        assert "/admin/users" in r

    def test_health(self):
        r = _paths('"/health"')
        assert "/health" in r

    def test_confidence_is_api_not_call(self):
        # No call-site prefix -> should be "api", not "call"
        r = _paths('var u = "/api/data"')
        assert r.get("/api/data") == "api"

    def test_call_beats_api_for_same_path(self):
        # fetch() appears first in Tier 1, so it wins
        body = "fetch('/api/users')\nvar u = \"/api/users\""
        r = _paths(body)
        assert r.get("/api/users") == "call"


# ---------------------------------------------------------------------------
# Tier 3: template literal prefix
# ---------------------------------------------------------------------------


class TestTemplateLiterals:
    def test_basic(self):
        r = _paths("`/api/${userId}/posts`")
        assert "/api/" in r
        assert r["/api/"] == "template"

    def test_longer_prefix(self):
        r = _paths("`/v1/users/${id}/orders`")
        assert "/v1/users/" in r

    def test_call_beats_template(self):
        body = "fetch('/v1/users/')\n`/v1/users/${id}`"
        r = _paths(body)
        assert r.get("/v1/users/") == "call"


# ---------------------------------------------------------------------------
# Noise filter
# ---------------------------------------------------------------------------


class TestNoiseFilter:
    def test_js_extension_dropped(self):
        r = _paths("fetch('/assets/main.js')")
        assert "/assets/main.js" not in r

    def test_css_dropped(self):
        r = _paths('fetch("/styles/app.css")')
        assert "/styles/app.css" not in r

    def test_png_dropped(self):
        r = _paths('fetch("/images/logo.png")')
        assert "/images/logo.png" not in r

    def test_svg_dropped(self):
        r = _paths("fetch('/icons/arrow.svg')")
        assert "/icons/arrow.svg" not in r

    def test_woff_dropped(self):
        r = _paths("fetch('/fonts/sans.woff2')")
        assert "/fonts/sans.woff2" not in r

    def test_sourcemap_dropped(self):
        r = _paths('fetch("/dist/app.js.map")')
        assert "/dist/app.js.map" not in r

    def test_wasm_dropped(self):
        r = _paths('fetch("/app.wasm")')
        assert "/app.wasm" not in r

    def test_webpack_hmr_dropped(self):
        r = _paths('fetch("/__webpack_hmr")')
        assert "/__webpack_hmr" not in r

    def test_node_modules_dropped(self):
        r = _paths('fetch("/node_modules/lodash")')
        assert "/node_modules/lodash" not in r

    def test_too_short_dropped(self):
        r = _paths("fetch('/')")
        assert "/" not in r

    def test_two_char_dropped(self):
        r = _paths("fetch('/a')")
        assert "/a" not in r


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_path_appears_once(self):
        body = "fetch('/api/users')\naxios.get('/api/users')"
        eps = extract_paths(body)
        hits = [ep for ep in eps if ep.path == "/api/users"]
        assert len(hits) == 1

    def test_higher_confidence_wins(self):
        # Tier 1 runs before Tier 2; call wins
        body = "fetch('/api/data')\n\"/api/data\""
        r = _paths(body)
        assert r["/api/data"] == "call"

    def test_query_and_bare_same_path(self):
        body = "fetch('/api/users?page=1')\nfetch('/api/users')"
        eps = extract_paths(body)
        hits = [ep for ep in eps if ep.path == "/api/users"]
        assert len(hits) == 1


# ---------------------------------------------------------------------------
# source_url propagation
# ---------------------------------------------------------------------------


def test_source_url_propagated():
    eps = extract_paths("fetch('/api/users')", source_url="https://example.com/app.js")
    assert any(ep.source_url == "https://example.com/app.js" for ep in eps)


# ---------------------------------------------------------------------------
# Bytes input
# ---------------------------------------------------------------------------


def test_bytes_input():
    r = _paths(b"fetch('/api/users')")
    assert "/api/users" in r


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------


def test_to_dict_keys():
    ep = ExtractedPath(path="/api/x", confidence="call", source_url="https://x.com/a.js")
    d = ep.to_dict()
    assert d == {"path": "/api/x", "confidence": "call", "source_url": "https://x.com/a.js"}


# ---------------------------------------------------------------------------
# Real-world snippet smoke tests
# ---------------------------------------------------------------------------


def test_minified_fetch_snippet():
    snippet = (
        'n.get("/api/v1/user"),n.post("/api/v1/login",e),'
        'n.delete("/api/v1/session")'
    )
    r = _paths(snippet)
    assert "/api/v1/user" in r
    assert "/api/v1/login" in r
    assert "/api/v1/session" in r


def test_axios_instance_config():
    snippet = 'const api=axios.create({baseURL:"/api/v2",timeout:5e3})'
    r = _paths(snippet)
    assert "/api/v2" in r


def test_graphql_endpoint():
    snippet = 'fetch("/graphql",{method:"POST",body:JSON.stringify({query:e})})'
    r = _paths(snippet)
    assert "/graphql" in r
