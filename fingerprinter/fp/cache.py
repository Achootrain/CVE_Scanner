"""Build a fast in-memory scan cache from the SQLite fingerprint DB.

Cache shape (JSON-serialisable)::

    {
      "templates":   {template_pk: {id, name, vendor, product, category, tags, cpe}},
      "requests":    [{pk, template_pk, method, paths:[...], matchers_condition,
                       stop_at_first_match, matchers:[...], extractors:[...]}],
      "by_path":     {"/":       [req_pk, ...],
                      "/feed/":  [req_pk, ...]},
      "stats":       {templates, requests, paths, matchers, extractors},
    }

Each matcher is pre-normalised to ``{type, name, part, condition, negative, values}``
with ``values`` already lowered/compiled where useful.  Scanners consume this
structure directly — there is no further SQL access on the hot path.

The cache can be saved to disk (`dump_cache`) and reloaded cheaply, but since
"in-memory" is the objective we also expose `build_cache` which returns the
dict directly.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_BASEURL_RE = re.compile(r"\{\{\s*BaseURL\s*\}\}", re.IGNORECASE)


def _path_from_template(path_template: str) -> str:
    """Strip ``{{BaseURL}}`` and return the path portion (with query) only.

    ``{{BaseURL}}``            -> ``/``
    ``{{BaseURL}}/wp-login``   -> ``/wp-login``
    ``https://x.example/a?b=1`` -> ``/a?b=1`` (absolute paths are accepted)
    """
    stripped = _BASEURL_RE.sub("", path_template).strip()
    if not stripped:
        return "/"
    if stripped.startswith("http://") or stripped.startswith("https://"):
        parts = urlsplit(stripped)
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if not stripped.startswith("/"):
        stripped = "/" + stripped
    return stripped


def _normalise_matcher(row: sqlite3.Row) -> dict[str, Any]:
    payload = json.loads(row["payload"]) if row["payload"] else {}
    mtype = row["type"]
    case_insensitive = bool(payload.get("case-insensitive"))
    out: dict[str, Any] = {
        "type": mtype,
        "name": row["name"],
        "part": row["part"],
        "condition": row["condition"],
        "negative": bool(row["negative"]),
        "case_insensitive": case_insensitive,
    }
    if mtype == "word":
        # Nuclei word matchers are case-sensitive unless `case-insensitive: true`.
        words = [str(w) for w in (payload.get("words") or [])]
        out["values"] = [w.lower() for w in words] if case_insensitive else words
    elif mtype == "regex":
        out["values"] = list(payload.get("regex") or [])
    elif mtype == "status":
        out["values"] = [int(s) for s in (payload.get("status") or [])]
    elif mtype == "kval":
        # `kval` targets header keys — Nuclei accepts Server, Content-Type, etc.
        # Lowercase + normalise '-' <-> '_' for consistent lookups.
        out["values"] = [
            str(k).lower().replace("_", "-") for k in (payload.get("kval") or [])
        ]
    elif mtype == "binary":
        out["values"] = list(payload.get("binary") or [])
    elif mtype == "dsl":
        out["values"] = list(payload.get("dsl") or [])
    else:
        out["values"] = payload
    return out


def _normalise_extractor(row: sqlite3.Row) -> dict[str, Any]:
    payload = json.loads(row["payload"]) if row["payload"] else {}
    etype = row["type"]
    out: dict[str, Any] = {
        "type": etype,
        "name": row["name"],
        "part": row["part"],
        "group": row["group_val"] or 0,
    }
    if etype == "regex":
        out["values"] = list(payload.get("regex") or [])
    elif etype == "kval":
        out["values"] = [
            str(k).lower().replace("_", "-") for k in (payload.get("kval") or [])
        ]
    elif etype == "json":
        out["values"] = list(payload.get("json") or [])
    elif etype == "xpath":
        out["values"] = list(payload.get("xpath") or [])
    else:
        out["values"] = payload
    return out


def build_cache(db_path: str | Path) -> dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    templates: dict[int, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT id, template_id, name, author, severity, vendor, product, "
        "       category, cpe, tags, verified, max_request, file_path "
        "FROM templates"
    ):
        templates[row["id"]] = {
            "pk": row["id"],
            "id": row["template_id"],
            "name": row["name"],
            "author": row["author"],
            "severity": row["severity"],
            "vendor": row["vendor"],
            "product": row["product"],
            "category": row["category"],
            "cpe": row["cpe"],
            "tags": (row["tags"] or "").split(",") if row["tags"] else [],
            "verified": bool(row["verified"]),
            "file_path": row["file_path"],
        }

    requests_by_pk: dict[int, dict[str, Any]] = {}
    by_path: dict[str, list[int]] = {}

    for req in conn.execute(
        "SELECT id, template_id, method, headers_json, body, redirects, "
        "       host_redirects, max_redirects, stop_at_first_match, matchers_condition "
        "FROM requests"
    ):
        req_pk = req["id"]
        paths = [
            _path_from_template(r["path"])
            for r in conn.execute(
                "SELECT path FROM paths WHERE request_id=? ORDER BY idx", (req_pk,)
            )
        ]
        matchers = [
            _normalise_matcher(r)
            for r in conn.execute(
                "SELECT type, name, part, condition, negative, payload "
                "FROM matchers WHERE request_id=? ORDER BY idx",
                (req_pk,),
            )
        ]
        extractors = [
            _normalise_extractor(r)
            for r in conn.execute(
                "SELECT type, name, part, group_val, payload "
                "FROM extractors WHERE request_id=? ORDER BY idx",
                (req_pk,),
            )
        ]
        requests_by_pk[req_pk] = {
            "pk": req_pk,
            "template_pk": req["template_id"],
            "method": req["method"],
            "headers": json.loads(req["headers_json"]) if req["headers_json"] else {},
            "body": req["body"],
            "redirects": bool(req["redirects"] or req["host_redirects"]),
            "max_redirects": req["max_redirects"] or 0,
            "stop_at_first_match": bool(req["stop_at_first_match"]),
            "matchers_condition": req["matchers_condition"] or "or",
            "paths": paths,
            "matchers": matchers,
            "extractors": extractors,
        }
        for p in paths:
            by_path.setdefault(p, []).append(req_pk)

    stats = {
        "templates": len(templates),
        "requests": len(requests_by_pk),
        "paths": sum(len(r["paths"]) for r in requests_by_pk.values()),
        "matchers": sum(len(r["matchers"]) for r in requests_by_pk.values()),
        "extractors": sum(len(r["extractors"]) for r in requests_by_pk.values()),
        "unique_paths": len(by_path),
    }

    conn.close()
    return {
        "templates": templates,
        "requests": requests_by_pk,
        "by_path": by_path,
        "stats": stats,
    }


def dump_cache(cache: dict, out_path: str | Path) -> None:
    # JSON keys must be strings — int keys get serialised transparently here because
    # we round-trip them to str on save / int on load.
    serialisable = {
        "templates": {str(k): v for k, v in cache["templates"].items()},
        "requests": {str(k): v for k, v in cache["requests"].items()},
        "by_path": cache["by_path"],
        "stats": cache["stats"],
    }
    Path(out_path).write_text(json.dumps(serialisable, ensure_ascii=False, indent=2), encoding="utf-8")


def load_cache(path: str | Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "templates": {int(k): v for k, v in raw["templates"].items()},
        "requests": {int(k): v for k, v in raw["requests"].items()},
        "by_path": raw["by_path"],
        "stats": raw["stats"],
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python -m fp.cache <db_path> [out_cache.json]")
        raise SystemExit(2)
    cache = build_cache(sys.argv[1])
    if len(sys.argv) >= 3:
        dump_cache(cache, sys.argv[2])
    print(json.dumps(cache["stats"], indent=2))
