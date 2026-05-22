"""AI-powered tech-version detection from pre-crawled web data.

Accepts JSONL produced by Crawl4AI (or any crawler that writes one HTTP
response per line) and feeds the raw content to an AI agent to identify
technologies and versions.  No live HTTP requests are made.

Supports two AI providers:
  openai    -- GitHub Copilot, GitHub Models, Azure OpenAI, or direct OpenAI.
               Env: OPENAI_API_KEY (or GITHUB_TOKEN), OPENAI_BASE_URL (optional).
  anthropic -- Anthropic Claude (legacy/fallback).
               Env: ANTHROPIC_API_KEY.

Provider is auto-selected: if OPENAI_API_KEY or GITHUB_TOKEN is set the openai
provider is used; otherwise anthropic is tried.  Override with --provider.

GitHub Copilot endpoints:
  GitHub Models (easiest):
    OPENAI_BASE_URL=https://models.inference.ai.azure.com
    OPENAI_API_KEY=<your GITHUB_TOKEN with models:read scope>
    model: gpt-4o-mini  (fast + cheap) or gpt-4o

Input format (one JSON object per line):
    {
      "url":         "https://example.com/page",   # required
      "html":        "...",                         # response body (HTML or JS)
      "headers":     {"content-type": "..."},       # HTTP response headers
      "status_code": 200                            # HTTP status (default 200)
    }

Output schema (one JSON object per target host, matches pipeline JSONL):
    {
      "target": "https://example.com",
      "techs": [
        {
          "name":               "WordPress",
          "version":            "6.4.3",
          "version_confidence": "exact",
          "categories":         ["CMS"],
          "sources":            ["ai-agent"],
          "evidence":           [{"source": "ai-agent", "url": "...", "quote": "..."}]
        }
      ],
      "stats": {
        "records_read":       12,
        "techs_total":         5,
        "techs_with_version":  4,
        "model":              "gpt-4o-mini",
        "provider":           "openai"
      }
    }
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from textwrap import shorten
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

MAX_HTML_CHARS = 6000
MAX_JS_CHARS = 2000
MAX_RECORDS_PER_TARGET = 15
MAX_CONTEXT_CHARS = 30000

_JS_EXT_RE = re.compile(r"\.(js|mjs|cjs)(\?|#|$)", re.IGNORECASE)
_JS_CT_RE = re.compile(
    r"(text|application)/javascript|application/x-javascript", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


@dataclass
class CrawlRecord:
    url: str
    body: str
    headers: dict[str, str]
    status: int
    is_js: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.is_js = _detect_js(self)


def _detect_js(rec: CrawlRecord) -> bool:
    for k, v in rec.headers.items():
        if k.lower() == "content-type":
            return bool(_JS_CT_RE.search(v or ""))
    return bool(_JS_EXT_RE.search(rec.url.split("?")[0]))


def _parse_record(raw: dict) -> CrawlRecord | None:
    url = raw.get("url") or raw.get("request_url") or raw.get("source_url") or ""
    if not url:
        return None
    body = (
        raw.get("html")
        or raw.get("body")
        or raw.get("content")
        or raw.get("cleaned_html")
        or raw.get("raw_html")
        or raw.get("resp_body")
        or ""
    )
    headers = raw.get("headers") or raw.get("response_headers") or raw.get("resp_headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    try:
        status = int(raw.get("status_code") or raw.get("status") or raw.get("resp_status") or 200)
    except (TypeError, ValueError):
        status = 200
    return CrawlRecord(url=url, body=body or "", headers=headers, status=status)


_URL_LINE_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)


def sniff_file_format(path: str | Path) -> str:
    """Return 'urls' if every non-blank non-comment line looks like a URL,
    otherwise 'jsonl'."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not _URL_LINE_RE.match(line):
                return "jsonl"
    return "urls"


def load_urls_from_file(path: str | Path) -> list[str]:
    """Read a plain URL list (one URL per line, # comments ignored)."""
    urls = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and _URL_LINE_RE.match(line):
                urls.append(line)
    return urls


def load_crawl_records(path: str | Path) -> list[CrawlRecord]:
    """Parse a JSONL/JSON file into CrawlRecord objects.

    Handles: one-object-per-line JSONL, a single JSON array, and Crawl4AI
    wrappers with a ``result`` or ``results`` key.
    """
    records: list[CrawlRecord] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                sys.stderr.write(f"warning: line {lineno}: JSON parse error: {exc}\n")
                continue

            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, dict):
                        rec = _parse_record(item)
                        if rec:
                            records.append(rec)
                continue

            if isinstance(raw, dict):
                inner = raw.get("result") or raw.get("results")
                if isinstance(inner, dict):
                    raw = inner
                elif isinstance(inner, list):
                    for item in inner:
                        if isinstance(item, dict):
                            rec = _parse_record(item)
                            if rec:
                                records.append(rec)
                    continue
                rec = _parse_record(raw)
                if rec:
                    records.append(rec)

    return records


def _target_key(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return url


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------


def _fmt_headers(headers: dict[str, str]) -> str:
    interesting = ("server", "x-", "content-type", "set-cookie", "via", "powered-by", "generator")
    lines = [
        f"  {k}: {shorten(v, 120, placeholder='...')}"
        for k, v in headers.items()
        if any(k.lower().startswith(p) for p in interesting)
    ]
    return "\n".join(lines) or "  (none)"


def _head_snippet(html: str, max_chars: int) -> str:
    m = re.search(r"<head\b[^>]*>(.*?)</head>", html, re.IGNORECASE | re.DOTALL)
    if m:
        s = m.group(0)
        return s[:max_chars] + "\n...[truncated]" if len(s) > max_chars else s
    return html[:max_chars] + ("\n...[truncated]" if len(html) > max_chars else "")


def build_context(target: str, records: list[CrawlRecord]) -> str:
    """Compose a compact text context for the AI agent from crawled records."""
    parts: list[str] = [f"Target: {target}\n"]
    total_chars = len(parts[0])

    for i, rec in enumerate(records[:MAX_RECORDS_PER_TARGET]):
        if total_chars >= MAX_CONTEXT_CHARS:
            remaining = len(records) - i
            parts.append(f"\n[{remaining} more records omitted: context size limit reached]")
            break
        section = [f"\n--- URL: {rec.url}  (HTTP {rec.status}) ---"]
        section.append(f"Headers:\n{_fmt_headers(rec.headers)}")
        if rec.body:
            if rec.is_js:
                snippet = rec.body[:MAX_JS_CHARS]
                if len(rec.body) > MAX_JS_CHARS:
                    snippet += "\n...[truncated]"
                section.append(f"JS content:\n{snippet}")
            else:
                section.append(f"HTML head:\n{_head_snippet(rec.body, MAX_HTML_CHARS)}")
        block = "\n".join(section)
        total_chars += len(block)
        parts.append(block)

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Shared tool definition (converted per-provider at call time)
# ---------------------------------------------------------------------------

_TOOL_NAME = "report_technologies"

_TOOL_DESCRIPTION = "Report all technologies and their versions found in the crawled web data."

_TOOL_PARAMETERS = {
    "type": "object",
    "properties": {
        "techs": {
            "type": "array",
            "description": "List of detected technologies.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Technology name, e.g. 'WordPress', 'jQuery', 'Nginx'.",
                    },
                    "version": {
                        "type": "string",
                        "description": "Exact or approximate version string. Omit if not found.",
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["exact", "approx", "none"],
                        "description": (
                            "exact: version string directly found in the data. "
                            "approx: version inferred from partial signal. "
                            "none: tech identified but no version signal."
                        ),
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Short quote or explanation of where/how this was detected.",
                    },
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Category tags. Examples: CMS, web-server, javascript-framework, "
                            "javascript-library, programming-language, database, cdn, analytics."
                        ),
                    },
                },
                "required": ["name", "confidence", "evidence", "categories"],
            },
        },
    },
    "required": ["techs"],
}

_SYSTEM_PROMPT = """\
You are a web technology fingerprinting expert. You receive raw data crawled
from a website (HTTP headers, HTML head sections, JavaScript snippets, URL
lists) and must identify every technology and version present.

Detection signals to check:
- HTTP headers: Server, X-Powered-By, X-Generator, Via, set-cookie names
- HTML meta tags: generator, application-name
- HTML script src attributes: library filenames and version query params (e.g. ?ver=3.7.1)
- JavaScript banner comments: /*! jQuery v3.7.1 ... */ or similar
- Version variables in JS: version = "x.y.z", __VERSION__, VERSION_STRING
- URL path clues: /wp-content/, /wp-includes/, /_next/, /nuxt/, /django-static/
- Cookie names that reveal platforms: PHPSESSID, laravel_session, JSESSIONID, PrestaShop-*

Rules:
- Only report what you can directly observe -- no guessing.
- Use canonical tech names (e.g. "jQuery" not "jquery.min.js").
- Report each tech once with the best version and evidence found.
- confidence="exact" means a clear version string like "6.4.3" was present.
  confidence="approx" means a major.minor was inferred.
  confidence="none" means the tech was detected but no version was visible.
"""

_USER_PROMPT_TMPL = """\
Analyze the crawled web data below and call report_technologies with every \
technology and version you find.

{context}
"""


# ---------------------------------------------------------------------------
# Provider backends
# ---------------------------------------------------------------------------


def _call_openai(
    context: str, model: str, api_key: str, base_url: str | None
) -> list[dict]:
    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")

    client = OpenAI(api_key=api_key, base_url=base_url or None)

    tool_def = {
        "type": "function",
        "function": {
            "name": _TOOL_NAME,
            "description": _TOOL_DESCRIPTION,
            "parameters": _TOOL_PARAMETERS,
        },
    }

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _USER_PROMPT_TMPL.format(context=context)},
        ],
        tools=[tool_def],
        tool_choice={"type": "function", "function": {"name": _TOOL_NAME}},
    )

    for choice in response.choices:
        for call in getattr(choice.message, "tool_calls", None) or []:
            if call.function.name == _TOOL_NAME:
                try:
                    return json.loads(call.function.arguments).get("techs", [])
                except json.JSONDecodeError:
                    pass
    return []


def _call_anthropic(context: str, model: str, api_key: str) -> list[dict]:
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=api_key)

    tool_def = {
        "name": _TOOL_NAME,
        "description": _TOOL_DESCRIPTION,
        "input_schema": _TOOL_PARAMETERS,
    }

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        tools=[tool_def],
        tool_choice={"type": "tool", "name": _TOOL_NAME},
        messages=[{"role": "user", "content": _USER_PROMPT_TMPL.format(context=context)}],
    )

    for block in message.content:
        if block.type == "tool_use" and block.name == _TOOL_NAME:
            return block.input.get("techs", [])
    return []


def _resolve_provider(provider: str | None, api_key: str | None, base_url: str | None):
    """Return (provider, api_key, base_url, model_default)."""
    if provider == "openai" or provider == "copilot":
        key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("GITHUB_TOKEN") or ""
        if not key:
            raise RuntimeError(
                "openai provider requires OPENAI_API_KEY or GITHUB_TOKEN env var."
            )
        url = base_url or os.environ.get("OPENAI_BASE_URL") or None
        return "openai", key, url, DEFAULT_OPENAI_MODEL

    if provider == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY") or ""
        if not key:
            raise RuntimeError("anthropic provider requires ANTHROPIC_API_KEY env var.")
        return "anthropic", key, None, DEFAULT_ANTHROPIC_MODEL

    # Auto-detect
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("GITHUB_TOKEN"):
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GITHUB_TOKEN") or ""
        url = base_url or os.environ.get("OPENAI_BASE_URL") or None
        return "openai", key, url, DEFAULT_OPENAI_MODEL

    if os.environ.get("ANTHROPIC_API_KEY"):
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        return "anthropic", key, None, DEFAULT_ANTHROPIC_MODEL

    raise RuntimeError(
        "No AI provider configured. Set one of:\n"
        "  OPENAI_API_KEY   (OpenAI / GitHub Copilot via GitHub Models)\n"
        "  GITHUB_TOKEN     (GitHub Models -- also set OPENAI_BASE_URL)\n"
        "  ANTHROPIC_API_KEY  (Anthropic Claude)\n"
        "Or pass --provider and --api-key explicitly."
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _build_output(
    target: str,
    ai_techs: list[dict],
    n_records: int,
    model: str,
    provider: str,
) -> dict:
    techs_out = []
    for t in ai_techs:
        name = (t.get("name") or "").strip()
        if not name:
            continue
        version = t.get("version") or None
        confidence = t.get("confidence") or "none"
        evidence_text = t.get("evidence") or ""
        categories = t.get("categories") or []

        version_confidence: str | None = None
        if version:
            version_confidence = "exact" if confidence == "exact" else "approx"

        techs_out.append({
            "name": name,
            "version": version,
            "version_confidence": version_confidence,
            "categories": sorted(set(categories)),
            "sources": ["ai-agent"],
            "evidence": [{
                "source": "ai-agent",
                "url": target,
                "quote": evidence_text,
                "confidence": confidence,
            }],
        })

    techs_out.sort(key=lambda t: (t["version"] is None, t["name"].lower()))

    return {
        "target": target,
        "techs": techs_out,
        "stats": {
            "records_read": n_records,
            "techs_total": len(techs_out),
            "techs_with_version": sum(1 for t in techs_out if t["version"]),
            "model": model,
            "provider": provider,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_detect_version(
    input_path: str | Path,
    *,
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> list[dict]:
    """Load crawl file, call AI per target host, return one output record each."""
    resolved_provider, resolved_key, resolved_base, default_model = _resolve_provider(
        provider, api_key, base_url
    )
    resolved_model = model or os.environ.get("DETECT_VERSION_MODEL") or default_model

    records = load_crawl_records(input_path)
    if not records:
        sys.stderr.write(f"warning: no records parsed from {input_path}\n")
        return []

    by_target: dict[str, list[CrawlRecord]] = {}
    for rec in records:
        by_target.setdefault(_target_key(rec.url), []).append(rec)

    output: list[dict] = []
    for target, recs in by_target.items():
        sys.stderr.write(
            f"[detect-version] {target}: {len(recs)} record(s)"
            f" -> {resolved_provider}/{resolved_model} ...\n"
        )
        context = build_context(target, recs)
        try:
            if resolved_provider == "openai":
                ai_techs = _call_openai(context, resolved_model, resolved_key, resolved_base)
            else:
                ai_techs = _call_anthropic(context, resolved_model, resolved_key)
        except Exception as exc:
            sys.stderr.write(f"[detect-version] {target}: AI call failed: {exc}\n")
            ai_techs = []
        output.append(_build_output(target, ai_techs, len(recs), resolved_model, resolved_provider))

    return output
