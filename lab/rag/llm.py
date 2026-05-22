"""Gemini API client for the rule drafter.

Stdlib only -- no SDK dependency. Reads ``GEMINI_API_KEY`` from environment;
NEVER hardcoded. The key is sensitive; the conversation history we send
contains source citations (file paths + lines) but no secrets.

Why a thin client and not the google-generativeai SDK: this project is dep-
averse (Windows dev box, low setup tax), and the calls we make are simple
generateContent invocations. The SDK adds ~50 transitive deps for features
we don't use.

Gemini API endpoint shape:

    POST https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent?key=<KEY>
    Body: { "contents": [{"role": "user"|"model", "parts": [{"text": "..."}]}],
            "generationConfig": {...},
            "systemInstruction": {"parts":[{"text":"..."}]} }

We use roles ``user`` and ``model``. The drafter inserts tool results back
into the conversation as user messages tagged ``[tool_result name=...]`` so
the model can read them on the next turn -- no native function-calling
required, which keeps the code identical across Gemini and other providers.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# .env loader (stdlib, no python-dotenv dependency)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path = _REPO_ROOT / ".env") -> None:
    """Populate os.environ from a KEY=VALUE .env file at the repo root.

    Idempotent and non-destructive: existing env vars are NEVER overwritten
    (so shell-set keys still win). Silently skips if the file is missing or
    unreadable -- callers handle the GeminiError/AnthropicError that the
    __post_init__ check raises when a key is still absent.
    """
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Auto-run at import so any subprocess that imports lab.rag.llm picks up
# the keys without the caller having to remember to source .env.
_load_dotenv()


# ---------------------------------------------------------------------------
# Config loader (drives the per-client defaults below)
# ---------------------------------------------------------------------------

_CONFIG_FILE = Path(__file__).resolve().parent / "config.json"


def load_rag_config(path: Path = _CONFIG_FILE) -> dict:
    """Read lab/rag/config.json. Returns ``{}`` if missing/unreadable.

    Public so callers (judge, research_cycle) can pull their own sections
    without re-implementing the file read. Keys prefixed with ``_`` are
    documentation and are ignored.
    """
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


_CFG = load_rag_config()
_DRAFTER_CFG = _CFG.get("drafter") or {}
_JUDGE_CFG = _CFG.get("judge") or {}

DEFAULT_MODEL = _DRAFTER_CFG.get("model", "gemini-2.5-flash")
DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 4
DEFAULT_MIN_INTERVAL_SECS = float(_DRAFTER_CFG.get("min_interval_secs", 0.5))
# Regex to recover the server-suggested retry delay from a 429 body
# (Gemini emits it both as text and as a structured retryInfo block).
_RETRY_DELAY_RE = re.compile(r"retry in ([\d.]+)\s*s", re.IGNORECASE)


class GeminiError(RuntimeError):
    pass


@dataclass
class Message:
    role: str   # "user" | "model"
    text: str


@dataclass
class GeminiClient:
    model: str = DEFAULT_MODEL
    endpoint: str = DEFAULT_ENDPOINT
    api_key: str = field(default_factory=lambda: os.environ.get("GEMINI_API_KEY", ""))
    timeout: int = DEFAULT_TIMEOUT
    json_mode: bool = True
    # Defaults come from lab/rag/config.json. Override per-call by
    # passing the field explicitly to the constructor or via CLI.
    temperature: float = float(_DRAFTER_CFG.get("temperature", 0.2))
    max_output_tokens: int = int(_DRAFTER_CFG.get("max_output_tokens", 4096))
    # Minimum seconds between calls. Config-driven so swapping a 5-RPM
    # free-tier model for a 1K-RPM tier doesn't require code changes.
    min_interval_secs: float = DEFAULT_MIN_INTERVAL_SECS
    _last_call_at: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise GeminiError(
                "GEMINI_API_KEY is not set. Export it before invoking the drafter.\n"
                "  PowerShell:  $env:GEMINI_API_KEY = '<key>'\n"
                "  bash:        export GEMINI_API_KEY=<key>"
            )

    # ------------------------------------------------------------------
    # Single-shot generate
    # ------------------------------------------------------------------

    def _wait_for_slot(self) -> None:
        """Block until min_interval_secs has elapsed since the last call."""
        if self.min_interval_secs <= 0 or self._last_call_at == 0.0:
            return
        elapsed = time.monotonic() - self._last_call_at
        remaining = self.min_interval_secs - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def generate_text(self, text: str, *, system: str | None = None) -> str:
        """One-shot string-in/string-out adapter.

        Lets callers that only need a single turn (e.g. the judge) treat
        this client the same shape as ``AnthropicClient``. Wraps ``text``
        in a single user Message and delegates to ``generate``.
        """
        return self.generate([Message("user", text)], system=system)

    def generate(self, messages: list[Message],
                 *, system: str | None = None,
                 json_schema: dict | None = None) -> str:
        """Send a single generation request, return the raw text response.

        When ``json_mode`` is True (default), the API returns valid JSON
        parseable by ``json.loads`` (assuming the schema is satisfiable).
        The caller is responsible for ``json.loads`` and validation.
        """
        url = f"{self.endpoint}/models/{self.model}:generateContent?key={self.api_key}"
        body: dict[str, Any] = {
            "contents": [
                {"role": m.role, "parts": [{"text": m.text}]} for m in messages
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        if self.json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"
            if json_schema:
                body["generationConfig"]["responseSchema"] = json_schema

        data = json.dumps(body).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(MAX_RETRIES):
            # Proactive throttle so we don't post calls faster than RPM allows.
            self._wait_for_slot()
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                self._last_call_at = time.monotonic()
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                    return _extract_text(payload)
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
                    # Read body once so we can both parse retry hints AND
                    # surface the body if we exhaust retries.
                    err_body = ""
                    try:
                        err_body = e.read().decode("utf-8")[:1000]
                    except Exception:
                        pass
                    # Respect the API's retry suggestion when present; floor
                    # at min_interval_secs so we never poll faster than RPM.
                    server_hint = _parse_retry_delay(err_body)
                    backoff = max(
                        server_hint if server_hint is not None else 0.0,
                        self.min_interval_secs if e.code == 429 else 0.0,
                        1.5 * (2 ** attempt),
                    )
                    time.sleep(backoff)
                    continue
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8")[:500]
                except Exception:
                    pass
                raise GeminiError(f"Gemini HTTP {e.code}: {err_body}") from e
            except urllib.error.URLError as e:
                last_err = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1.0 * (2 ** attempt))
                    continue
                raise GeminiError(f"Gemini network error: {e}") from e
        raise GeminiError(f"Gemini retry budget exhausted: {last_err}")


def _parse_retry_delay(err_body: str) -> float | None:
    """Pull a retry-after suggestion out of a Gemini 429 body.

    Body usually contains both `"Please retry in 6.092104435s."` (in the
    message) and a `retryDelay` field inside a structured RetryInfo
    detail. We try the structured field first, then the plain-text form.
    Returns seconds, or None if neither shape is present.
    """
    if not err_body:
        return None
    try:
        data = json.loads(err_body)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        details = (data.get("error") or {}).get("details") or []
        for d in details:
            rd = d.get("retryDelay") if isinstance(d, dict) else None
            if isinstance(rd, str) and rd.endswith("s"):
                try:
                    return float(rd[:-1])
                except ValueError:
                    pass
    m = _RETRY_DELAY_RE.search(err_body)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _extract_text(payload: dict) -> str:
    """Pull the model's text out of the generateContent response.

    Response shape:
      {"candidates":[{"content":{"parts":[{"text":"..."}], "role":"model"}, ...}], ...}

    Defensive: API can return safety blocks (no parts) or partial responses.
    """
    candidates = payload.get("candidates") or []
    if not candidates:
        prompt_feedback = payload.get("promptFeedback") or {}
        raise GeminiError(
            f"Gemini returned no candidates. promptFeedback={prompt_feedback}"
        )
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts)
    if not text:
        finish_reason = candidates[0].get("finishReason", "?")
        raise GeminiError(f"Gemini returned empty text. finishReason={finish_reason}")
    return text


# ---------------------------------------------------------------------------
# Anthropic client (for the Judge step -- CLAUDE.md §12)
# ---------------------------------------------------------------------------

# Anthropic defaults pull from the same config block but only apply when
# the user explicitly selects provider='anthropic' in lab/rag/config.json.
_ANTHROPIC_MODEL_FROM_CFG = (
    _JUDGE_CFG.get("model") if _JUDGE_CFG.get("provider") == "anthropic"
    else "claude-sonnet-4-5"
)
DEFAULT_ANTHROPIC_MODEL = _ANTHROPIC_MODEL_FROM_CFG
DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com"


class AnthropicError(RuntimeError):
    pass


@dataclass
class AnthropicClient:
    """Thin Anthropic Messages-API client for the Sonnet judge.

    Same dep-averse posture as GeminiClient: stdlib HTTP, no SDK. Reads
    ANTHROPIC_API_KEY from env. Single-turn generate() suffices because
    the judge is a one-shot reviewer (read input -> emit verdict JSON).
    """
    model: str = DEFAULT_ANTHROPIC_MODEL
    endpoint: str = DEFAULT_ANTHROPIC_ENDPOINT
    api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    timeout: int = DEFAULT_TIMEOUT
    max_tokens: int = 1024
    temperature: float = 0.0  # judge wants determinism

    def __post_init__(self) -> None:
        if not self.api_key:
            raise AnthropicError(
                "ANTHROPIC_API_KEY is not set. Export it before invoking the judge.\n"
                "  PowerShell:  $env:ANTHROPIC_API_KEY = '<key>'\n"
                "  bash:        export ANTHROPIC_API_KEY=<key>"
            )

    def generate_text(self, text: str, *, system: str | None = None) -> str:
        """Alias matching GeminiClient.generate_text so callers can treat
        either client uniformly."""
        return self.generate(text, system=system)

    def generate(self, user_message: str, *, system: str | None = None) -> str:
        url = f"{self.endpoint}/v1/messages"
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": user_message}],
        }
        if system:
            body["system"] = system
        data = json.dumps(body).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(MAX_RETRIES):
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                    return _extract_anthropic_text(payload)
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
                    time.sleep(1.5 * (2 ** attempt))
                    continue
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8")[:500]
                except Exception:
                    pass
                raise AnthropicError(f"Anthropic HTTP {e.code}: {err_body}") from e
            except urllib.error.URLError as e:
                last_err = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1.0 * (2 ** attempt))
                    continue
                raise AnthropicError(f"Anthropic network error: {e}") from e
        raise AnthropicError(f"Anthropic retry budget exhausted: {last_err}")


def _extract_anthropic_text(payload: dict) -> str:
    """Pull text out of an Anthropic Messages API response.

    Response shape:
      {"content":[{"type":"text","text":"..."}], "stop_reason":"end_turn", ...}
    """
    content = payload.get("content") or []
    if not content:
        stop = payload.get("stop_reason", "?")
        raise AnthropicError(f"Anthropic returned no content. stop_reason={stop}")
    text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
    if not text:
        raise AnthropicError(f"Anthropic returned no text blocks. payload={payload!r}")
    return text
