"""Uniform result type returned by every fetcher implementation."""

from __future__ import annotations

from dataclasses import dataclass, field


MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB - matches retirejs cap in scanner


@dataclass
class FetchResult:
    """Outcome of a single fetch.

    `status_tag` values:
      - "ok_body"  - 2xx with non-empty body. Use `body` + `headers`.
      - "empty"    - 2xx but empty body.
      - "http_4xx" / "http_5xx" - server error status.
      - "blocked"  - vendor block / challenge page detected. `error` holds
                     the vendor label ("cloudflare:interstitial", etc.).
      - "error"    - network / TLS / timeout. `error` holds the message.
    """

    status_tag: str
    http_status: int | None = None
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    error: str | None = None

    @property
    def is_ok(self) -> bool:
        return self.status_tag == "ok_body"

    @property
    def is_blocked(self) -> bool:
        return self.status_tag == "blocked"
