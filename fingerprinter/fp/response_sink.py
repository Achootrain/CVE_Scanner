"""HTTP response archiver for AI training data collection.

Saves (response body, tech label) pairs to JSONL for each scanned target.
Each target gets its own file pair inside ``out_dir``:

  - ``<slug>.responses.jsonl`` -- raw HTTP responses (base64-encoded body)
  - ``<slug>.labels.jsonl``    -- tech/version labels keyed by body SHA1

The join key across both files is ``id`` (SHA1 of the raw response body).
Responses are deduplicated globally by body SHA1 so CDN-identical assets
served across thousands of sites count as one training example.

Excluded from labels: jsextract, bundle-leak, backend-probe detections
(those are endpoint/topology discoveries, not technology fingerprints).
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .scanner import Detection, FetchedResponse


class ResponseSink:
    """Write (response, labels) JSONL pairs for AI training data collection.

    Thread-safe and asyncio-safe. Concurrent targets each get their own
    file pair; the global SHA1 dedup set is protected by a lock.
    """

    _SKIP_SOURCES = frozenset({"jsextract", "bundle-leak", "backend-probe"})

    def __init__(self, out_dir: str | Path) -> None:
        self._dir = Path(out_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._handles: dict[str, tuple] = {}

    def _get_handles(self, target: str):
        if target not in self._handles:
            slug = _target_slug(target)
            rf = (self._dir / f"{slug}.responses.jsonl").open("a", encoding="utf-8")
            lf = (self._dir / f"{slug}.labels.jsonl").open("a", encoding="utf-8")
            self._handles[target] = (rf, lf)
        return self._handles[target]

    def record(
        self,
        resp: "FetchedResponse",
        detections: list["Detection"],
        target: str,
        request_headers: dict[str, str],
    ) -> None:
        """Archive one response + its tech labels.

        Skips: error responses, empty bodies, duplicate bodies (SHA1),
        and records whose only detections are non-tech sources.
        """
        if resp.error or not resp.body:
            return
        labels = [
            {
                "tech": d.name,
                "version": d.version,
                "source": d.source,
                "template_id": d.template_id,
                "confidence": d.confidence,
            }
            for d in detections
            if d.source not in self._SKIP_SOURCES
        ]
        if not labels:
            return

        sha1 = hashlib.sha1(resp.body).hexdigest()
        ts = datetime.now(timezone.utc).isoformat()

        with self._lock:
            if sha1 in self._seen:
                return
            self._seen.add(sha1)
            rf, lf = self._get_handles(target)
            rf.write(json.dumps({
                "id": sha1,
                "url": resp.url,
                "status": resp.status,
                "request_headers": request_headers,
                "response_headers": dict(resp.headers),
                "content_type": resp.headers.get("Content-Type", ""),
                "body_size": len(resp.body),
                "body_b64": base64.b64encode(resp.body).decode(),
                "target": target,
                "timestamp": ts,
            }) + "\n")
            rf.flush()
            lf.write(json.dumps({
                "id": sha1,
                "url": resp.url,
                "target": target,
                "labels": labels,
            }) + "\n")
            lf.flush()

    def close(self) -> None:
        with self._lock:
            for rf, lf in self._handles.values():
                rf.close()
                lf.close()
            self._handles.clear()

    def __enter__(self) -> "ResponseSink":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _target_slug(target: str) -> str:
    parts = urlsplit(target if "://" in target else "https://" + target)
    host = (parts.netloc or parts.path)
    return host.replace(":", "_").replace("/", "_").replace(".", "_")[:80]
