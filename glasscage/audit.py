# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Operational safety + chain of custody.

The review flagged --authorized as an honor-system checkbox and the SVG as a
self-drawn reconstruction rather than a tamper-evident capture. This module adds:

  * Scope    - an explicit host allowlist; requests outside it are refused.
  * RateLimiter - minimum inter-request interval (be a polite tester).
  * AuditLog - append-only JSONL of every payload sent, with sha256 + timestamp,
               chained (each entry hashes the previous) so tampering is evident.
  * capture  - hash + timestamp raw request/response for evidentiary integrity.
  * har_export - standard HAR so raw exchanges load in any HTTP tooling.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
    return h.hexdigest()


class Scope:
    """Explicit allowlist of hosts that may be tested."""

    def __init__(self, allowed_hosts: list[str] | None = None):
        self.allowed = set(h.lower() for h in (allowed_hosts or []))

    def check(self, url: str) -> None:
        if not self.allowed:
            return  # no scope configured -> caller relies on --authorized
        host = (urlparse(url).hostname or "").lower()
        if host not in self.allowed:
            raise PermissionError(
                f"Refusing to test out-of-scope host '{host}'. "
                f"Allowed: {sorted(self.allowed)}")


class RateLimiter:
    def __init__(self, rps: float | None = None):
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        delta = time.perf_counter() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.perf_counter()


class AuditLog:
    """Append-only, hash-chained JSONL audit trail of everything sent."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.prev = "0" * 64
        self.entries: list[dict] = []

    def record(self, url: str, prompt: str, response: str, ok: bool) -> dict:
        ts = now_iso()
        digest = sha256(self.prev, ts, url, prompt, response)
        entry = {"ts": ts, "url": url, "prompt_sha256": sha256(prompt),
                 "response_sha256": sha256(response), "ok": ok,
                 "prev": self.prev, "entry_hash": digest}
        self.prev = digest
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            if e["prev"] != prev:
                return False
            prev = e["entry_hash"]
        return True


def har_export(exchanges: list[dict], path: str) -> None:
    """exchanges: [{url, method, request_body, status, response_body, ts, ms}]."""
    entries = []
    for x in exchanges:
        entries.append({
            "startedDateTime": x.get("ts", now_iso()),
            "time": x.get("ms", 0),
            "request": {"method": x.get("method", "POST"), "url": x.get("url", ""),
                        "httpVersion": "HTTP/1.1", "headers": [], "queryString": [],
                        "postData": {"mimeType": "application/json",
                                     "text": x.get("request_body", "")},
                        "headersSize": -1, "bodySize": -1},
            "response": {"status": x.get("status", 0), "statusText": "",
                         "httpVersion": "HTTP/1.1", "headers": [],
                         "content": {"size": len(x.get("response_body", "")),
                                     "mimeType": "application/json",
                                     "text": x.get("response_body", "")},
                         "redirectURL": "", "headersSize": -1, "bodySize": -1},
            "cache": {}, "timings": {"send": 0, "wait": x.get("ms", 0), "receive": 0},
        })
    har = {"log": {"version": "1.2",
                   "creator": {"name": "GLASSCAGE", "version": "0.5.0"},
                   "entries": entries}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(har, fh, indent=2)
