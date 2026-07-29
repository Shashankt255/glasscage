# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Target adapters.

HTTPChatTarget speaks to any HTTP chat endpoint (OpenAI-style, Anthropic-style,
or a custom bot) using a configurable request template and a dot-path to pull the
assistant's text out of the JSON response. Zero third-party dependencies: uses the
standard library only, so it runs anywhere Python does.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

PROMPT_PLACEHOLDER = "{{PROMPT}}"


@dataclass
class ChatResponse:
    text: str
    raw: Any
    latency_ms: float
    ok: bool
    error: str | None = None
    trace: dict | None = None   # L2+: {plan, tool_calls, memory, retrieval}


def _dig(obj: Any, path: str) -> Any:
    """Extract a value via a dot path, supporting list indices e.g. choices.0.message.content."""
    cur = obj
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"cannot descend into {type(cur).__name__} with '{part}'")
    return cur


def _inject(template: Any, prompt: str) -> Any:
    """Recursively replace the PROMPT placeholder inside a JSON-like body template."""
    if isinstance(template, str):
        return template.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(template, list):
        return [_inject(x, prompt) for x in template]
    if isinstance(template, dict):
        return {k: _inject(v, prompt) for k, v in template.items()}
    return template


class HTTPChatTarget:
    """Configurable adapter for a black-box chat endpoint.

    Config keys:
      url            : endpoint URL
      method         : HTTP method (default POST)
      headers        : dict of headers (put auth tokens here)
      body_template  : JSON body with "{{PROMPT}}" where the user message goes
      response_path  : dot path to the assistant text in the JSON response
      timeout        : seconds (default 30)
    """

    def __init__(self, config: dict[str, Any]):
        from .config import validate_target_config
        config = validate_target_config(config)
        self.url: str = config["url"]
        self.method: str = config.get("method", "POST").upper()
        self.headers: dict[str, str] = config.get("headers", {})
        self.body_template: Any = config.get("body_template", {"prompt": PROMPT_PLACEHOLDER})
        self.response_path: str = config.get("response_path", "response")
        self.timeout: float = float(config.get("timeout", 30))
        self.name: str = config.get("name", self.url)
        # Stage A: capability tier. A plain HTTP chat endpoint is L0 unless the
        # integrator declares it maintains session state across calls.
        from .tal import TargetCapabilities
        self.capabilities = TargetCapabilities(stateful=bool(config.get("stateful", False)))
        # operational safety + chain of custody (set by the engine/CLI)
        self.scope = None          # audit.Scope
        self.rate = None           # audit.RateLimiter
        self.audit = None          # audit.AuditLog
        self.exchanges: list = []  # raw request/response records for HAR

    def send(self, prompt: str) -> ChatResponse:
        if self.scope is not None:
            self.scope.check(self.url)          # refuse out-of-scope hosts
        if self.rate is not None:
            self.rate.wait()                    # be a polite tester
        body = _inject(self.body_template, prompt)
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(self.url, data=data, headers=headers, method=self.method)

        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        start = time.perf_counter()
        resp_obj = None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read()
                status_code = resp.status
            latency = (time.perf_counter() - start) * 1000
            raw = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            try:
                text = _dig(raw, self.response_path)
            except (KeyError, IndexError, ValueError) as e:
                resp_obj = ChatResponse("", raw, latency, ok=False,
                                        error=f"response_path '{self.response_path}' failed: {e}")
            else:
                if not isinstance(text, str):
                    text = json.dumps(text)
                resp_obj = ChatResponse(text, raw, latency, ok=True)
            self._record(ts, data, status_code, raw_bytes.decode("utf-8", "replace"),
                         latency, resp_obj)
            return resp_obj
        except urllib.error.HTTPError as e:
            latency = (time.perf_counter() - start) * 1000
            resp_obj = ChatResponse("", None, latency, ok=False, error=f"HTTP {e.code}: {e.reason}")
            self._record(ts, data, e.code, str(e.reason), latency, resp_obj)
            return resp_obj
        except Exception as e:  # noqa: BLE001 - report any transport error to caller
            latency = (time.perf_counter() - start) * 1000
            resp_obj = ChatResponse("", None, latency, ok=False, error=str(e))
            self._record(ts, data, 0, str(e), latency, resp_obj)
            return resp_obj

    def _record(self, ts, req_bytes, status, resp_text, ms, resp_obj) -> None:
        req_body = req_bytes.decode("utf-8", "replace") if isinstance(req_bytes, bytes) else str(req_bytes)
        self.exchanges.append({
            "ts": ts, "url": self.url, "method": self.method,
            "request_body": req_body, "status": status,
            "response_body": resp_text, "ms": round(ms, 1),
        })
        if self.audit is not None:
            self.audit.record(self.url, req_body, resp_text, resp_obj.ok if resp_obj else False)
