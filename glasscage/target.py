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
import ssl
import time
import urllib.error
import urllib.parse
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


class _ScopeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only if the target host stays within scope."""

    def __init__(self, allowed_host: str):
        self._allowed = allowed_host.lower()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.hostname and parsed.hostname.lower() != self._allowed:
            from .errors import ConfigError
            raise ConfigError(
                f"redirect to {parsed.hostname} blocked (out of scope; "
                f"only {self._allowed} is allowed)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_proxy_opener(
    proxy_url: str, no_verify: bool = False,
) -> urllib.request.OpenerDirector:
    """Build an opener that routes all traffic through a proxy."""
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    handlers: list = [handler]
    if no_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


class HTTPChatTarget:
    """Configurable adapter for a black-box chat endpoint.

    Config keys:
      url            : endpoint URL
      method         : HTTP method (default POST)
      headers        : dict of headers (put auth tokens here)
      body_template  : JSON body with "{{PROMPT}}" where the user message goes
      response_path  : dot path to the assistant text in the JSON response
      timeout        : seconds (default 30)
      proxy          : HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080 for Burp)
      proxy_no_verify: disable SSL verification when proxying (needed for Burp's
                       intercepting CA unless the cert is installed system-wide)
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
        self.max_retries: int = int(config.get("max_retries", 3))
        self.backoff_base: float = float(config.get("backoff_base", 2.0))
        self._proxy: str | None = config.get("proxy")
        self._proxy_no_verify: bool = bool(config.get("proxy_no_verify", False))
        self._opener: urllib.request.OpenerDirector | None = None
        if self._proxy:
            self._opener = _build_proxy_opener(self._proxy, self._proxy_no_verify)
        parsed = urllib.parse.urlparse(self.url)
        self._redirect_handler = _ScopeRedirectHandler(parsed.hostname or "")
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
        import logging
        _log = logging.getLogger("glasscage.target")

        if self.scope is not None:
            self.scope.check(self.url)          # refuse out-of-scope hosts
        if self.rate is not None:
            self.rate.wait()                    # be a polite tester
        body = _inject(self.body_template, prompt)
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.headers}

        from datetime import datetime, timezone
        _RETRYABLE = (429, 402)

        for attempt in range(1 + self.max_retries):
            req = urllib.request.Request(self.url, data=data, headers=headers, method=self.method)
            ts = datetime.now(timezone.utc).isoformat()
            start = time.perf_counter()
            resp_obj = None
            try:
                if self._opener:
                    _open = self._opener.open
                else:
                    _open = urllib.request.build_opener(self._redirect_handler).open
                with _open(req, timeout=self.timeout) as resp:
                    raw_bytes = resp.read()
                    status_code = resp.status
                latency = (time.perf_counter() - start) * 1000
                body_text = raw_bytes.decode("utf-8", "replace")
                raw = json.loads(body_text)
                try:
                    text = _dig(raw, self.response_path)
                except (KeyError, IndexError, ValueError) as e:
                    resp_obj = ChatResponse("", raw, latency, ok=False,
                                            error=f"response_path '{self.response_path}' failed: {e}")
                else:
                    if not isinstance(text, str):
                        text = json.dumps(text)
                    resp_obj = ChatResponse(text, raw, latency, ok=True)
                status = status_code
                break
            except urllib.error.HTTPError as e:
                latency = (time.perf_counter() - start) * 1000
                status, body_text = e.code, str(e.reason)
                if e.code in _RETRYABLE and attempt < self.max_retries:
                    retry_after = e.headers.get("Retry-After") if hasattr(e, "headers") else None
                    if retry_after and retry_after.isdigit():
                        wait = int(retry_after)
                    else:
                        wait = self.backoff_base ** (attempt + 1)
                    _log.info("HTTP %d on attempt %d/%d, retrying in %.1fs",
                              e.code, attempt + 1, 1 + self.max_retries, wait)
                    time.sleep(wait)
                    continue
                resp_obj = ChatResponse("", None, latency, ok=False, error=f"HTTP {e.code}: {e.reason}")
                break
            except Exception as e:
                latency = (time.perf_counter() - start) * 1000
                resp_obj = ChatResponse("", None, latency, ok=False, error=str(e))
                status, body_text = 0, str(e)
                break
        self._record(ts, data, status, body_text, latency, resp_obj)
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
