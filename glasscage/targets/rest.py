# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""RestTarget / RestDriver: the first non-chat runtime driver (ADR 0012).

Consumes `HttpAction` (ADR 0007), declares the target it drives (ADR 0005), attaches
custody to every observation (ADR 0008), and enforces the operational controls it holds.

Fail closed on scope. `audit.Scope.check()` returns silently on an empty allowlist, so a
REST surface requires a *non-empty* Scope: possession alone is not enough. The reason is
ADR 0014's accepted limitation, recorded by ADR 0015 - binding does not verify that the
supplied target's host matches the discovered document, so the allowlist is the only
control between a mis-paired binding and traffic to a host the operator never named. Chat
keeps its optional scope because its target is one configured endpoint rather than
operations discovered from a separate document; the asymmetry is deliberate.

The driver hashes but does not record twice: `Observation.custody_hash` is the driver's
attestation (ADR 0008), and `audit.record` is called once per request because, unlike
chat, there is no `HTTPChatTarget.send()` beneath it already doing so.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ..audit import sha256
from ..errors import TargetError
from .driver import HttpAction, Observation
from .surface import Surface, SurfaceKind


def canonical_request(action: HttpAction, url: str) -> str:
    """The canonical serialization of one REST request (ADR 0012 R2).

    One format serves three consumers: custody hashing, Finding identity via the subject
    digest, and reproduction. Every ordering is total, so the same request always
    produces the same string - no timestamps, no dict iteration order, no locale.

        <METHOD> <url>[?<sorted query>]
        <lowercased header>: <value>        one per line, sorted
                                            blank line
        <canonical body>
    """
    line = f"{action.method.upper()} {url}"
    if action.query:
        pairs = sorted((str(k), str(v)) for k, v in action.query.items())
        line += "?" + "&".join(f"{k}={v}" for k, v in pairs)
    headers = sorted((str(k).lower(), str(v)) for k, v in (action.headers or {}).items())
    head = "\n".join(f"{k}: {v}" for k, v in headers)
    body = action.body
    if body is None:
        body_s = ""
    elif isinstance(body, str):
        body_s = body
    else:
        body_s = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "\n".join([line, head, "", body_s])


class RestTarget:
    """A REST endpoint under test: transport configuration plus operational controls.

    Mirrors the control attributes `HTTPChatTarget` carries (`scope`, `rate`, `audit`) so
    the ownership model (ADR 0005) verifies it by attribute, unchanged.
    """

    def __init__(self, url: str, headers: dict | None = None, timeout: float = 30,
                 name: str | None = None):
        self.url = url.rstrip("/")
        self.headers: dict[str, str] = headers or {}
        self.timeout = float(timeout)
        self.name = name or self.url
        self.scope = None          # audit.Scope   - REQUIRED and non-empty (ADR 0012)
        self.rate = None           # audit.RateLimiter
        self.audit = None          # audit.AuditLog
        # ADR 0013: an AuthContext, attached by the caller exactly as the controls above
        # are. Request material, not an operational control - the three above enforce
        # something, this one is sent.
        self.auth = None           # targets.AuthContext
        self.exchanges: list = []


class RestDriver:
    """Drives a REST surface with an HttpAction."""

    kind = SurfaceKind.REST
    # ADR 0012: the ownership boundary refuses this driver unless its target holds a
    # non-empty Scope. Declared here so `compat` enforces it without knowing about REST.
    requires_scope = True

    def __init__(self, target: RestTarget):
        self._target = target

    @property
    def target(self) -> RestTarget:
        """The endpoint this driver drives (ADR 0005)."""
        return self._target

    def _url_for(self, action: HttpAction) -> str:
        """Absolute URL. Composed once and used for scope check, request, custody and
        reproduction, so all four agree (ADR 0012 R8)."""
        return f"{self._target.url}/{str(action.path).lstrip('/')}"

    def _auth_headers(self) -> dict:
        """Headers contributed by the target's `AuthContext`, or none (ADR 0013).

        Read here, at the transport boundary, and nowhere else. `canonical_request` is
        built from the `action` alone, so a credential supplied through this path never
        reaches the canonical form - and therefore never reaches custody, Finding
        identity, reproduction, `exchanges`, HAR or the audit chain, all of which are
        computed over that form. Placing auth in `action.headers` instead would put it in
        every one of them, where `SECRET_PATTERNS` could not redact it.
        """
        return dict(getattr(getattr(self._target, "auth", None), "headers", None) or {})

    def drive(self, surface: Surface, action: Any) -> Observation:
        if not isinstance(action, HttpAction):
            return Observation.failure(
                f"RestDriver requires an HttpAction, got {type(action).__name__}")
        t = self._target
        url = self._url_for(action)
        t.scope.check(url)               # refuse out-of-scope hosts; non-empty by contract
        if t.rate is not None:
            t.rate.wait()
        canonical = canonical_request(action, url)

        # Auth sits beneath both, so an explicit per-request or per-target header always
        # wins over application-level credentials (ADR 0013).
        headers = {**self._auth_headers(), **t.headers, **(action.headers or {})}
        data = None
        if action.body is not None:
            raw = (action.body if isinstance(action.body, str)
                   else json.dumps(action.body, sort_keys=True, separators=(",", ":")))
            data = raw.encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        full = url
        if action.query:
            pairs = sorted((str(k), str(v)) for k, v in action.query.items())
            full += "?" + "&".join(f"{k}={v}" for k, v in pairs)
        req = urllib.request.Request(full, data=data, headers=headers,
                                     method=action.method.upper())

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=t.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
            obs = Observation(ok=True, text=body, status=status,
                              latency_ms=(time.perf_counter() - start) * 1000,
                              request=canonical, response=body,
                              custody_hash=sha256(canonical, body))
        except urllib.error.HTTPError as e:
            body = str(e.reason)
            obs = Observation(ok=False, text="", status=e.code, error=f"HTTP {e.code}: {body}",
                              latency_ms=(time.perf_counter() - start) * 1000,
                              request=canonical, response=body,
                              custody_hash=sha256(canonical, body))
        except Exception as e:  # noqa: BLE001 - report any transport error to the caller
            body = str(e)
            obs = Observation(ok=False, text="", error=body,
                              latency_ms=(time.perf_counter() - start) * 1000,
                              request=canonical, response=body,
                              custody_hash=sha256(canonical, body))
        t.exchanges.append({"url": full, "method": action.method.upper(),
                            "request_body": canonical, "status": obs.status,
                            "response_body": obs.response, "ms": round(obs.latency_ms, 1)})
        if t.audit is not None:
            t.audit.record(full, canonical, str(obs.response), obs.ok)
        return obs


def rest_surface_from_target(target: RestTarget, method: str, path: str,
                             surface_id: str | None = None) -> Surface:
    """Build a REST Surface bound to a RestDriver over an existing RestTarget."""
    return Surface(
        id=surface_id or f"rest:{method.lower()}:{path}",
        kind=SurfaceKind.REST,
        locator={"method": method.upper(), "path": path},
        driver=RestDriver(target),
    )


def require_scope(driven: object) -> None:
    """Refuse a driver whose target holds no usable Scope (ADR 0012 R1).

    An absent Scope, or one with an empty allowlist, enforces nothing: `Scope.check()`
    returns silently. Binding does not check the supplied target's host against the
    discovered document (ADR 0014), so the allowlist is what stands between a mis-paired
    binding and an unintended host.
    """
    scope = getattr(driven, "scope", None)
    if scope is None:
        raise TargetError(
            f"REST target {getattr(driven, 'url', driven)!r} holds no scope: an explicit "
            "host allowlist is required before any request is issued, because binding "
            "does not verify this target against the document it was discovered from")
    if not getattr(scope, "allowed", None):
        raise TargetError(
            f"REST target {getattr(driven, 'url', driven)!r} holds an empty scope "
            "allowlist, which enforces nothing; name the hosts you are authorised to test")
