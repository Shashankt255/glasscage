# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""ChatSurface / ChatDriver: adapt the existing HTTPChatTarget to the Surface model.

This is the one place the new abstraction meets the old code. HTTPChatTarget is NOT
modified, renamed, or moved — it is wrapped from the outside. ChatDriver.drive() calls
HTTPChatTarget.send() and maps the returned ChatResponse onto an Observation field for
field, so behaviour is identical and the mapping is lossless.

Since ADR 0008 the driver also attaches chain of custody: the request that produced the
response, and a SHA-256 over the pair. Recording stays with the target, which already
maintains `exchanges` and the audit chain.

Only SurfaceKind.CHAT is exercised in this release.
"""

from __future__ import annotations

from ..audit import sha256
from ..target import ChatResponse, HTTPChatTarget
from .driver import Action, Observation, PromptAction
from .surface import Surface, SurfaceKind


def _to_observation(r: ChatResponse, request: str) -> Observation:
    """Map a ChatResponse to an Observation with no loss and no reinterpretation.

    ADR 0008: the observation carries the request that produced it and a custody hash
    over (request, response), using the same helper and argument order the engine uses
    for `Finding.evidence_hash`. The driver hashes but does not record - the underlying
    target already appends to `exchanges` and writes the audit chain.
    """
    return Observation(
        ok=r.ok,
        text=r.text,
        latency_ms=r.latency_ms,
        error=r.error,
        trace=r.trace,
        request=request,
        response=r.raw,
        custody_hash=sha256(request, r.text),
    )


class ChatDriver:
    """Drives a chat surface by delegating to an underlying HTTPChatTarget."""

    kind = SurfaceKind.CHAT

    def __init__(self, target: HTTPChatTarget):
        self._target = target

    @property
    def target(self) -> HTTPChatTarget:
        """The target this driver drives. Read by the engine wiring to verify that a
        surface and the supplied target are the same object, so evidence cannot be
        attributed to a system that was never probed."""
        return self._target

    def drive(self, surface: Surface, action: Action) -> Observation:
        if not isinstance(action, PromptAction):
            return Observation.failure(
                f"ChatDriver requires a PromptAction, got {type(action).__name__}")
        return _to_observation(self._target.send(action.prompt), action.prompt)


def chat_surface_from_target(
    target: HTTPChatTarget, surface_id: str = "chat"
) -> Surface:
    """Build a CHAT Surface bound to a ChatDriver over an existing HTTPChatTarget.

    Convenience for the (current) single-endpoint case and for tests. Does not alter the
    target or the run pipeline.
    """
    return Surface(
        id=surface_id,
        kind=SurfaceKind.CHAT,
        locator=getattr(target, "url", None),
        driver=ChatDriver(target),
    )


# Public alias matching the PR spec's naming.
ChatSurface = chat_surface_from_target
