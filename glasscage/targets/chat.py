# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""ChatSurface / ChatDriver: adapt the existing HTTPChatTarget to the Surface model.

This is the one place the new abstraction meets the old code. HTTPChatTarget is NOT
modified, renamed, or moved — it is wrapped from the outside. ChatDriver.drive() calls
HTTPChatTarget.send() and maps the returned ChatResponse onto an Observation field for
field, so behaviour is identical and the mapping is lossless.

Only SurfaceKind.CHAT is exercised in this release.
"""

from __future__ import annotations

from ..target import ChatResponse, HTTPChatTarget
from .driver import Action, Observation, PromptAction
from .surface import Surface, SurfaceKind


def _to_observation(r: ChatResponse) -> Observation:
    """Map a ChatResponse to an Observation with no loss and no reinterpretation."""
    return Observation(
        ok=r.ok,
        text=r.text,
        latency_ms=r.latency_ms,
        error=r.error,
        trace=r.trace,
        response=r.raw,
    )


class ChatDriver:
    """Drives a chat surface by delegating to an underlying HTTPChatTarget."""

    kind = SurfaceKind.CHAT

    def __init__(self, target: HTTPChatTarget):
        self._target = target

    def drive(self, surface: Surface, action: Action) -> Observation:
        if not isinstance(action, PromptAction):
            return Observation.failure(
                f"ChatDriver requires a PromptAction, got {type(action).__name__}")
        return _to_observation(self._target.send(action.prompt))


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
