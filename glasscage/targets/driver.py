# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Driver protocol and the Observation/Action records (Phase 1 foundation).

A *Driver* knows how to exercise one kind of Surface and return an *Observation* — a
uniform record of a single request/response interaction. Observation's fields
deliberately mirror `target.ChatResponse` (text, ok, latency_ms, error, trace) so the
ChatDriver mapping is lossless and so downstream code that already understands a
ChatResponse can understand an Observation with no translation surprises.

Drivers perform I/O; Surfaces do not. That keeps transport in one layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:  # typing-only import; no runtime cycle
    from .surface import Surface, SurfaceKind


@dataclass
class Action:
    """Base request descriptor handed to a driver. Subtypes carry kind-specific data."""


@dataclass
class PromptAction(Action):
    """A chat prompt — the only action kind exercised in this release."""

    prompt: str


@dataclass
class Observation:
    """The uniform result of driving a surface once.

    Field parity with `target.ChatResponse` is intentional (text/ok/latency_ms/error/
    trace). `request`/`response`/`status`/`custody_hash` generalise beyond chat for the
    REST/GraphQL drivers that arrive in later PRs; they are optional and default to None
    so the ChatDriver need only populate the chat-equivalent fields.
    """

    ok: bool
    text: str = ""
    latency_ms: float = 0.0
    error: Optional[str] = None
    trace: Optional[dict] = None
    request: Any = None
    response: Any = None
    status: Optional[int] = None
    custody_hash: Optional[str] = None

    @classmethod
    def failure(cls, error: str) -> "Observation":
        """Construct a failed observation. Drivers return this instead of raising, so a
        dead surface becomes a recordable non-result rather than crashing a probe loop."""
        return cls(ok=False, error=error)


@runtime_checkable
class Driver(Protocol):
    """Exercises a Surface. Implementations live per kind (chat now; REST/GraphQL/etc.
    in later PRs). `runtime_checkable` so tests can assert conformance structurally."""

    kind: "SurfaceKind"

    def drive(self, surface: "Surface", action: Action) -> Observation:
        ...
