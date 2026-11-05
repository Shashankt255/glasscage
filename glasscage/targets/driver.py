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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

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
class HttpAction(Action):
    """A single HTTP request against a REST or GraphQL surface (ADR 0007).

    Status: Experimental — no driver consumes it yet.

    The shape mirrors what `discovery` already emits for a REST candidate (a
    `{"method", "path"}` locator plus an `io_schema`), so it describes data the
    repository already produces rather than an invented model.

    Deliberately minimal: this expresses *one request*, nothing more. Authentication
    belongs to `AuthContext`; timeouts, retries, redirects, pagination and content
    negotiation belong to the driver that performs the request.
    """

    method: str
    path: str
    query: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    body: Any = None


@dataclass
class ToolCallAction(Action):
    """A single tool invocation on an MCP or function surface (ADR 0007).

    Status: Experimental — no driver consumes it yet.

    Kept separate from HttpAction rather than merged into one envelope: a tool call has
    no path or method and an HTTP request has no tool name, so a single record would
    make every field optional and meaningless.
    """

    name: str
    arguments: dict = field(default_factory=dict)


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
    error: str | None = None
    trace: dict | None = None
    request: Any = None
    response: Any = None
    status: int | None = None
    custody_hash: str | None = None

    @property
    def raw(self) -> Any:
        """Compatibility alias for `ChatResponse.raw`.

        Additive: plugin probes written against the pre-surface contract read `.raw` off
        whatever `target.send()` returns. `ChatDriver` maps `ChatResponse.raw` onto
        `response`, so this alias keeps those probes working when the engine drives a
        surface. Not a field, so serialization and equality are unaffected."""
        return self.response

    @classmethod
    def failure(cls, error: str) -> Observation:
        """Construct a failed observation. Drivers return this instead of raising, so a
        dead surface becomes a recordable non-result rather than crashing a probe loop."""
        return cls(ok=False, error=error)


@runtime_checkable
class Driver(Protocol):
    """Exercises a Surface. Implementations live per kind (chat now; REST/GraphQL/etc.
    in later PRs). `runtime_checkable` so tests can assert conformance structurally."""

    kind: SurfaceKind
    # ADR 0005: every driver declares the target it drives. Ownership is verified from
    # this declaration, so a driver that cannot answer "what do you drive?" is refused
    # rather than trusted.
    target: Any

    def drive(self, surface: Surface, action: Action) -> Observation:
        ...
