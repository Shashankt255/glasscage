# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface abstraction (GLASSCAGE Phase 1 foundation).

A *Surface* is one drivable thing on an AI application: a chat endpoint, a REST
operation, a GraphQL field, a callable function/tool, an MCP tool, a RAG ingest/
retrieve path, or a vector store. Today only CHAT is exercised end-to-end (via the
ChatDriver adapter over the existing HTTPChatTarget); the other kinds are declared so
that later Phase 1 pull requests implement against a stable, agreed contract.

This module is intentionally free of network or engine logic. A Surface holds identity
and shape and delegates the act of exercising itself to a bound Driver. Keeping the two
apart mirrors the existing separation between `target` (how to talk) and `probes` (what
to say), and keeps the dependency direction pointing inward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid an import cycle at runtime; Driver is only needed for typing
    from .driver import Action, Driver, Observation


class SurfaceKind(str, Enum):
    """The kind of drivable surface. Only CHAT is driven in this release."""

    CHAT = "chat"
    REST = "rest"
    GRAPHQL = "graphql"
    FUNCTION = "function"
    MCP_TOOL = "mcp_tool"
    RAG = "rag"
    VECTOR_DB = "vector_db"


@dataclass
class SurfaceCandidate:
    """A surface proposed by discovery but not yet promoted to a bound Surface.

    Discovery modules (later Phase 1 PRs) emit these; the engine decides which to bind
    to a Driver. Kept deliberately minimal: identity, kind, a locator, and an optional
    request/response schema.
    """

    id: str
    kind: SurfaceKind
    locator: Any
    io_schema: dict | None = None
    source: str = ""  # which discoverer proposed it (evidence/provenance)


@dataclass
class Surface:
    """A drivable surface bound to a Driver.

    `drive()` delegates to the bound driver rather than performing I/O itself, so a
    Surface stays a value object and all transport lives in one place (the driver).
    Equality and hashing are by `id` so surfaces can live in sets/dedupe cleanly.
    """

    id: str
    kind: SurfaceKind
    locator: Any
    driver: Driver
    io_schema: dict | None = None
    metadata: dict = field(default_factory=dict)

    def drive(self, action: Action) -> Observation:
        """Exercise this surface with an action, via the bound driver."""
        return self.driver.drive(self, action)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Surface) and other.id == self.id

    def __hash__(self) -> int:
        return hash(self.id)
