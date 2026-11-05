# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""targets: the multi-surface application model (GLASSCAGE Phase 1 foundation).

Additive package. It defines the stable Surface/Driver/ApplicationTarget contract that
later Phase 1 PRs implement against. The existing single-endpoint HTTPChatTarget is
adapted here (ChatSurface/ChatDriver) without being modified.

Since ADR 0002 the run pipeline can optionally consume it: `Engine(target, surface=...)`
routes probe traffic through a bound Surface via the SurfaceTarget shim. The default
path (no `surface=`) is unchanged.
"""

from __future__ import annotations

from .application import ApplicationTarget, AuthContext
from .binding import bind_candidate
from .chat import ChatDriver, ChatSurface, chat_surface_from_target
from .compat import (
    SurfaceTarget,
    chat_surface_of,
    chat_surfaces_of,
    drivable_surfaces_of,
)
from .discovery import discover, discover_mcp, discover_openapi
from .driver import (
    Action,
    Driver,
    HttpAction,
    Observation,
    PromptAction,
    ToolCallAction,
)
from .rest import RestDriver, RestTarget, canonical_request, rest_surface_from_target
from .surface import Surface, SurfaceCandidate, SurfaceKind

__all__ = [
    "Action",
    "ApplicationTarget",
    "AuthContext",
    "ChatDriver",
    "ChatSurface",
    "Driver",
    "HttpAction",
    "Observation",
    "PromptAction",
    "RestDriver",
    "RestTarget",
    "Surface",
    "SurfaceCandidate",
    "SurfaceKind",
    "SurfaceTarget",
    "ToolCallAction",
    "bind_candidate",
    "canonical_request",
    "chat_surface_from_target",
    "chat_surface_of",
    "chat_surfaces_of",
    "discover",
    "discover_mcp",
    "discover_openapi",
    "drivable_surfaces_of",
    "rest_surface_from_target",
]
