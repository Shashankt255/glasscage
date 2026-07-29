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
from .chat import ChatDriver, ChatSurface, chat_surface_from_target
from .compat import SurfaceTarget, chat_surface_of, chat_surfaces_of
from .discovery import discover, discover_mcp, discover_openapi
from .driver import (
    Action, Driver, HttpAction, Observation, PromptAction, ToolCallAction,
)
from .surface import Surface, SurfaceCandidate, SurfaceKind

__all__ = [
    "ApplicationTarget",
    "AuthContext",
    "SurfaceTarget",
    "chat_surface_of",
    "chat_surfaces_of",
    "discover",
    "discover_openapi",
    "discover_mcp",
    "Surface",
    "SurfaceCandidate",
    "SurfaceKind",
    "Driver",
    "Observation",
    "Action",
    "PromptAction",
    "HttpAction",
    "ToolCallAction",
    "ChatDriver",
    "ChatSurface",
    "chat_surface_from_target",
]
