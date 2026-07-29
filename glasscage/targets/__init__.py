# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""targets: the multi-surface application model (GLASSCAGE Phase 1 foundation).

Additive package. Nothing in the run pipeline consumes it yet; it defines the stable
Surface/Driver/ApplicationTarget contract that later Phase 1 PRs implement against. The
existing single-endpoint HTTPChatTarget is adapted here (ChatSurface/ChatDriver) without
being modified.
"""

from __future__ import annotations

from .application import ApplicationTarget, AuthContext
from .chat import ChatDriver, ChatSurface, chat_surface_from_target
from .driver import Action, Driver, Observation, PromptAction
from .surface import Surface, SurfaceCandidate, SurfaceKind

__all__ = [
    "ApplicationTarget",
    "AuthContext",
    "Surface",
    "SurfaceCandidate",
    "SurfaceKind",
    "Driver",
    "Observation",
    "Action",
    "PromptAction",
    "ChatDriver",
    "ChatSurface",
    "chat_surface_from_target",
]
