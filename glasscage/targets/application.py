# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""ApplicationTarget: the whole AI application under test (Phase 1 foundation).

Where `target.HTTPChatTarget` models a single chat endpoint, ApplicationTarget models an
application as a set of Surfaces sharing an auth context and an optional Scope. It is a
pure container: no network, no I/O, no engine logic. The run pipeline is NOT rewired to
consume it in this PR; wiring arrives in a later PR against this stable shape.

Scope is reused from `audit.Scope` rather than reinvented, keeping host-allowlist logic
in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .surface import Surface, SurfaceKind


@dataclass
class AuthContext:
    """Shared authentication material for an application's surfaces.

    Headers/cookies are held in memory for use by drivers; this object does not persist
    or log secrets. Redaction of any secret that appears in evidence remains the job of
    the reporting layer (`redaction`), exactly as it is today — this object does not
    change that guarantee.
    """

    scheme: str = "none"  # e.g. "none", "bearer", "api_key", "cookie", "oauth"
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


@dataclass
class ApplicationTarget:
    """An AI application as a collection of drivable surfaces.

    Pure data + small registry helpers. `scope` accepts an `audit.Scope` (or any object
    with a compatible `check(url)`), injected by the caller; ApplicationTarget does not
    import audit to avoid widening the dependency graph for a container.
    """

    base_url: str = ""
    auth: AuthContext = field(default_factory=AuthContext)
    surfaces: list[Surface] = field(default_factory=list)
    scope: Optional[object] = None  # audit.Scope-compatible; optional

    def add_surface(self, surface: Surface) -> Surface:
        """Register a surface (idempotent by surface id) and return it."""
        if surface not in self.surfaces:
            self.surfaces.append(surface)
        return surface

    def surfaces_of(self, kind: SurfaceKind) -> list[Surface]:
        """All registered surfaces of a given kind, in registration order."""
        return [s for s in self.surfaces if s.kind == kind]
