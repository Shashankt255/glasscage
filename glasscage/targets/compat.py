# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""SurfaceTarget: drive a bound Surface through the legacy `send()` contract.

Phase 1 wiring shim (ADR 0002). The run pipeline talks to a target by calling
`send(prompt)` and reading `.ok`, `.text`, `.error`, `.trace` and `.latency_ms` off the
result. `Observation` declares those same five fields with the same meaning, so a
surface-driven Observation is accepted by every existing probe unchanged and no probe,
recon, mutation or genetic call site needs migrating.

SurfaceTarget therefore does two things and nothing else:

  * `send(prompt)` drives the bound Surface with a PromptAction and returns the
    resulting Observation.
  * any other attribute is delegated to the *origin* object the surface was built from,
    so identity (`name`, `url`), transport metadata (`method`), the capability tier
    (`capabilities`) and the optional replay hooks (`set_seed`, `new_session`) behave
    exactly as they do without the shim. Delegation preserves `hasattr` semantics, which
    `stats.TrialRunner` relies on when deciding whether to seed a run.

Structural typing only: nothing here checks for HTTPChatTarget, so the deterministic
reference harness and plain test stubs drive surfaces on equal terms.

Declared and governed ownership (ADR 0005): when an `origin` is supplied (the engine
always supplies one) the surface's driver must *declare* the target it drives, and that
driven target becomes authoritative for attribution — identity, capability tier and
reproduction follow it. A driver that declares nothing is refused: unverifiable
attribution is treated as failed attribution.

The driven target need no longer be the same object as the origin, which is what allows
non-chat drivers to exist. What object identity used to guarantee for free is now checked
explicitly: a driven target must be governed by the supplied target's operational
controls (scope allowlist, rate limiter, audit log), or the run is refused before any
traffic.
"""

from __future__ import annotations

from ..errors import ConfigError, TargetError
from .application import ApplicationTarget
from .driver import Observation, PromptAction
from .surface import Surface, SurfaceKind


def _bound_target(surface: Surface):
    """The object a surface's driver drives, or None if the driver does not declare one."""
    return getattr(surface.driver, "target", None)


def _describe(target) -> str:
    """Identify a target in an error message. URL first: two targets often share a name."""
    return str(getattr(target, "url", None) or getattr(target, "name", None) or target)


# Operational controls live on the target and are enforced inside its own send(): the
# scope allowlist, the rate limiter and the audit log. They are attached by the caller to
# the target it supplies, so a driven target that does not carry the same objects would
# silently escape them.
_CONTROLS = ("scope", "rate", "audit")


def _verify_governance(origin, driven) -> None:
    """Refuse a driven target that is not governed by the supplied target's controls.

    Object identity used to guarantee this for free. With ownership generalised, it has
    to be checked: probing a target that never received the scope allowlist would test a
    host the operator never authorised, and one without the rate limiter would ignore the
    politeness budget. Controls the origin does not set impose no requirement.
    """
    for control in _CONTROLS:
        expected = getattr(origin, control, None)
        if expected is None:
            continue
        if getattr(driven, control, None) is not expected:
            raise TargetError(
                f"driven target {_describe(driven)!r} is not governed by the supplied "
                f"target's {control}: probing it would bypass the operational control "
                f"attached to {_describe(origin)!r}")


class SurfaceTarget:
    """Presents a bound Surface through the `send(prompt)` contract probes expect."""

    def __init__(self, surface: Surface, origin: object | None = None):
        driven = _bound_target(surface)
        if origin is not None:
            if driven is None:
                raise TargetError(
                    f"driver {type(surface.driver).__name__} does not expose the target it "
                    "drives, so evidence attribution cannot be verified; expose a `target` "
                    "attribute on the driver")
            _verify_governance(origin, driven)
        self.surface = surface
        self.origin = origin
        # ADR 0005: the driven target is authoritative for attribution.
        self.driven = driven

    def send(self, prompt: str) -> Observation:
        """Drive the bound surface once. Returns an Observation, never raises."""
        return self.surface.drive(PromptAction(prompt=prompt))

    def __getattr__(self, name: str):
        # Only reached for attributes SurfaceTarget does not define itself. Delegation
        # goes to the DRIVEN target (ADR 0005), so identity, capability tier and
        # reproduction follow what was actually probed rather than what was supplied.
        if self.__dict__.get("origin") is None:
            raise AttributeError(name)
        return getattr(self.__dict__["driven"], name)


def chat_surfaces_of(source: object) -> list[Surface]:
    """Resolve a Surface or ApplicationTarget to every drivable CHAT surface (ADR 0009).

    Order is **registration order** - the sequence the operator added surfaces in - and
    is deliberately not sorted. `discovery` sorts its candidates by id because a document
    has no inherent order; a registration list does, and that order is the operator's.
    Duplicate ids collapse first-wins. Only CHAT is drivable in this release, so anything
    else is refused loudly rather than silently assessed at the wrong surface.

    Resolution only: ownership and governance are validated per surface when a
    `SurfaceTarget` is constructed (ADR 0005). This function never raises `TargetError`.
    """
    if isinstance(source, Surface):
        if source.kind is not SurfaceKind.CHAT:
            raise ConfigError(
                f"only CHAT surfaces are drivable in this release, got {source.kind}")
        return [source]
    if isinstance(source, ApplicationTarget):
        chat = source.surfaces_of(SurfaceKind.CHAT)
        if not chat:
            raise ConfigError("ApplicationTarget registers no CHAT surface to drive")
        seen: dict = {}
        for surface in chat:
            seen.setdefault(surface.id, surface)   # first-wins, insertion-ordered
        return list(seen.values())
    raise ConfigError(
        f"expected a Surface or ApplicationTarget, got {type(source).__name__}")


def chat_surface_of(source: object) -> Surface:
    """The single CHAT surface to drive: the first result of `chat_surfaces_of`.

    Ambiguity is not refused - an application registering several CHAT surfaces yields
    the first. Multi-surface execution is a later change; until then this preserves the
    behaviour every current caller depends on.

    No refusal logic lives here. Every `ConfigError` originates in `chat_surfaces_of`,
    so the two cannot drift, and indexing is safe because the empty case is already
    refused there.
    """
    return chat_surfaces_of(source)[0]
