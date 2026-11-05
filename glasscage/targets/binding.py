# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Binding: promote a discovered `SurfaceCandidate` to a bound `Surface` (ADR 0014).

`discovery` proposes, binding promotes, `ApplicationTarget` stores, `compat` resolves, the
driver drives. Each verb has one home; this module owns exactly one of them, which is why
promotion is a free function rather than a container method — `ApplicationTarget` is a pure
container whose every method stores or queries, and binding is a transform.

**Binding is pure resolution.** It performs no I/O, constructs no target, and mutates
nothing. The caller supplies the target the surface will drive, because ADR 0002 requires a
bound surface to be bound to the target supplied to the engine, and ADR 0011 rejected
propagating an application's controls onto a target the engine does not own. Ownership,
governance and the fail-closed scope check stay where ADR 0005 and ADR 0012 put them — at
`SurfaceTarget` construction — so nothing here raises `TargetError`. A candidate bound to a
scopeless target binds successfully and is refused later, at the boundary that owns that
refusal.

Only a kind with a driver can be bound. That set is deliberately *not*
`compat._DRIVABLE_KINDS`: CHAT is drivable, but `discovery` emits only REST and MCP_TOOL
candidates, so CHAT is not bindable from discovery. REST is both. MCP_TOOL is neither, and
is refused rather than bound to a driver that does not exist.
"""

from __future__ import annotations

from typing import Any

from ..errors import ConfigError
from .rest import RestDriver
from .surface import Surface, SurfaceCandidate, SurfaceKind


def _bind_rest(candidate: SurfaceCandidate, target: Any, surface_id: str | None) -> Surface:
    """Bind a REST candidate to a `RestDriver` over the supplied target.

    The candidate's `locator` is carried through unchanged rather than rebuilt from its
    parts: `discovery` and `rest_surface_from_target` already agree on the
    `{"method", "path"}` shape, so rebuilding would be a no-op on well-formed input and a
    silent field-drop on anything carrying more. `io_schema` is carried for the same
    reason — promotion should lose nothing the candidate recorded.
    """
    locator = candidate.locator
    if not isinstance(locator, dict) or not locator.get("path"):
        raise ConfigError(
            f"REST candidate {candidate.id!r} has no usable locator: expected "
            f'{{"method", "path"}}, got {locator!r}')
    return Surface(
        id=surface_id or candidate.id,
        kind=SurfaceKind.REST,
        locator=locator,
        driver=RestDriver(target),
        io_schema=candidate.io_schema,
    )


# Kind -> binder. Membership is the definition of "bindable"; a kind absent here has no
# driver to bind to and is refused by name rather than bound to nothing.
_BINDERS = {SurfaceKind.REST: _bind_rest}


def bind_candidate(candidate: SurfaceCandidate, target: Any,
                   surface_id: str | None = None) -> Surface:
    """Promote one discovered candidate to a `Surface` bound to `target`.

    The bound surface keeps the candidate's id, so a finding's `surface_id` traces back to
    the discovered operation it came from. `surface_id` overrides that only when the caller
    needs to disambiguate two candidates promoted onto different targets.

    Raises `ConfigError` — never `TargetError` — for a non-candidate or for a kind with no
    driver, matching `drivable_surfaces_of`'s refusal discipline (ADR 0009).
    """
    if not isinstance(candidate, SurfaceCandidate):
        raise ConfigError(
            f"expected a SurfaceCandidate, got {type(candidate).__name__}")
    binder = _BINDERS.get(candidate.kind)
    if binder is None:
        raise ConfigError(
            f"no driver for surface kind {candidate.kind} in this release, so candidate "
            f"{candidate.id!r} cannot be bound")
    return binder(candidate, target, surface_id)
