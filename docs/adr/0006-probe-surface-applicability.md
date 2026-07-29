# ADR 0006 — Probe surface applicability

Status: Accepted · Phase 2 / Sprint 1 / PR #6

## Context
[ADR 0005](0005-declared-and-governed-ownership.md) removed the last architectural
blocker on non-chat drivers: a driver may now be bound to a target other than the one
supplied to the engine. The accepted Phase 1 Foundation Review then identified what still
stands between that and a *shippable* REST or MCP driver — probe applicability — and
ranked it the highest-readiness item, describing it as "the difference between drivers
that produce evidence and drivers that produce noise."

All 21 registered probes are **prompt-shaped**: they call `target.send(prompt)` and
interpret free text. Run `direct-injection-canary` against a REST operation and it emits
`PASSED` or `VULNERABLE` — a verdict with no meaning. Nothing in the probe contract
prevents this, because `Probe` declares only a *capability* requirement (`min_tier`) and
says nothing about *what kind of thing* it can drive.

This is the validity crisis the L0–L3 tier system was built to fix, recurring on a second
axis. The repository already owns the fix pattern.

## Decision
Probes declare the surface kinds they can drive, and the engine gates on it.

1. `Probe.surface_kinds` defaults to `(SurfaceKind.CHAT,)`. Every built-in probe inherits
   it; none was edited.
2. The engine resolves the driven surface kind from the driven surface, defaulting to
   `CHAT` when no surface is bound (a legacy run drives a single chat endpoint).
3. A probe whose declaration excludes the driven kind is never invoked and yields one
   `NOT_ASSESSABLE` finding naming both the driven kind and the kinds it does drive —
   the same shape the tier gate already produces.

**Set membership, not ordinal.** `min_tier` is an `IntEnum` comparison because capability
tiers are ordered: L2 implies L1. Surface kinds are not ordered — a REST driver is not
"more" than a chat driver — so applicability is a declared tuple and the test is
membership.

**Applicability is checked before capability tier.** Being unable to drive a surface at
all is more fundamental than lacking a capability on it, and the resulting message is more
useful: "this probe does not drive REST" beats "this probe needs L2" when the probe could
never have run regardless of tier.

**Read with a default.** `getattr(probe, "surface_kinds", (SurfaceKind.CHAT,))` means a
third-party probe written before this ADR keeps working and is treated as chat-applicable.
The plugin SDK documents the attribute as optional.

## Alternatives considered
1. **A `min_surface_kind` ordinal mirroring `min_tier`.** Rejected: it would impose a
   false ordering on kinds that have none.
2. **A new `Finding` field carrying the gate reason.** Rejected: a model change for
   parity the tier gate does not have either. Recorded as a future enhancement.
3. **Inferring applicability from the probe's payload shape.** Rejected: inference is
   exactly the guessing this project refuses elsewhere. A probe declares what it drives.
4. **Deferring until the first driver exists.** Rejected: the gate is cheapest before
   there is any non-chat traffic to audit, and the Review ranked it ready now.

## Consequences
- **Positive:** the first REST or MCP driver is born into a system that already refuses to
  run prompt probes against it. No finding audit is needed afterwards.
- **No behaviour change today.** All shipped probes are chat-applicable and every current
  run drives CHAT, so output is unchanged on the default and surface-driven CHAT paths.
- **The deny branch is live, not theoretical.** A probe declaring a non-chat kind is gated
  on a chat run, so the path is exercised end to end without any driver existing.
- **New import direction `probes → targets`.** The first of its kind, and the permitted
  direction: `targets/` never imports `probes`, enforced by
  `tests/test_targets_foundation.py`.
- **Accepted:** the gate reason lives in the finding title, not a machine-readable field,
  matching the tier gate. A consumer wanting to distinguish gate types parses `prompt`
  (`"(surface-gated)"` vs `"(tier-gated)"`), which is serviceable but not a contract.
- **Follow-up (not this PR):** action model generalisation, driver-side custody,
  multi-surface iteration, then the REST and MCP drivers; binding last.
