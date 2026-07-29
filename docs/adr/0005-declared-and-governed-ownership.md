# ADR 0005 — Declared and governed ownership

Status: Accepted · Phase 1 / Sprint 2 / PR #5
Supersedes the "one authoritative target" clause of
[ADR 0002](0002-engine-surface-wiring.md) (that ADR's other decisions stand).

## Context
[ADR 0002](0002-engine-surface-wiring.md) required a driven surface to be bound to the
*same object* supplied as the engine's target. That guard was introduced for a
demonstrated failure: an engine given target A and a surface bound to target B produced 21
findings whose reproduction steps cited A while B was probed.

Object identity is total, not incidental: a REST or MCP driver is by construction bound to
something other than the single `HTTPChatTarget`, so **every** non-chat surface is refused.
The guard is therefore the gate on the whole remaining Phase 1 roadmap — probe/surface-kind
applicability in usable form, driver-side custody, multi-surface iteration, and both
drivers.

The invariant cannot simply be dropped. Assessment of the guard established that it was
load-bearing for **two** things, not one:

1. **Attribution.** Identity, capability tier and reproduction are read off the supplied
   target, so a different driven target makes them lie.
2. **Operational safety, not previously identified.** The scope allowlist, the rate limiter
   and the audit log are attributes of the target object, attached by the CLI and enforced
   inside `HTTPChatTarget.send()`. Object identity guaranteed for free that the object
   actually driven was the object the operator's controls were attached to. Relaxing
   attribution alone would let a run probe a target that never received the scope
   allowlist — testing a host the operator never authorised, silently, in a tool whose
   first documented condition is authorised use only.

## Decision
Replace *object identity* with **declared and governed ownership**.

1. **Declared.** Every driver declares the target it drives. `Driver` gains `target` as a
   protocol member (additive; `ChatDriver` already satisfied it). A driver that declares
   nothing is refused — unverifiable attribution is treated as failed attribution, exactly
   as before.
2. **Authoritative.** The declared driven target becomes the attribution source.
   `SurfaceTarget` delegates every non-`send` attribute to it, so identity, capability tier
   and reproduction follow what was probed.
3. **Governed.** Where the supplied target sets `scope`, `rate` or `audit`, the driven
   target must present the *same object references*. Otherwise the run is refused with
   `TargetError` before any traffic. Controls the supplied target does not set impose no
   requirement.

The invariant is relocated, not weakened: *"one authoritative target"* becomes *"the driven
target is authoritative, must declare itself, and must be governed by the same operational
controls."*

## Alternatives considered
1. **Broaden the predicate** (same class, same URL, "compatible"). Rejected: substitutes a
   heuristic for a proof, and no rule built on chat-target attributes generalises to
   REST/MCP.
2. **Surface-level attribution alone**, without the governance check. Rejected: correct for
   attribution, silently unsafe for scope and rate limiting.
3. **An attribution-context object** passed to consumers. Deferred: the right end-state for
   multi-surface iteration, but it introduces an architectural concept this PR is scoped to
   avoid. Delegation reaches the same place with no new type.
4. **Kind-scoped relaxation** (strict for CHAT, waived for others). Rejected: weakens the
   guarantee exactly where the code is least mature, and creates two attribution regimes.

## Consequences
- **Positive:** non-chat drivers become possible; the guard now states its intent
  explicitly rather than relying on an identity coincidence; the scope/rate bypass is
  closed structurally rather than by documentation.
- **Two engine reads redirected.** `caps` and `repro.build_all` read `self.target`
  directly, not through the shim, so delegation alone did not reach them. Both now read the
  resolved probe target. On the default path that object *is* `self.target`, so behaviour
  is unchanged.
- **The report header still names the supplied target.** `Engine.report_markdown` /
  `report_html` pass `self.target.name`, which identifies the assessment subject rather
  than the endpoint. Findings carry `surface_id` (ADR 0004) and reproduction cites the
  driven target, so per-finding provenance is exact. Revisit when multi-surface iteration
  lands.
- **Custody remains target-scoped.** `HTTPChatTarget.send()` records into its own
  `exchanges`, and `--har` exports the supplied target's. Unreachable from the CLI, which
  never passes `surface=`; the governance check covers the `audit` log. Driver-side custody
  is a separate, already-identified roadmap item.
- **Two approved tests changed** in `tests/test_surface_wiring.py`, both asserting the
  superseded identity rule. Rewritten to assert the new guarantee.
- **Follow-up (not this PR):** probe/surface-kind applicability, action model
  generalisation, driver-side custody, multi-surface iteration, then the REST and MCP
  drivers; binding last.
