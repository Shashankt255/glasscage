# ADR 0015 — CLI exposure of surface-driven assessment

Status: Accepted · Phase 2 / PR #16

Discharges the `CLI exposure` follow-up carried by
[ADR 0002](0002-engine-surface-wiring.md),
[ADR 0013](0013-request-material-at-the-transport-boundary.md) and
[ADR 0014](0014-surface-binding.md). Supersedes the *authorisation-asymmetry rationale* of
[ADR 0012](0012-rest-surface-execution.md); that ADR's R1 requirement is unchanged.

## Context
[ADR 0002](0002-engine-surface-wiring.md) deferred a CLI flag on an explicit condition:

> **Expose a CLI flag now.** Deferred: it would pull `cli.py`, `--har`, the audit log and
> replay bundles into the blast radius for no architectural gain. The capability is
> Python-API-only until a discovery PR gives it something to select.

Discovery arrived in ADR 0003 and binding in ADR 0014, so the condition is met twice over.
Until this PR the REST programme built across PRs #12–#15 — driver, probe, transport-boundary
auth, binding — was unreachable from the shipped CLI: `Engine(target, …)` was constructed
with no `surface=`, and `--discover` was standalone, running no assessment.

## Decision

### A dedicated `--rest-spec`; `--discover` is not overloaded
The assessment path takes its OpenAPI document through `--rest-spec`, paired with
`--rest-config`. `--discover` is unchanged in every combination.

The separation protects a documented guarantee rather than being merely conservative.
`discovery` declares itself *"Status: Experimental. Read-only"* and `--discover` is
*"standalone; needs no target and runs no assessment"*. Overloading one flag would make
that read-only guarantee conditional on which other flags were present — the kind of
non-locality ADR 0010 rejected when it refused a conditional `surface_id`. Two flags cost a
line of help text; one overloaded flag costs a guarantee. The help text for each names the
other so the redundancy is navigable.

### The CLI adds no refusal logic
`--authorized` gates the REST path exactly as it gates `--config`. ADR 0012 R1 — the
non-empty `Scope` — is enforced where it already lives, by `require_scope` at
`SurfaceTarget` construction. `cli.py` attaches controls as it already did and checks
nothing extra, so there is one enforcement point, not two that could drift.

### Binding happens after controls are attached
Surfaces are bound once `--scope`, `--rate` and the audit log are on the target, so every
bound surface drives a target that already carries them. Passing the same object as both
`Engine`'s target and the bound driver's target makes ADR 0005's governance check compare
an object with itself, so no propagation is introduced.

### ADR 0012's authorisation asymmetry is re-grounded
ADR 0012 justified requiring a non-empty `Scope` for REST — while chat's stays optional —
with a single reason: *"a gate that does not exist for REST, which has no CLI path… the
asymmetry is deliberate and has exactly one reason."* That premise is now false: REST has a
CLI path and `--authorized` gates it.

**R1 is nonetheless retained, on a new and CLI-independent ground.** ADR 0014 records as an
accepted limitation that *"binding does not verify that the supplied target's host matches
the discovered document"*. An operator can therefore pair an OpenAPI document with a
`RestTarget` pointing somewhere else, and the host allowlist is the only control standing
between that mis-pairing and traffic to an unintended host. Chat has no equivalent exposure:
its target is a single configured endpoint, not a set of operations discovered from a
separate document. The asymmetry survives its original justification because binding gave it
a better one.

## Consequences
- **Positive:** the REST programme is reachable by an operator for the first time. A single
  invocation discovers an application's operations, binds them, and assesses every one.
- **Accepted — a REST report is mostly NOT ASSESSABLE.** ADR 0006 gates every chat probe on
  a REST surface and ADR 0012 registered the REST probe into the default battery, so a
  two-operation spec yields 42 gated findings and 2 assessed ones. This is the honest
  reading of a battery that is 21/22 chat-shaped, and it is visible rather than hidden:
  gating a registered probe was preferred to omitting it and reporting coverage it had not
  earned.
- **Accepted:** two flags accept an OpenAPI document. The redundancy is the price of keeping
  `--discover` read-only.
- **Accepted, unfixed:** `--discover` alongside `--config` still silently ignores `--config`,
  as it did before this PR. Fixing it would modify `--discover`, which this ADR's decision
  forbids; it remains available as its own change.
- **Unchanged:** every existing invocation — `--demo`, `--harness`, `--config`,
  `--benchmark`, `--diff`, `--mcp-manifest` and `--discover` in all combinations. Verified
  against `v0.3.4-surface-binding` by tree comparison. No existing test required
  modification.
- **Follow-up (not this ADR):** MCP runtime, GraphQL and function drivers; per-operation
  REST batteries; `Surface.io_schema` consumption. **`rest.py`'s `require_scope` message
  still tells the operator that "REST has no `--authorized` gate", which this ADR makes
  false; correcting that wording requires editing a module this PR held out of scope.**
