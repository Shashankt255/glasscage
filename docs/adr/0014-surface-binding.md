# ADR 0014 — Surface binding

Status: Accepted · Phase 2 / PR #15

Discharges the `binding` follow-up carried by
[ADR 0003](0003-surface-discovery.md), [ADR 0004](0004-attribution-before-binding.md),
[ADR 0005](0005-declared-and-governed-ownership.md),
[ADR 0006](0006-probe-surface-applicability.md),
[ADR 0007](0007-action-model-generalisation.md), [ADR 0008](0008-driver-side-custody.md),
[ADR 0009](0009-surface-resolution-contract.md),
[ADR 0011](0011-multi-surface-execution.md) and
[ADR 0012](0012-rest-surface-execution.md). Supersedes nothing.

## Context
`discovery` has emitted `SurfaceCandidate` records since ADR 0003 and nothing has consumed
them. The module states its own precondition:

> **Candidates are never bound to a Driver here.** A bound surface must be bound to the
> target supplied to the engine (ADR 0002), so binding a discovered endpoint cannot happen
> until per-surface attribution exists. Discovery produces the input that work needs.

Per-surface attribution landed in ADR 0004 and was generalised in ADR 0011; a non-chat
driver arrived in ADR 0012. The stated blocker is cleared, and ADR 0003's own sequence —
*"per-surface attribution, then binding and non-chat drivers"* — has its other two members
delivered.

Two structural alignments already existed and were evidently designed for: `discovery`
emits candidate ids as `rest:<method>:<path>`, which is exactly `rest_surface_from_target`'s
default surface id; and a REST candidate's locator is the `{"method", "path"}` shape that
`RestDriver`, `recon` and the REST disclosure probe already consume. Binding is therefore a
resolution step over shapes that agree, not a translation layer.

## Decision

### Binding is pure resolution
It performs no I/O, constructs no target, and mutates neither the candidate nor the target.
The caller supplies the target the surface will drive, because ADR 0002 requires a bound
surface to be bound to the target supplied to the engine, and ADR 0011 rejected propagating
an application's controls onto a target the engine does not own. Ownership, governance and
ADR 0012's fail-closed scope check stay at `SurfaceTarget` construction, where ADR 0005 put
them, so binding raises `ConfigError` and never `TargetError`. A candidate bound to a
scopeless target binds successfully and is refused at the boundary that owns that refusal.

### Only a kind with a driver can be bound
Bindability is defined by membership in a per-kind binder registry. That set is deliberately
**not** `compat._DRIVABLE_KINDS`: CHAT is drivable, but `discovery` emits only REST and
MCP_TOOL candidates, so CHAT is not bindable *from discovery*. REST is both. MCP_TOOL is
neither, and is refused by name rather than bound to a driver that does not exist. The two
sets encode different facts, so this is not a duplicated policy.

### Promotion is a free function, not a container method
`ApplicationTarget` is a pure container whose every method stores or queries
(`add_surface`/`surfaces_of`, `add_candidate`/`candidates_of`), and it imports only
`.surface` — the narrowest dependency footprint in the package. Binding is a transform and
needs `RestDriver`, so a method would make the leaf container depend on a driver
implementation and break the add/query symmetry. It would also contradict `add_candidate`'s
own contract: *"A candidate is a proposal, not a surface… Promotion to a bound Surface is a
separate, explicit decision."*

Neither existing surface constructor is a container method either — `chat_surface_from_target`
lives in `chat.py` and `rest_surface_from_target` in `rest.py`, each beside the driver it
binds. A third constructor living outside the container is the rule, not an exception, and
the operator idiom is unchanged: `app.add_surface(bind_candidate(candidate, target))` has
the same shape as the existing `app.add_surface(rest_surface_from_target(...))`.

### The candidate's locator and `io_schema` are carried through unchanged
Rebuilding the locator from its parts would be a no-op on well-formed input and a silent
field-drop on anything carrying more. Promotion should lose nothing the candidate recorded.

### The bound surface keeps the candidate's id
So a finding's `surface_id` traces back to the discovered operation that produced it. An
explicit override exists only for disambiguating two candidates promoted onto different
targets.

## Alternatives considered
1. **A method on `ApplicationTarget`.** Rejected: forces the pure container to import a
   driver, breaks its add/query symmetry, and makes it the de facto driver registry — a role
   no module holds.
2. **Inside `compat.py`.** Rejected: that module is the `send()` shim and the ownership
   boundary; binding is neither. It also defers its `from .rest import` to function scope,
   showing module-level coupling there is treated as something to avoid.
3. **Inside `discovery.py`.** Rejected: contradicts an emphasised statement in that module's
   own docstring and would make a module declared "Read-only" construct drivers.
4. **Inside `rest.py`.** Rejected: a binder that must refuse MCP_TOOL and every driverless
   kind is dispatching across kinds, which does not belong in a kind-specific module.
5. **Binding constructing its own `RestTarget` from `ApplicationTarget.base_url`.**
   Rejected: ADR 0012 requires a non-empty `Scope` before any REST request, so a constructed
   target would have to be given one — the propagation ADR 0011 rejected.

## Consequences
- **Positive:** an entire module and its registry API gain their first consumer. A
  discovered REST operation can be promoted, registered and driven without hand-transcribing
  its method and path, and the surface id ties findings back to the discovered operation.
- **Unchanged:** everything. Binding is additive and no existing module was modified beyond
  one export. Verified against `v0.3.3-diff-identity` by tree comparison: `discovery`'s JSON
  and markdown output, graph identity, custody, SARIF, replay, benchmark,
  `runtime_coverage_ratio`, CHAT and REST behaviour, determinism. No existing test required
  modification.
- **Accepted:** binding does not verify that the supplied target's host matches the
  discovered document. ADR 0012's scope allowlist refuses an out-of-scope host before the
  socket, so binding adds no exposure — but it does not itself detect a mismatched pairing.
- **Accepted:** `SurfaceCandidate.source` has no field on `Surface` and is not carried.
  Adding one would invent a convention this ADR does not need.
- **Follow-up (not this ADR):** CLI exposure; MCP runtime, GraphQL and function drivers;
  per-operation REST batteries; `SurfaceCandidate.io_schema` consumption, which is now
  carried onto the bound surface but still read by nothing.
