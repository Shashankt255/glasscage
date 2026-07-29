# ADR 0009 — Surface resolution contract

Status: Accepted · Phase 2 / Sprint 2 / PR #9

## Context
[ADR 0008](0008-driver-side-custody.md) places multi-surface iteration next on the
roadmap. The engine reaches a surface through exactly one call — `chat_surface_of` in
`compat.py` — which resolves an `ApplicationTarget` by taking
`surfaces_of(SurfaceKind.CHAT)[0]`.

The accepted Phase 1 Foundation Review recorded that selection as risk **N2**:
"registration-order dependent, invisible. Harmless with one surface; a correctness
question under multi-surface." It listed surface selection as one of three questions that
must be answered *inside* multi-surface work. Answering it on its own keeps the
engine-iteration change to a single concept, rather than bundling selection, report
identity and scope ownership into one un-reviewable PR.

## Decision
Resolution becomes plural and explicitly ordered.

1. **`chat_surfaces_of(source) -> list[Surface]`** returns every drivable CHAT surface.
2. **Order is registration order** — the sequence the operator added surfaces in — and is
   deliberately **not** sorted.
3. **Duplicate ids collapse first-wins**, preserving order.
4. **`chat_surface_of` is the first result**, and contains no logic of its own.
5. **All three refusals live in `chat_surfaces_of`.** The singular form indexes `[0]`,
   which is safe precisely because the empty case has already been refused. Had both
   functions kept their own checks they would eventually drift.
6. **Resolution does not validate ownership.** Governance and declared ownership are
   checked per surface when a `SurfaceTarget` is constructed ([ADR 0005](0005-declared-and-governed-ownership.md)).
   `chat_surfaces_of` raises `ConfigError` and never `TargetError`.

## Why registration order, when discovery sorts by id
`discovery._finalize` deduplicates and then sorts candidates by id, because an OpenAPI
document or MCP manifest has no inherent order — sorting is what makes discovery
deterministic. A registration list *does* have an inherent order, and it is the
operator's. Two ordering contracts therefore coexist in `targets/`, deliberately.

Unifying them was rejected: sorting resolution results would change which surface
`chat_surface_of` returns, breaking the behaviour every current caller depends on.

## Why ambiguity is not refused
An application registering several CHAT surfaces still yields the first, silently. The
alternative — refusing ambiguity — is a behaviour change, and nothing in the tree
constructs a multi-CHAT application today (there is no binding and discovery emits no CHAT
candidates), so the refusal would be unreachable while the behaviour change would be real.
The plural form makes the full set visible; what to do with it is multi-surface
iteration's decision, not this PR's.

## Alternatives considered
1. **Refuse ambiguity in the singular form.** Rejected above.
2. **Sort resolution results by id for consistency with discovery.** Rejected — changes
   which surface is driven.
3. **Validate ownership during resolution.** Rejected — it would move the refusal point
   earlier, change *when* `TargetError` is raised, and duplicate the per-surface guard
   that multi-surface iteration will rely on.
4. **Defer the whole question into the engine-iteration PR.** Rejected — that PR already
   carries two open architectural questions; adding a third makes it un-reviewable.

## Consequences
- **Positive:** Review risk N2 is closed. Multi-surface iteration now has a defined,
  ordered input and needs only the loop plus the two remaining decisions.
- **No behaviour change.** `chat_surface_of` returns the identical object and raises the
  identical exceptions for every input it handles today, structurally guaranteed by being
  a one-line wrapper.
- **Not a dead abstraction.** `chat_surface_of` consumes the plural form, and the engine
  calls that on every surface-driven run — unlike several earlier `targets/` additions,
  this has an immediate in-repo consumer.
- **Accepted:** first-wins deduplication is defensive. `ApplicationTarget.add_surface` is
  already idempotent by id, so duplicates can only arise by constructing the dataclass
  directly with a `surfaces=[...]` list. That path is public, so the guard is kept.
- **Still open, deliberately:** report identity (`self.target.name` names the assessment
  subject, not the endpoint) and where `scope` lives (Review risk M1 —
  `ApplicationTarget.scope` still has no reader). Both belong to multi-surface iteration.
- **Follow-up (not this PR):** multi-surface iteration, then the REST and MCP drivers;
  binding last.
