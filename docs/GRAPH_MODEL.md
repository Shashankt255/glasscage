# AAKG Graph Model Reference

## Node types (24)
Finding, Evidence, Asset, Component, User, LLM, Planner, Memory, Retriever, MCP,
Tool, API, Database, Filesystem, Secrets, TrustZone, Mitigation, OWASP, ATLAS,
CAPEC, CWE, NIST, CapabilityTier.

## Edge types (12)
enables, requires, invokes, accesses, crosses, trusts, mitigates, mapped_to,
verified_by, hypothesized_by, observed_on, affects.

## Edge state (epistemic)
- `demonstrated` — observed on-target (impact-confirmed finding).
- `hypothesized` — architecturally reachable but unproven.
- `not_assessable` — the probe that would prove it was tier-gated.
State upgrades are monotonic; a path's state is its weakest edge.

## Determinism
Node id = `Type:key`; edge id = `src-[type]->dst`. All iteration is sorted;
serialization round-trips exactly. Analyses are cached and the cache is invalidated
on any mutation.

## Consumers (read-only)
`paths` (attack paths), `trust_graph` (trust boundaries), `blast` (blast radius),
`posture` (score + contributions), `coverage` (per-taxonomy), `remediation`
(prioritized), `report` (markdown). None recompute attack logic independently.
