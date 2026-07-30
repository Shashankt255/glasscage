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

## Finding-node identity
See [ADR 0010](adr/0010-finding-node-identity.md).

```
Finding:<owasp_id>:<probe_name>:<subject_digest>

subject_digest = first 12 hex chars of sha256(normalise(prompt))
normalise(s)   = collapse whitespace runs to one space, then strip
```

`owasp_id:probe_name` alone is **not** unique: `mcp.analyze_manifest` emits one finding per
flagged tool and `architecture.assess` one per control, so findings merged into a single node
whose label described one finding and whose status described another. The subject digest
separates them — one node per graph-eligible finding.

- **Content-derived, not order-derived.** Every component is intrinsic to the finding, so
  reordering probes or changing the probe selection cannot re-key another finding's node.
- **Target-behaviour-independent.** No component derives from the response, so a behavioural
  change updates a node's metadata rather than creating a new node. This is what makes
  cross-run graph comparison meaningful.
- **Opaque.** No consumer parses a Finding id; the digest keeps payloads, canaries and
  unredacted text out of node ids, which the redaction pass does not cover.
- **`surface_id` is deliberately excluded.** It is empty on every current run, and including
  it would make surface-driven graphs differ from direct ones, breaking the equivalence
  guaranteed by ADR 0002 and re-asserted by ADR 0004 and ADR 0008. Surface differentiation
  is deferred to multi-surface execution, which must resolve the case of findings identical
  in category, probe and prompt across surfaces.

## Consumers (read-only)
`paths` (attack paths), `trust_graph` (trust boundaries), `blast` (blast radius),
`posture` (score + contributions), `coverage` (per-taxonomy), `remediation`
(prioritized), `report` (markdown). None recompute attack logic independently.
