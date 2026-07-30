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
Finding:<owasp_id>:<probe_name>:<surface_id>:<subject_digest>

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
- **`surface_id` distinguishes surfaces** ([ADR 0011](adr/0011-multi-surface-execution.md)).
  Every probe sends a fixed prompt, so without it every finding would collide across
  surfaces. A direct run carries an empty component, so its ids are PR #10's with one added
  colon and every CLI invocation is unchanged. A surface-driven run's ids differ from a
  direct run's: ADR 0011 supersedes the *representational* equivalence of ADRs 0002/0004/0008
  while preserving their behavioural intent.

## techniques_run
A **run-level** property counting distinct techniques executed, owned by the orchestration
layer — not derived from the graph. The graph excludes `passed` findings, so it can only
know which techniques produced graph-eligible evidence, never how many ran. Surface-count
independent: driving one application at three surfaces does not treble it. Every
evidence-derived analysis — posture, attack paths, blast radius, trust boundaries,
remediation — remains graph-native.

## Consumers (read-only)
`paths` (attack paths), `trust_graph` (trust boundaries), `blast` (blast radius),
`posture` (score + contributions), `coverage` (per-taxonomy), `remediation`
(prioritized), `report` (markdown). None recompute attack logic independently.
