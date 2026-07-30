# ADR 0011 — Multi-surface execution

Status: Accepted · Phase 2 / PR #11

Partially supersedes the *representational* clauses of
[ADR 0002](0002-engine-surface-wiring.md), [ADR 0004](0004-attribution-before-binding.md),
[ADR 0008](0008-driver-side-custody.md) and [ADR 0010](0010-finding-node-identity.md).
Discharges ADR 0005's deferred report-identity question.

## Context
[ADR 0009](0009-surface-resolution-contract.md) made surface resolution plural and
explicitly ordered, but the engine still drove only the first CHAT surface. Four decisions
were deferred to this PR by ADRs 0005, 0009 and 0010: report identity, surface collision in
Finding identity, `ApplicationTarget.scope` ownership, and failure semantics.

Measurement established the scale of the collision problem: **all 15 built-in probes send
fixed prompt strings**, and three (`excessive-agency-review`, `vector-rag-review`,
`supply-chain-review`) emit the literal marker `"(recon-derived)"`. Under ADR 0010's
three-part key every finding would therefore repeat identically on a second surface,
merging N surfaces' evidence into one node per finding — reinstating at N× scale the
fabrication class PR #10 removed.

A second measurement corrected an earlier assumption: **recon is a probe input, not only a
graph input.** `probes.py` reads `recon.tool_surface` and `recon.model_hints` while
assessing, and three probes derive their findings entirely from recon.

## Decision

### Execution model
The engine drives every surface `chat_surfaces_of()` returns, in that order, validating all
of them before any traffic. Per surface: its own `ReconResult`, its own capability tier, its
own applicability gate, its own probes and attackers, its own attribution, its own
reproduction. Findings concatenate surface-major; recon merges at run level.

### INV-1 — Surface execution order is defined exclusively by `chat_surfaces_of()`
The engine iterates exactly the sequence returned, in the order returned. It must not sort,
filter, re-order or deduplicate. Ordering is a property of the resolution layer (ADR 0009);
execution inherits it rather than re-deciding it.

### INV-2 — `scope_confirmed` is a run-level property
Computed once per run from `Engine.schema_tools`. It must never be derived from a
per-surface or merged `ReconResult`. It multiplies the CVSS base by 1.6 and so drives
`Finding.severity`; reading it from a union would let a side-effecting tool declared for one
endpoint inflate severity for findings from every other endpoint.

### INV-3 — The attacker budget contract is `PER_SURFACE`
`--adaptive` and `--genetic` budgets are per-surface exploration allowances; driving N
surfaces performs N × budget evaluations, and the effective total is reported. Naming the
contract is a backward-compatibility requirement: moving to a total-budget model later would
change which findings are produced, so any future total mode must arrive as an additional
named contract rather than a silent redefinition.

### INV-4 — All-surfaces-unreachable is a distinguishable outcome
Run-level `reachable` is true if any surface was; every unreachable surface is named in
`notes`. A report over an application where nothing was assessed must not be
indistinguishable from one where everything passed.

### Report identity
An `ApplicationTarget` run names the application (`base_url`); a bare `Surface` or a direct
run names the target, exactly as before. This discharges ADR 0005's deferral. Per-finding
provenance stays exact via `surface_id` and reproduction steps, so the header names the
assessment subject while findings name their endpoints.

### `ApplicationTarget.scope`
Authoritative for the application, and **verified, never propagated**: when set, every
driven target must present that same object or the run is refused with `TargetError` before
any traffic. This closes a field declared by ADR 0001 that had no reader, where an operator
attaching a scope received silent zero enforcement.

### Failure semantics
Ownership, governance and resolution failures abort the whole run before any traffic. A
surface unreachable at recon is skipped and named; its siblings continue. Probe and attacker
crashes stay per-surface, as before.

### `techniques_run`
A run-level property counting distinct techniques executed, owned by the orchestration layer.
Graph derivation was never sound: the graph excludes `passed` findings, so it can only know
which techniques produced graph-eligible evidence, never how many ran. The previous
implementation counted `len(g.nodes(NodeType.FINDING))`, reporting 27 on a baseline run in
which 23 distinct techniques ran and 21 probes were registered — a defect measurable on
v0.1.0-phase1 with a single surface, which restoring `surface_id` would have amplified ~N×.
Single-source-of-truth is unaffected: every evidence-derived analysis — posture, attack
paths, blast radius, trust boundaries, remediation — remains graph-native.

## Relationship to ADR 0010
ADR 0010 established Finding-node identity as `owasp_id:probe_name:subject_digest` and
deliberately excluded `surface_id`, because it was empty on every run and including it would
have broken the direct/surface graph equivalence of ADR 0002. That reasoning was correct for
its baseline and is now partly overtaken.

**ADR 0010's single-surface identity guarantee remains true.** A run with no bound surface
produces `surface_id = ""` and therefore node ids, edge ids and serialization byte-identical
to PR #10 apart from one added colon. Every CLI invocation is such a run. Its uniqueness
property is likewise preserved: one graph node per graph-eligible finding, verified on
single- and multi-surface runs alike.

**ADR 0010's surface-id exclusion guarantee is intentionally superseded for multi-surface
execution.** The identity becomes `owasp_id:probe_name:surface_id:subject_digest`.

**Behavioural equivalence remains.** A single-surface driven run produces findings
indistinguishable from a direct run: same statuses, severities, confidences, evidence hashes
and reproduction steps.

**Representational equivalence no longer does.** A surface-driven run's graph node ids carry
the surface component and therefore differ from a direct run's. This supersedes the
*serialization* clauses of ADRs 0002, 0004 and 0008 while preserving their behavioural
intent. The tests encoding representational equivalence — `TestSurfaceIdExcluded` in
`tests/test_finding_identity.py`, and the non-perturbation assertions in
`test_surface_wiring`, `test_surface_attribution` and `test_driver_custody` — were retired
knowingly, not incidentally.

## Alternatives considered
1. **Conditional `surface_id`** (only when N>1). Rejected: node ids would depend on how many
   surfaces the run drove — the non-locality ADR 0010 rejected.
2. **Merged recon for the probe loop.** Rejected: three probes derive findings entirely from
   recon, so one endpoint's self-reported tools would drive another's verdicts.
3. **Propagating `ApplicationTarget.scope` onto driven targets.** Rejected: mutating objects
   the engine does not own. Verification matches ADR 0005's established discipline.
4. **Dividing attacker budgets across surfaces.** Rejected: silently weakens every surface's
   assessment as the application grows.
5. **Deriving `techniques_run` from the graph.** Rejected: structurally impossible without
   parsing Finding node ids (prohibited by ADR 0010) or adding node types or metadata
   (prohibited by the frozen architecture).

## Consequences
- **Positive:** an application with several chat endpoints is assessed at all of them, with
  per-finding provenance, per-surface reproduction, and no cross-surface evidence merge. A
  safety-shaped field with no reader is closed. A pre-existing coverage defect is corrected.
- **Unavoidable:** surface-driven runs' node and edge ids differ from direct runs'; ten
  existing tests changed (eight superseded guarantees, two identity updates).
- **Unchanged:** direct runs, and therefore every CLI invocation. Replay bundles, SARIF,
  `diff.py`, the benchmark and `runtime_coverage_ratio` are unaffected.
- **Accepted:** driving several surfaces bound to the same stateful target lets earlier
  surfaces affect later ones. That is a property of the target, not of the orchestration —
  the surfaces genuinely share it.
- **Follow-up (not this ADR):** REST driver, MCP runtime driver, surface binding. Review risk
  D3 (operational controls enforced by the target rather than the driver) remains open and
  belongs to the first non-chat driver PR.
