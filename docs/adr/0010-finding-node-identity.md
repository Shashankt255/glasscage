# ADR 0010 — Finding-node identity

Status: **Accepted (revised)** · Phase 2 / PR #10

> **Extended by [ADR 0011](0011-multi-surface-execution.md).** The single-surface identity
> guarantee below remains true — a direct run is unchanged. The `surface_id` *exclusion*
> is intentionally superseded for multi-surface execution: the key is now
> `owasp_id:probe_name:surface_id:subject_digest`.

Revision: `surface_id` removed from the identity composition following implementation
findings. All other content stands.

## Context
`aakg/build.py` keyed Finding nodes as `f"{owasp_id}:{probe_name}"`. This is not unique.
Measured on v0.1.0-phase1, **two independent collision sources exist**:

| Collision | Count | Cause |
|---|---|---|
| `MCP07:mcp-analyzer` | ×2 | `mcp.analyze_manifest` emits one finding per flagged tool |
| `LLM06:architecture-review` | ×3 | `architecture.assess` emits one finding per control |

`PropertyGraph.add_node` merges on collision, keeping the **first** writer's label and
`dict.update`-ing metadata from the **last**, producing a node whose label describes one
finding and whose status describes another:

```
id     : Finding:MCP07:mcp-analyzer
label  : "Tool 'fetch_url' takes a URL/path param; validate against SSRF"   <- inconclusive
status : "vulnerable"                                                        <- metadata_probe
```

Reproducible with shipped inputs: `python -m glasscage --demo --mcp-manifest
samples/mcp_manifest.json`. In a maximal run, 29 graph-eligible findings produced 26 nodes.
The defect is independent of surface driving - identical with and without a bound `Surface`.

This fabricates a per-tool verdict and breaches the evidence ceiling, both documented as
*enforced* invariants in `ARCHITECTURE.md`.

## Decision

```
Finding node key  =  owasp_id : probe_name : subject_digest

subject_digest    =  first 12 hex chars of sha256( normalise(prompt) )
normalise(s)      =  collapse all whitespace runs to a single space, then strip
```

Full node id, via the unchanged `node_id(ntype, key)` helper:

```
Finding:<owasp_id>:<probe_name>:<subject_digest>
```

No new node type. No new edge type. No change to `PropertyGraph.add_node`'s merge policy -
that policy is sound once identity is unique. No consumer change: Finding node ids are
opaque to all eleven consumers (the five `.id.split()` sites parse taxonomy, mitigation and
evidence ids, never Finding).

## Revision: why `surface_id` was removed
The first revision included `surface_id` as a fourth component, on forward-compatibility
grounds for PR #11. Implementation proved that unsound. Measured:

| Composition | Tests | Collisions resolved |
|---|---|---|
| `owasp:probe:surface_id:digest` | **345/350** - 5 failures | 29/29 |
| `owasp:probe:digest` | **350/350** | **29/29** |

1. **`surface_id` contributes nothing to the defect this ADR fixes.** The prompt digest
   alone separates both collision groups. `surface_id` is empty on every current run and
   therefore discriminates nothing today.
2. **`surface_id` breaks a higher invariant.** On a surface-driven run it is `"chat"`; on a
   direct run `""`. Including it makes surface-driven graphs differ from direct graphs,
   failing five tests that encode three accepted ADRs: `test_surface_wiring.TestEquivalence`
   (×3, **ADR 0002**), `test_surface_attribution.TestNonPerturbation` (**ADR 0004**), and
   `test_driver_custody.TestNonPerturbation` (**ADR 0008**).

### Why direct/surface graph equivalence is the higher invariant
ADR 0002's central claim - the sole basis on which surface driving was accepted into the
engine - is that routing through a `Surface` changes nothing observable. That equivalence is
the correctness argument for the entire Phase 1 wiring: it let PR #1 modify `Engine.run()`
while asserting zero behavioural risk, and it is the stated reason PR #3 **rejected** a
`--surface` CLI flag as delivering "zero user-visible capability" - a decision that becomes
retroactively wrong if the flag would in fact alter the graph. ADRs 0004 and 0008 each
re-asserted it with a dedicated test.

Against that, `surface_id`-in-the-key buys anticipation of a feature that does not exist. A
three-ADR invariant defended by five tests outranks forward compatibility for unwritten
code. Correcting a live defect must not cost an accepted invariant when the two are
separable - and they are, exactly.

### Why surface identity is deferred to PR #11
- **Today there is at most one driven surface per run**, so the component encodes no
  information and only perturbs ids.
- **PR #11 is the first PR in which multiple runtime surfaces exist.** Only there does
  surface differentiation discriminate anything, and only there must the direct/surface
  equivalence question be re-posed anyway - a run driving N surfaces is not equivalent to a
  single-target run, so ADRs 0002/0004/0008 must be revisited by PR #11 on their own terms.
- **It keeps the two changes in their own layers.** Node identity is substrate; surface
  differentiation is a consequence of orchestration.

**Accepted, documented consequence for PR #11.** Without `surface_id`, findings identical in
category, probe and prompt across two surfaces will collide. The concrete case is
surface-gated findings (ADR 0006), which all carry `prompt = "(surface-gated)"` -> digest
`50ec532166cd`; two surfaces gating the same probe would both key to
`LLM01:<probe>:50ec532166cd`. **PR #11 must resolve this**, recorded here as a named
prerequisite rather than a latent surprise.

## Candidate evaluation
**Rejected as non-discriminating:** `probe_name`, `owasp_id`, the current pair, `category`,
`cwe_id`/`capec_id`/`nist_id`, `atlas_id`, `assessed_tier`/`required_tier`,
`source_framework` - measured constant or shared across both colliding groups.

**Rejected as unpopulated:** `source_rule_id` - semantically closest, but empty on both
colliding populations; populating it requires out-of-scope edits to `mcp.py`/
`architecture.py`. Recorded as the durable follow-up.

**Rejected as unstable:** `evidence_hash` - derived from the target's reply, so a node would
re-key whenever the target's behaviour changed, inverting provenance. `status`/`severity` -
outcome, not identity; a behavioural change would create a new node instead of updating one.
`trials_run`/`success_rate`/`ci_*`/`reproducibility` - vary with `--trials`. `title` - prose;
a wording edit would silently re-key nodes.

**Rejected as out of model:** `locator` (a `Surface` field), `Observation` (transient),
`reproduction_steps` (derived, verbose, target-coupled).

**Rejected as structurally invalid:** ordinal position (order-derived); set-relative
discriminators (non-local ids - a node's id would depend on what else is in the run);
convention-coupled prefix parsing (would make the analysis layer encode `mcp.py`'s and
`architecture.py`'s prompt string formats, inverting the dependency direction).

**Deferred:** `surface_id`, as above.

**Accepted:** `prompt`, whitespace-normalised and digested. It is the only existing field
carrying *what the finding is about* - `mcp.py` writes `"tool: <name>"`, `architecture.py`
writes `"(assessed) <control>"`, probes write the payload sent. Digested rather than raw
because payloads run 60-200+ characters and would embed attack strings and canaries verbatim
into node ids, which are **not** covered by the redaction pass that processes finding fields.

## Properties

**Unique.** Measured: 29 graph-eligible findings -> 29 distinct keys, zero residual
collisions. Two findings share a key only when they share category, probe and assessed
subject - at which point they are the same finding and merging is correct.

**Deterministic.** A pure function of three `Finding` field values. No timestamps, counters,
random state, I/O, or set-relative lookup. No dependence on emission order.

**Stable.** Verified identical across repeated runs, across `--seed 1` and `--seed 999`
(including `adaptive-attacker` `48347d438e9d` and `genetic-attacker` `1f74f6108f6a`), and
across run configurations (`planner-manipulation` digests `7c22f0d77a97` in minimal,
maximal and repeated runs). **No component depends on the target's response**, so a
behavioural change updates a node's metadata instead of re-keying it - which is what makes
cross-run graph comparison meaningful.

**Content-derived, not order-derived.** Every component is intrinsic to the finding.
Reordering probes, changing the probe selection, or shuffling the findings list leaves every
other finding's key untouched.

**Leaks nothing.** The digest is one-way; `build_graph` runs *after* `redaction.redact_all`,
so the digested prompt is already redacted; and no raw prompt text enters the id.

## Worked examples
All ids measured, not derived.

### The MCP collision - one node -> two
| | Before | After |
|---|---|---|
| `tool: fetch_url` (inconclusive) | `Finding:MCP07:mcp-analyzer` | `Finding:MCP07:mcp-analyzer:ca58bd41c936` |
| `tool: metadata_probe` (vulnerable) | *(merged into the above)* | `Finding:MCP07:mcp-analyzer:f74b6ac34d23` |

### The Architecture collision - one node -> three
`Finding:LLM06:architecture-review` becomes
`...:05a85ae420d3`, `...:873d0c42717e`, `...:c975880b427d`.

### Non-colliding findings - one node before, one after, new id
| Finding | Before | After |
|---|---|---|
| `direct-injection-canary` | `Finding:LLM01:direct-injection-canary` | `...:3cb153335f4a` |
| `planner-manipulation` | `Finding:LLM01:planner-manipulation` | `...:7c22f0d77a97` |
| `adaptive-attacker` | `Finding:LLM01:adaptive-attacker` | `...:48347d438e9d` |
| `genetic-attacker` | `Finding:LLM01:genetic-attacker` | `...:1f74f6108f6a` |

### Direct vs surface-driven - now identical (the point of the revision)
Both produce `Finding:LLM01:direct-injection-canary:3cb153335f4a`. Under the superseded
four-part composition these were `...::3cb153335f4a` and `...:chat:3cb153335f4a`.

## Consequences
**Positive** - every graph-eligible finding becomes exactly one node (29/29 maximal,
17/17 MCP path, 18/18 demo, 14/14 harness); the fabricated per-tool verdict is gone;
identity is local, content-derived and target-behaviour-independent; direct/surface
equivalence preserved; 350 pre-existing tests pass unmodified.

**Unavoidable** - all Finding node ids change; edge ids incident to them change with them,
because `edge_id` embeds node ids (7 edges on the previously-collided node); node and edge
counts rise where a collision was masking a finding.

**Measured non-changes** - posture 45.4 / risk 54.6 unchanged; `runtime_coverage_ratio` 0.54
unchanged; replay bundles, SARIF and the benchmark unaffected. The first revision predicted
a posture shift; measurement shows none, because the recovered findings are `info`-severity
and contribute no posture points. The prediction was wrong and is corrected here.

**Accepted limitations** - the subject is carried by `prompt` **by convention, not
contract**; the durable fix is populating `source_rule_id` (follow-up). `diff.py:15` uses
the same collapsing tuple independently and still merges those findings (follow-up,
different layer). A 12-hex digest gives ~2^-48 accidental-collision probability per pair
within single-digit groups; widenable without changing composition. Surface differentiation
deferred to PR #11 with the named collision above.

**Follow-up (not this ADR):** populate `source_rule_id` for subject-per-finding probes;
align `diff.py`'s comparison key; multi-surface execution (PR #11), which inherits a correct
substrate and must resolve the deferred surface collision.
