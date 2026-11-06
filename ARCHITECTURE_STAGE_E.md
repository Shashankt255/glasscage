# GLASSCAGE Stage E — AI Attack Knowledge Graph (AAKG)

Version 1.3.0. Stage E introduces the AAKG as the core substrate. This document
covers **E1–E4 only** (E5–E8 not started, per instruction) with explicit status
labels: **Implemented · Partial · Experimental · Roadmap**.

Backward compatibility: no public signature broken. `Engine(target).run()` works
unchanged and now derives trust/chains/blast from the graph; `--no-aakg` restores the
legacy path. **91 tests pass** (74 prior + 17 Stage E), zero regressions.

Design priority (as directed): correctness, maintainability, extensibility over
feature count. Every graph operation is deterministic (sorted traversal, deterministic
ids) and reproducible (serialization round-trips exactly).


## E1 — Graph engine — **Implemented**  (`aakg/types.py`, `aakg/engine.py`, `aakg/build.py`)
A lightweight, stdlib-only directed **property graph**.
- **Strongly typed nodes** (all 24 required): Finding, Evidence, Asset, Component,
  User, LLM, Planner, Memory, Retriever, MCP, Tool, API, Database, Filesystem,
  Secrets, TrustZone, Mitigation, OWASP, ATLAS, CAPEC, CWE, NIST, CapabilityTier.
- **Strongly typed edges** (all 12 required): enables, requires, invokes, accesses,
  crosses, trusts, mitigates, mapped_to, verified_by, hypothesized_by, observed_on,
  affects.
- Every node/edge carries metadata, timestamp, confidence, evidence_refs, provenance.
- **Edge epistemic state** (`EdgeState`): demonstrated / hypothesized / not_assessable,
  with **monotonic upgrade** (a demonstrated edge is never silently downgraded).
- Deterministic ids (`node_id`, `edge_id`); idempotent construction (re-adding merges);
  `to_dict/from_dict/to_json` round-trip exactly; `simple_paths`, `reachable`, `stats`.
- `build.py` assembles the graph from recon + findings + schema tools + MCP +
  architecture + taxonomy, deriving each edge's state from evidence (impact-confirmed →
  demonstrated; schema-reachable → hypothesized; tier-gated → not_assessable).

## E2 — Attack-path engine — **Implemented**  (`aakg/paths.py`)
Replaces template exploit chains with **dynamic traversal** from the untrusted User to
high-value assets along crosses/invokes/accesses edges.
- Each edge is marked demonstrated / hypothesized / not_assessable; a **path's state is
  its weakest edge** (only fully-demonstrated paths are "demonstrated").
- Every path carries supporting **evidence_refs** gathered from its edges, a likelihood,
  a severity, and a Mermaid rendering. Output is chain-shaped for backward-compatible
  reporting. Deterministic ordering (demonstrated first, then likelihood, then id).
- Verified: at L2 the harness yields real user→Secrets/Database paths; at L0 the agentic
  hops are not_assessable, so no false "demonstrated" path is ever claimed.

## E3 — Trust-boundary engine — **Implemented**  (`aakg/trust_graph.py`)
Trust analysis now runs **entirely on the graph**.
- Detects **privilege transitions** (edges into a higher trust zone), **trust-boundary
  crossings**, **excessive privilege** (a semi-trusted component reaching >1 trusted
  asset), **least-privilege violations** (demonstrated reach into a trusted asset with no
  mitigation), and **assets reachable from the untrusted user** (graph reachability).
- Emits the legacy trust dict shape (so existing report/posture code is unchanged) plus
  new fields (`excessive_privilege`, `least_privilege_violations`, `source: "aakg"`).
- Mitigation nodes (from architecture answers) suppress violations — verified by test.

## E4 — Blast-radius simulation — **Implemented**  (`aakg/blast.py`)
Answers "if this finding succeeds, what becomes reachable?" by traversing
enables/invokes/accesses/affects from a finding and collecting reachable components,
tools, secrets, and assets **from observed graph relationships**, not static heuristics.
- Run-level `summary()` originates from the strongest demonstrated enabler and computes a
  multiplier scaled by reachable high-value assets, discounted when only hypothesized.
- Verified: at L2 a demonstrated memory-poisoning finding yields a demonstrated blast to
  Secrets+Database (multiplier 2.0); at L0 the basis is correctly "hypothesized".


## Integration & backward compatibility
- The engine builds the AAKG after scoring and derives `trust`, `chains`, and `blast`
  from it; results gain `aakg` (graph stats) and `blast`. `--no-aakg` uses the legacy
  `trust.py`/`chain.py` path (still fully tested).
- Reporting, posture, coverage, benchmarking, validation, and remediation are **not yet
  migrated to consume the graph** — they still work via the compatible trust/chains
  shapes. Full migration of those subsystems is **Roadmap (E5–E8)**.
- `--out X` now also writes `X_aakg.json` (the serialized graph, for replay/inspection).

## Status summary
| Feature | Module | Status |
|---|---|---|
| Property-graph engine (24 node, 12 edge types) | `aakg/engine.py`,`types.py` | Implemented |
| Evidence-derived edge state + monotonic upgrade | `aakg/build.py` | Implemented |
| Deterministic traversal + serialization round-trip | `aakg/engine.py` | Implemented |
| Attack-path engine (weakest-link state, evidence) | `aakg/paths.py` | Implemented |
| Trust-boundary engine on graph | `aakg/trust_graph.py` | Implemented |
| Blast-radius simulation on graph | `aakg/blast.py` | Implemented |
| trust/chains/blast sourced from AAKG in engine | `engine.py` | Implemented |
| Graph export (`X_aakg.json`) | `cli.py` | Implemented |
| Posture/coverage/report/benchmark consuming graph natively | — | Roadmap (E5–E8) |
| Remediation reasoning over graph | — | Roadmap |
| Graph query language / persistence backend | — | Roadmap |

## NEXT IMPLEMENTATION STAGE — awaiting instruction
E1–E4 complete and tested. **E5–E8 not started.** Natural E5 scope when you approve:
migrate posture scoring and coverage to read directly from the AAKG (so scores are
computed from graph evidence rather than the compatibility shims), then reporting and
remediation. Say the word to proceed.
