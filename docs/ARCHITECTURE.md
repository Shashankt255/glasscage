# Architecture

> **This document is descriptive, not a design proposal.** The architecture is frozen
> as of Stage E5. It is provided so contributors and reviewers understand the existing
> implementation.

## Overview

GLASSCAGE has one organising idea: the **AI Attack Knowledge Graph (AAKG)** is the
single source of truth. Probes gather evidence; the graph is built once; every analysis
and report is a **query over that graph**. No subsystem recomputes findings
independently.

```
Target ──probes──> Findings + Evidence ──build──> AAKG
                                                   │
        ┌──────────────┬──────────────┬───────────┼───────────┬──────────────┐
        ▼              ▼              ▼           ▼           ▼              ▼
   Attack Paths   Trust Bound.   Blast Radius  Coverage   Posture     Remediation
        └──────────────┴──────────────┴───────────┴───────────┴──────────────┘
                                       │
                          Narratives · Story · Views  (renderers; read-only)
                                       │
                        Markdown · HTML · JSON · SARIF · Replay
```

## Module relationships

| Layer | Modules | Role |
|---|---|---|
| **Substrate** | `aakg/types.py`, `aakg/engine.py` (PropertyGraph), `aakg/build.py` | the graph and its construction |
| **Analysis** (query the graph) | `aakg/paths.py`, `trust_graph.py`, `blast.py`, `posture.py`, `coverage.py`, `remediation.py` | derive attack paths, trust boundaries, blast radius, risk index, coverage, remediation |
| **Reporting** (read-only renderers) | `aakg/report.py`, `narrative.py`, `story.py`, `views.py`, top-level `report.py`, `sarif.py` | markdown/HTML/JSON/SARIF, narratives, story, five audience views |
| **Acquisition** | `probes.py`, `agent_probes.py`, `target.py`, `refagent.py`, `recon.py`, `mcp.py` | send probes, capture evidence, model tiers |
| **Cross-cutting** | `evidence_confidence.py`, `redaction.py`, `stats.py`, `taxonomy.py`, `errors.py`, `logging_setup.py`, `config.py`, `plugins.py` | evidence classes, redaction, statistics, crosswalks, infra |
| **Experimental** | `benchmark.py`, `validation.py`, `genetic.py`, `mutation.py`, adapters | corpus benchmark, external-tool parsers |

## The AAKG

- **24 node types** (Finding, Evidence, Component, Tool, Asset, Secret, TrustZone,
  Mitigation, OWASP/ATLAS/CWE/CAPEC/NIST taxonomy nodes, …).
- **12 edge types** (`crosses`, `invokes`, `accesses`, `enables`, `affects`, `requires`,
  `mapped_to`, `mitigates`, `verified_by`, `observed_on`, `trusts`, `hypothesized_by`).
- **3 edge states**, monotonic (never downgraded): `demonstrated` → `hypothesized` →
  `not_assessable`.
- **Deterministic:** stable node/edge ids, sorted traversal, exact serialization
  round-trip (`to_dict`/`from_dict`), property-tested.

See [GRAPH_MODEL.md](GRAPH_MODEL.md) for the full node/edge catalogue.

## Graph lifecycle

1. **Recon** — capability tier assessed (L0–L3); tool surface discovered.
2. **Probe** — probes send payloads; each returns a `Finding` with evidence; below-tier
   probes return `NOT ASSESSABLE`.
3. **Build** — `build.build_graph(...)` assembles nodes/edges from findings, schema, MCP
   manifest, and (trusted) architecture answers.
4. **Analyse** — paths/trust/blast/coverage/posture/remediation query the graph. Results
   are memoized; the cache is invalidated on any mutation.
5. **Render** — narratives/story/views select existing graph objects and render them.
   They perform **no analysis** and create no nodes/edges.
6. **Emit** — markdown/HTML/JSON/SARIF/replay.

## Design invariants (enforced, not aspirational)

- **Single source of truth:** analyses query the graph; none recompute findings.
- **No fabrication:** unavailable tools/targets yield `Not Tested` /
  `Pending External Validation`, never synthetic data.
- **Evidence ceiling:** `EvidenceClass.at_most()` clamps any claim to its evidence; a
  narrative can never exceed its weakest hop.
- **Determinism:** same inputs → same graph → same report.
- **Renderers read; they never analyse.**

## Known architectural debt (for transparency)

- A legacy `graph.py` (attack-surface graph) still coexists with `aakg/`.
- Legacy `posture`/`coverage`/`chain`/`trust` shims still ship for `--no-aakg` and are
  deprecated (removal planned next major).
- `PropertyGraph` exposes `node(id)` but not `edge(id)`; a renderer works around this
  with a linear scan (a known performance cost).
- 16 broad `except Exception` handlers remain.

See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for how these affect contribution.

## Phase 1 foundation
See [`docs/targets.md`](targets.md) and [ADR 0001](adr/0001-surface-driver-foundation.md) for the additive Surface/Driver model introduced in Phase 1.

[ADR 0002](adr/0002-engine-surface-wiring.md) wires it into the engine: `Engine(target,
surface=...)` routes probe/recon/attacker traffic through a bound CHAT surface via the
`targets.SurfaceTarget` shim. Probes are unmodified — `Observation` and `ChatResponse`
agree on every field any caller reads. Omitting `surface=` reproduces the previous
behaviour exactly, and identity/custody/reproduction still read the target.
