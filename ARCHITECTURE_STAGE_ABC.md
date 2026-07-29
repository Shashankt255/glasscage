# GLASSCAGE Stage A–C — Architecture & Implementation Status

Version 1.1.0. This document uses explicit status labels for every feature:
**Implemented** · **Partial** · **Experimental** · **Roadmap**.

Backward compatibility: no existing public signature was broken. `Engine(target).run()`
works unchanged; every new capability is an additive constructor kwarg, CLI flag, or
result key. Existing 43 tests pass alongside 19 new Stage A–C tests (62 total).

---

## Stage A — Target Abstraction Layer (`tal.py`) — **Implemented**
**Rationale.** Prior versions let stateless single-turn probes assert stateful/agentic
results. TAL makes target capability an explicit contract and gates every probe by a
minimum tier.

**Tiers.** L0 single-turn · L1 stateful session · L2 tool-call observable (plan, tool
calls, memory, retrieval via a trace) · L3 provider-native (logprobs/multimodal, Roadmap).

**Mechanism.** `TargetCapabilities` derives a `Tier`. Every `Probe` declares `min_tier`.
The engine emits a **NOT ASSESSABLE** finding (new `Status`) when the target tier is
below the probe requirement — never a false PASS/FAIL. NOT ASSESSABLE is excluded from
coverage "tested" and from pass/fail scoring.

**Evidence.** Against the L0 mock, `planner-manipulation` and `tool-routing-manipulation`
report NOT ASSESSABLE (require L2); `memory-poisoning` requires L1. Against the L2
reference harness the same probes return VULNERABLE with `impact_confirmed=True`.
- Limitations: L3 (logprobs/multimodal) is declared but not exercised (Roadmap).
- Complexity: medium. Backward compatible: yes (new Status is additive).

## Reference agent harness (`refagent.py`) — **Implemented**
Deterministic, in-process, zero-network L2 target with planner, session memory,
retriever (poisonable doc store), MCP tool registry, tool router, and filesystem/
database/http_client/email/get_secret tools. Emits a real trace so agentic probes
CONFIRM exploitation. Vulnerability switches (`vuln_injection`, `vuln_memory_persist`,
`vuln_tool_routing`, `leak_secret`, …) model both vulnerable and hardened deployments.
- Limitations: emulation, not a real LLM; behaviours are scripted (by design, for
  determinism). Not a substitute for testing a real agent.
- Complexity: medium-high. Use: `--harness`.

## Stage B — Statistical evaluation (`stats.py`) — **Implemented**
**Rationale.** LLM outputs vary; a single run is a point estimate. `TrialRunner` repeats
each probe N times and reports success rate with a **Wilson score CI**, outcome variance,
a **reproducibility** metric (modal-outcome agreement), and deterministic replay via a
seed for seed-aware targets.
- Evidence: `--trials 7` on the harness yields e.g. rate 1.0, CI[0.65, 1.0], repro 1.0
  (deterministic target). Confidence is derived from interval width.
- Limitations: reproducibility is only meaningful for stochastic targets; the harness/mock
  are deterministic so they report 1.0 by construction.
- Complexity: medium. Use: `--trials N [--seed S]`.

## Stage C — Benchmark & validation (`benchmark.py`, `benchmark/corpus.json`) — **Implemented / Experimental corpus**
**Rationale.** Unit tests were tautological. The benchmark scores GLASSCAGE **detectors**
against a hand-labeled corpus the detectors never saw, yielding real precision/recall/F1
and explicit FP/FN lists — including the refusal-with-canary false-positive class.
- Evidence: on the shipped corpus, precision/recall = 1.0 (FP0/FN0). **This is indicative
  only**: the corpus is small (18 cases) and Experimental; do not read it as general accuracy.
- Limitations: corpus size; detector-level (not full end-to-end) measurement.
- Complexity: medium. Use: `--benchmark benchmark/corpus.json`.

## Stage C — Adapter architecture (`adapters/`, `orchestrator.py`) — **Implemented (orchestration) / Roadmap (external normalization)**
**Rationale.** Don't replace garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI — orchestrate and
benchmark them. Stable, versioned `ExternalToolAdapter` interface (`ADAPTER_API_VERSION`).
- **Implemented:** `NativeAdapter` (wraps the engine), `FakeAdapter` (deterministic, proves
  orchestration), the orchestrator, and honest availability gating.
- **Roadmap:** `garak/pyrit/promptfoo/deepteam/fuzzyai` adapters — interface + availability
  detection are real; result **normalization is not implemented** and is reported as such.
  They never fabricate results; unavailable tools are labelled unavailable.
- Evidence: orchestration table shows native (21 detections) + fake (1) available; external
  tools honestly "not installed in this environment".
- Complexity: low (interface) / medium (each real normalization). Use:
  `--orchestrate native fake garak pyrit promptfoo`.

---

## Status summary

| Feature | Module | Status |
|---|---|---|
| Capability tiers L0–L2 + gating | `tal.py`, `engine.py` | Implemented |
| Capability tier L3 (logprobs/multimodal) | `tal.py` | Roadmap |
| NOT ASSESSABLE status + coverage exclusion | `models.py`,`coverage.py` | Implemented |
| Reference agent harness (L2) | `refagent.py` | Implemented |
| Wilson CI + repeated trials + reproducibility | `stats.py` | Implemented |
| Deterministic replay (seeded) | `stats.py` | Implemented (seed-aware targets) |
| Detector benchmark (precision/recall/F1) | `benchmark.py` | Implemented |
| Labeled corpus | `benchmark/corpus.json` | Experimental (18 cases) |
| Adapter interface (versioned) | `adapters/base.py` | Implemented |
| Native + Fake adapters | `adapters/` | Implemented |
| garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI adapters | `adapters/external.py` | Roadmap (no result normalization) |
| Multi-tool orchestrator | `orchestrator.py` | Implemented (Roadmap for external results) |
| AI Attack Knowledge Graph | — | Roadmap (deliberately deferred to after Stage C) |

## Deliberately NOT built yet (per instruction)
The **AI Attack Knowledge Graph** is deferred until after the abstraction layer,
statistical engine, and validation framework — which are now complete.

---

## NEXT IMPLEMENTATION STAGE — Stage D (awaiting your go-ahead)
Candidates, in suggested order:
1. **Real external-adapter normalization** (garak/PyRIT first) — turn Roadmap adapters
   into Implemented so cross-tool detection-rate/precision benchmarking becomes real.
2. **Expand the labeled corpus** (100+ cases, multi-lingual, more attack classes) to move
   benchmark numbers from Experimental to credible.
3. **L3 tier** (logprob/multimodal targets) + multimodal injection probes.
4. Then the **AI Attack Knowledge Graph** as the substrate for chains/scoring/coverage.

Stopping cleanly after Stage C as instructed. Tell me which Stage D item to start.
