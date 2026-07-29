# Architecture Stability Report — 1.0.0rc1

## Status: FROZEN (as of Stage E5)
The AI Attack Knowledge Graph is the single source of truth. No new node/edge types,
probes, or graph features were added in the RC.

## Module boundaries
- **Substrate:** `aakg/engine`, `aakg/types` — no intra-package dependencies.
- **Builder:** `aakg/build` — depends on substrate + `taxonomy` (reference data only).
- **Analyses (read-only consumers):** `aakg/paths`, `trust_graph`, `blast`, `posture`,
  `coverage`, `remediation`, `report`. None recompute attack logic independently.
- **Orchestration:** `engine.py` builds one graph per run and derives all outputs.
- **Infra:** `errors`, `logging_setup`, `config`, `plugins` — cross-cutting, no cycles.

## Dependency integrity
- No import cycles (verified; `engine` imports `aakg` lazily inside `run()`).
- 55 modules documented via pydoc.
- Determinism guarantees hold: sorted traversal, deterministic ids, exact
  serialization round-trip (property-tested over random graphs).

## Change-control expectations post-RC
- Adding capabilities = new probes/adapters/plugins (extension points), not core edits.
- Any new node/edge type is a **major** architectural change requiring review.
