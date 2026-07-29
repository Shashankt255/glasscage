# GLASSCAGE Stage E5 — Migration to a Single Source of Truth

Version 1.4.0. Objective: make the AAKG the authoritative source for posture,
coverage, reporting, and remediation — eliminating duplicate logic. **No new node/
edge types, no new probes, no new attack techniques** were added. Backward compatible;
**104 tests pass** (91 prior + 13 Stage E5), zero regressions.

Status labels: **Implemented · Partial · Experimental · Roadmap**.

---

## 1. Architecture diff (before → after)

| Subsystem | Before (v1.3) | After (E5) | Status |
|---|---|---|---|
| Posture | `posture.py` recomputed 8 factors from findings/recon/trust/chains dicts | `aakg/posture.py` computes from graph evidence (demonstrated/hypothesized findings, tiers, trust, paths, blast, mitigations) with a per-point **contribution breakdown** | **Implemented** |
| Coverage | `coverage.py` counted OWASP ids from the findings list | `aakg/coverage.py` derives OWASP/ATLAS/CWE/CAPEC/NIST coverage from `mapped_to` edges, classified Demonstrated/Hypothesized/Not-Assessable/Untested | **Implemented** |
| Reporting (markdown) | `report.to_markdown` rebuilt sections from findings/trust/chains dicts | `aakg/report.to_markdown` queries the graph for every section | **Implemented** |
| Remediation | `kb.py`/`remediation.py` attached generic per-finding text | `aakg/remediation.py` ranks mitigations by measured graph impact (paths broken, blast reduced, violations resolved) and **cites nodes/edges** | **Implemented** |
| Trust / paths / blast | already graph-native in E1–E4 | unchanged | **Implemented** |
| Reporting (HTML) | `report.to_html` renders the results dict | unchanged — results are now graph-derived, so it presents graph truth | **Partial (presentation shim)** |
| Scoring grade (`scoring.py`) | legacy risk grade | unchanged; de-emphasized in favour of graph posture | **Roadmap (E6+)** |

The headline number (Posture Score) is now attributable point-by-point to graph
evidence. Example (reference harness): Risk 74.2 = exploitability 18.0 + privileges
9.0 + reachable_assets 7.0 + automation 7.2 + persistence 10.0 + blast_radius 7.0 +
business_impact 14.0 + chain_risk 2.0, each citing the graph nodes/edges behind it.

## 2. Dependency graph

```
                         glasscage.taxonomy (crosswalk)
                                  |
        glasscage.coverage(CANONICAL, KNOWN_GAPS)  \
                                  |                  v
   aakg.types  <--  aakg.engine  <--  aakg.build  --------------------+
      ^                 ^                 ^   ^   ^   ^                |
      |                 |                 |   |   |   |                |
  aakg.paths       aakg.trust_graph   aakg.blast  |   |               |
      ^   ^              ^   ^            ^  ^      |   |               |
      |   |              |   |            |  |      |   |               |
   aakg.posture  <-------+   |            |  +--- aakg.coverage         |
      ^                      |            |                            |
   aakg.remediation  <-------+------------+                            |
      ^                                                                |
   aakg.report  (posture, coverage, paths, trust, blast, remediation)  |
      ^                                                                |
      +----------------------- glasscage.engine --------------------- -+
```
- `aakg.engine`/`types` have **no intra-package dependencies** (pure substrate).
- `build` depends only on engine/types + taxonomy (reference data).
- paths/trust_graph/blast depend on engine + build.
- posture/coverage/remediation/report are **pure consumers** of the graph + the E2–E4
  engines. No consumer recomputes attack logic independently.
- `engine.py` imports the AAKG lazily inside `run()` (no import cycle; verified).

## 3. Migration summary
- **Removed duplication:** posture no longer re-derives blast/reachability (reads
  `blast.summary`/`trust_graph.analyze`); coverage no longer maintains its own tested-set
  logic beyond the canonical universe; the markdown report no longer rebuilds trust/chain
  sections from dicts; remediation no longer emits static generic advice as the primary
  recommendation.
- **Single traversal source:** attack paths, trust, and blast all read the one graph
  built per run; posture/coverage/remediation/report consume those results.
- **Engine wiring:** when `use_aakg=True` (default), `results["posture"|"coverage"|
  "trust"|"chains"|"blast"|"remediation_priorities"]` are all graph-sourced;
  `report_markdown` routes through `aakg.report`.
- **New result key:** `remediation_priorities` (ranked, graph-cited).

## 4. Remaining compatibility shims (explicit)
1. **Legacy `posture.py`, `coverage.py`, `chain.py`, `trust.py`** — retained and still
   tested; used only when `use_aakg=False`. Kept for backward compatibility and as a
   fallback; slated for removal once the graph path is the sole supported mode.
2. **`report.to_html` (results-driven)** — the interactive HTML is not yet a direct graph
   query; it renders the (graph-derived) results dict. Functionally correct, but a
   presentation shim. Graph-native HTML is **Roadmap**.
3. **`report.to_markdown` (legacy)** — remains for the `use_aakg=False` path only.
4. **`scoring.py` grade/risk_score** — legacy aggregate still computed for the summary
   line; superseded by graph posture, not yet removed.
5. **`coverage.statement()`** — still consumed by the HTML DATA block; graph coverage
   emits legacy keys specifically to keep it working.

None of these duplicate active graph logic; they are inert unless the legacy path is
selected, except (2) and (5) which format already-graph-derived data.

## 5. Performance comparison
Reference harness + 2 schema tools, 15 runs each (in-process, no network):

| Path | Mean | Std | Notes |
|---|---|---|---|
| Legacy (`--no-aakg`) | ~1.2 ms | 0.1 | findings-list posture/coverage, template chains |
| Graph (default) | ~3.1 ms | 0.9 | builds ~80-node graph, enumerates paths, 5-taxonomy coverage, ranks remediations |

Overhead ≈ **+1.8 ms/run (+147% relative, negligible absolute)** for substantially more
analysis. Cost scales with graph size and path depth (bounded by `max_depth=6`); for
large agentic targets, path enumeration is the dominant term and is the first place to
add caching/pruning if needed (Roadmap).

## 6. Full regression test results
```
Ran 104 tests in ~0.23s — OK (0 failures, 0 errors)
```
Breakdown: 43 original · 19 Stage A–C · 12 Stage D · 17 Stage E (E1–E4) · 13 Stage E5.
Includes explicit fallback tests proving `use_aakg=False` still works and graph vs legacy
both render reports.

---

## NEXT IMPLEMENTATION STAGE — awaiting instruction
E5 complete. **E6–E8 not started.** When you approve, natural E6 scope: migrate the HTML
report to query the graph directly and retire the legacy `posture.py`/`coverage.py`/
`chain.py`/`trust.py` shims once the graph path is declared the sole supported mode.
