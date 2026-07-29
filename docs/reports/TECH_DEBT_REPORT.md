# Technical Debt Report — 1.0.0rc1

## Resolved this RC
- Removed dead modules (`validation_report.py`, `build_corpus.py`) and a broken
  `--paper` CLI branch; cleaned unused imports (cvss/probes/graph/aakg).
- Added typed errors, structured logging, config validation, formal Plugin SDK.
- Added graph analysis caching (removes redundant recomputation across posture/
  remediation/report).

## Remaining debt (tracked, not blocking RC)
1. **Legacy fallback shims** — `posture.py`, `coverage.py`, `chain.py`, `trust.py`
   remain for `--no-aakg`. Duplicate the graph engines' intent. *Plan:* remove in E6
   once graph path is the sole supported mode. Risk: low (inert unless `--no-aakg`).
2. **HTML report is results-driven, not a direct graph query** — presentation shim over
   graph-derived data. *Plan:* graph-native HTML in E6.
3. **`scoring.py` legacy grade/risk_score** — superseded by graph posture; still emitted
   in the summary line. *Plan:* remove after downstream consumers drop it.
4. **External adapter live-run paths (garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI)** — parsers
   are unit-tested against representative fixtures; **live execution is unverified**
   because the tools are not installed in this environment. *Gate:* run against real
   installed tools before GA (see Release Checklist item 20).
5. **Corpus size** — 109 hand-labeled cases (Experimental). *Plan:* grow to peer-reviewed
   scale for credible population-level metrics.
6. **Lint/type gates advisory** — CI runs `ruff`/`mypy` non-blocking during RC. *Plan:*
   make blocking once the codebase is annotated.

## Deliberately out of scope (frozen architecture)
No new node/edge types, probes, attack techniques, or redesign, per RC directive.
