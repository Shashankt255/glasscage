# GLASSCAGE Stage D — External Integration, Benchmarking & Validation

Version 1.2.0. Focus: scientific credibility and enterprise trust — not new attack
features. Status labels are explicit: **Implemented · Partial · Experimental · Roadmap**.

Backward compatibility: no public signature broken. `Engine(target).run()` unchanged.
All Stage D capability is additive (new modules, CLI flags, result keys). Test count:
**74 pass** (43 original + 19 Stage A–C + 12 Stage D).

Hard honesty rule honored throughout: external tools that are neither installed nor
supplied an output file are reported **Not Tested** and contribute **zero** findings.
No synthetic external results are ever produced.


## D1 — External tool integration (`adapters/`, `taxonomy.py`)
Production normalization from each framework's **native output** into the canonical
GLASSCAGE `Finding`, preserving `source_framework`, `source_rule_id`, `confidence`,
evidence, `timestamp`, `raw_output`, and full OWASP/ATLAS/CWE/CAPEC/NIST taxonomy.

| Adapter | Parser | Live run | Status |
|---|---|---|---|
| garak (`report.jsonl`) | verified vs NVIDIA format | needs garak installed | **Implemented (parser) / Partial (live)** |
| Promptfoo (eval JSON) | documented shape | needs promptfoo | **Implemented (parser) / Experimental (live)** |
| PyRIT | representative export | DuckDB memory export varies | **Experimental** |
| DeepTeam | representative RiskAssessment | needs deepteam | **Experimental** |
| FuzzyAI | representative results | needs FuzzyAI | **Experimental** |

- Parsers are unit-tested against representative fixtures in `adapters/fixtures/`.
  garak's format was verified against NVIDIA documentation (entry_type rows; `attempt`
  status 0/1/2; `detector_results` name→[scores]; `probe_classname`) and the parser
  correctly drops sub-threshold attempts.
- `taxonomy.py` is a static crosswalk (OWASP→ATLAS/CWE/CAPEC/NIST) plus a keyword
  classifier that maps external rule/probe/plugin ids onto OWASP. CAPEC/NIST are
  best-effort advisory. **This is not the AI Attack Knowledge Graph** — deliberately a
  lookup table; the KG remains deferred.
- Honest limitation: fixtures represent documented formats; live parsing may need
  per-version adjustments. Real external output can be fed via
  `--adapter-file tool=path` today (fully supported, tested path).

## D2 — Benchmark corpus (`benchmark/corpus.json`)
Expanded 18 → **109 labeled cases**. 77 text-measurable, 32 tier-gated (trace-only).
Each case carries expected outcome, reasoning, labels, references, category, confidence,
and `min_tier`. Categories: prompt/indirect/multilingual/unicode/role-play injection,
secret disclosure, refusal FP/FN, harmless controls, plus trace-only planner/memory/
retrieval/MCP/tool-misuse/excessive-agency/delayed-trigger/scratchpad/reflection cases.
- **Deliberately includes hard cases the exact-match oracle must miss** (canary-stripped
  injections, obfuscated secrets, interposed multilingual refusals). Status: **Experimental**
  (small, hand-labeled; indicative not population-level).

## D3 — Measurement framework (`benchmark.py`, `stats.py`)
Precision, recall, F1, accuracy — each with **95% Wilson confidence intervals** — plus
FP/FN lists, per-detector and per-category breakdown, coverage, execution time, and
reproducibility. Detectors covered: injection, indirect, disclosure, refusal. Trace/
tier-gated cases are excluded from metrics and reported separately (never scored).
- Measured result on the shipped corpus: **Precision 0.97 [0.85, 0.99], Recall 0.91
  [0.78, 0.97], F1 0.94**, with 1 FP and 3 FN — all documented, legitimate detector
  limitations (e.g. a German refusal that interposes the canary defeats the substring
  detector). Status: **Implemented**.
- Posture scores are always emitted with their interval (Stage-6 rule upheld).

## D4 — Independent validation (`validation.py`)
Runs multiple adapters against one shared target and compares: detection overlap,
per-tool unique categories, pairwise **Jaccard agreement**, runtime, and **native
reproducibility** (two identical runs). Unavailable tools → **Not Tested**.
- Demonstrated: native (21) + fake (1) live; garak/promptfoo via `from_file`; pyrit
  Not Tested. Native reproducibility 1.0. Status: **Implemented (mechanism)**; real
  cross-tool numbers require the tools installed or their output files supplied.

## D5 — Paper-quality report (`validation.paper_report`)
Auto-generated `*_VALIDATION_REPORT.md` covering methodology, assumptions, limitations,
corpus description, benchmark results with CIs, cross-framework comparison, statistical
methods, and maturity labels. Reproducible: `python cli.py --validate --harness`.
Status: **Implemented**.


## New CLI (all additive)
- `--harness` — deterministic L2 reference agent as target
- `--trials N [--seed S]` — Wilson-CI statistical runs
- `--benchmark corpus.json` — detector benchmark, then exit
- `--orchestrate native fake garak …` — multi-tool run + table
- `--adapter-file garak=out.jsonl promptfoo=out.json` — normalize saved native output
- `--validate` — benchmark + cross-framework validation + paper report

## Honest status summary
- **Implemented:** taxonomy crosswalk + enrichment; garak & promptfoo parsers; native/
  fake adapters; orchestrator; benchmark with Wilson CIs; validation harness; paper report;
  109-case corpus loader; `--adapter-file` normalization path.
- **Partial:** live execution of garak/promptfoo (parser tested; live needs the tool).
- **Experimental:** PyRIT/DeepTeam/FuzzyAI parsers (representative fixtures; live
  compatibility unverified); corpus size/label coverage.
- **Roadmap:** L3 tier + multimodal; large-scale live external orchestration; expanded,
  peer-reviewed corpus; **AI Attack Knowledge Graph** (still deferred).

## NEXT IMPLEMENTATION STAGE — awaiting instruction
Stage D is complete and internally validated. Per your directive, the AI Attack
Knowledge Graph (Stage E) is **not** started. Suggested Stage E scope when you're ready:
promote the KG from the static `taxonomy.py` crosswalk into a queryable graph substrate
that chains/scoring/coverage/validation all read from. Tell me to proceed.
