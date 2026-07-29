# Changelog

All notable changes. Versions prior to 1.0.0rc1 were internal stage-build milestones
during development; the first public release candidate is **1.0.0rc1**.

## [1.0.0rc3] — Attack Narratives & Assessment Story
Reporting layer only. No new analysis, graph node types, attack techniques, or scoring.
### Added
- `aakg/narrative.py`: NarrativeModel + 8 strategies (filters over existing paths), strategy
  dedup, full per-transition citation (node ids, edge id, evidence ids, confidence, state).
- `aakg/story.py`: 13-section Assessment Story, each section evidence-classified.
- `aakg/views.py`: executive / security / developer / incident_response / compliance views
  over the same models; `--views` CLI flag writes `<out>_view_<audience>.md`.
- Narratives + story integrated into markdown, HTML, JSON, and the executive summary.
- `docs/NARRATIVES.md` (incl. honest limitations) and `docs/examples/` before/after reports.
### Changed
- Markdown "Attack Paths" section condensed to an index table (prose now lives in the
  narratives) to avoid duplicating the same information twice.
- `report.write_json` / `report.to_html` accept optional `narratives`/`story` (omitting them
  reproduces the previous output exactly).
### Unchanged (by design)
- SARIF output and replay bundles.
### Tests
- 189 passing (+44), including anti-hallucination guarantees: every cited node/edge must
  exist in the graph, states must match graph edges verbatim, no path may be invented, and
  hostile model text must be HTML-escaped.

## [1.0.0rc1] — Release Candidate hardening
Engineering quality only; no new security capabilities, node types, or graph features.
### Added
- Typed error hierarchy (`errors.py`), structured logging (`logging_setup.py`, JSON
  option), configuration validation (`config.py`), `--log-level/--log-json` flags.
- Formal Plugin SDK (`PLUGIN_API_VERSION`, version gating, contract validation) + example.
- `python -m glasscage`; `py.typed`; richer `pyproject.toml` (extras, classifiers, URLs).
- Developer CI (`.github/workflows/ci.yml`), `Makefile`, profiling + perf tools.
- Fuzz tests, stdlib property-based tests, hardening tests (config/errors/logging/plugin/cache).
- Developer docs, Plugin SDK doc, graph-model reference, auto-generated API docs (pydoc).
- Graph analysis cache (paths/trust/blast memoized; invalidated on mutation; ~56x on repeat).
### Changed
- Target construction now validates config and raises `ConfigError` with clear messages.
### Removed
- Dead modules `validation_report.py`, `build_corpus.py`; dead `--paper` CLI branch;
  unused imports across the codebase.
### Tests
- 125 passing (unit/integration/fuzz/property/hardening), zero regressions.

## [1.4.0] — Stage E5: single source of truth
Posture, coverage, reporting, remediation migrated to read the AAKG directly.

## [1.3.0] — Stage E (E1–E4): AI Attack Knowledge Graph
Property-graph engine, attack-path engine, trust-boundary engine, blast-radius sim.

## [1.2.0] — Stage D: external integration & validation
garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI normalization adapters; 109-case corpus; Wilson
CIs; cross-framework validation; paper report.

## [1.1.0] — Stages A–C: abstraction, statistics, validation
Target Abstraction Layer (tiers L0–L3), NOT ASSESSABLE, statistical engine, benchmark,
reference agent harness.

## [1.0.0] — platform upgrade
Exploit chains, genetic engine, agent probes, trust boundaries, posture, SARIF/replay.

## [0.5.0] — initial hardened prototype
Probes, recon, CVSS-style scoring, interactive report, evidence, audit log.
