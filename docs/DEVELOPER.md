# GLASSCAGE Developer Guide

Zero-dependency Python (stdlib only) security assessment platform built around the
**AI Attack Knowledge Graph (AAKG)**.

## Layout
- `glasscage/` — library
  - `aakg/` — the graph substrate (E1) and graph-native engines: `engine` (property
    graph), `types`, `build`, `paths` (E2), `trust_graph` (E3), `blast` (E4),
    `posture`, `coverage`, `remediation`, `report` (E5).
  - `probes.py`, `agent_probes.py` — probes (declare `min_tier`).
  - `tal.py` — capability tiers L0–L3. `target.py` — HTTP target. `refagent.py` — L2
    reference harness.
  - `adapters/` — external framework adapters (garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI).
  - `stats.py`, `benchmark.py`, `validation.py` — measurement & validation.
  - `taxonomy.py` — OWASP↔ATLAS↔CWE↔CAPEC↔NIST crosswalk.
  - `errors.py`, `logging_setup.py`, `config.py`, `plugins.py` — production infra.
- `cli.py` — command line; `python -m glasscage` also works.
- `tests/` — unittest suites (unit, integration, fuzz, property, hardening).
- `tools/` — `profile_run.py`, `benchmark_perf.py`, `gen_api_docs.py`.

## Run
```
python -m unittest discover -s tests -q      # all tests
python cli.py --harness --out report         # run against the reference agent
python cli.py --demo --adaptive --genetic --sarif --out report
python -m glasscage --benchmark benchmark/corpus.json --out b
```

## Architecture rule (frozen at Stage E5)
The AAKG is the single source of truth. Posture, coverage, remediation, and the
markdown report are computed by querying the graph — do not reintroduce independent
calculations. Legacy `posture.py`/`coverage.py`/`chain.py`/`trust.py` exist only as
`--no-aakg` fallbacks and are candidates for removal.

## Adding a probe
Subclass `glasscage.probes.Probe`, set `name`, `owasp_id`, `min_tier`, implement
`run(self, target, recon) -> list[Finding]`, decorate with `@register`. Below-tier
targets automatically yield NOT ASSESSABLE — don't hand-roll that.

## Adding an external adapter
Subclass `glasscage.adapters.base.ExternalToolAdapter`; implement `available()`,
`version()`, and a `parser(path)` that returns normalized `Finding`s. Register in
`adapters/__init__.REGISTRY`. Never fabricate results when the tool is absent.

## Determinism
Graph traversal is sorted; ids are deterministic; `to_dict/from_dict` round-trips.
All randomized components (genetic engine, trials) take a seed. Keep it that way.
