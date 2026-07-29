# API Stability Report — 1.0.0rc1

Semantic versioning (PEP 440). Within a major version, the following are **stable**:

## Stable public API
- `glasscage.__version__`.
- `Engine(target, ...).run() -> dict` and its documented result keys: `recon, findings,
  summary, graph, coverage, architecture, trust, chains, posture, stats, tier, aakg,
  blast, remediation_priorities`.
- `models.Finding`, `models.Status`, `models.Severity` fields.
- `probes.Probe` base contract (`name/owasp_id/min_tier/run`), `register`,
  `canary_verdict`, `detect_secret`, `CANARY_INJECT`.
- `tal.Tier`, `TargetCapabilities`.
- `aakg.PropertyGraph` public methods; `NodeType`, `EdgeType`, `EdgeState`.
- `adapters.base.ExternalToolAdapter` (`ADAPTER_API_VERSION = "1.0"`).
- Plugin SDK (`plugins.load_plugins`, `PLUGIN_API_VERSION = "1.0"`).
- `errors.*`, `config.validate_target_config`, `logging_setup.get_logger/configure`.
- CLI flags documented in `--help`.

## Experimental (may change within major)
- External adapter live-run behavior (parsers stable; live invocation Experimental).
- `aakg.*` analysis dict shapes beyond the documented keys.
- Benchmark corpus schema.

## Deprecated / fallback (removal planned, will follow deprecation policy)
- Legacy `posture.py`, `coverage.py`, `chain.py`, `trust.py` (`--no-aakg` only).
- `scoring.py` grade/risk_score.

## Compatibility guarantee
No stable-API signature was broken during Stages A–E5 or this RC (verified by
backward-compatibility tests, including `--no-aakg`).
