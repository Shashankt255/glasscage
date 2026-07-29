# Versioning Policy

GLASSCAGE follows Semantic Versioning 2.0.0 (PEP 440 for Python pre-releases).

## History note
Internal development used stage-build tags (0.5 -> 1.4) during Stages A-E5. The first
PUBLIC version is **1.0.0rc1**. Public semantics begin here; earlier tags were internal.

## What "stable" means (within a major version)
Backward-compatible across minors: `Engine(...).run()` result keys; `models.Finding/
Status/Severity` fields; `probes.Probe` contract, `register`, `canary_verdict`,
`detect_secret`, `CANARY_INJECT`; `tal.Tier`, `TargetCapabilities`; `aakg.PropertyGraph`
public methods, `NodeType/EdgeType/EdgeState`; `adapters.base.ExternalToolAdapter`
(`ADAPTER_API_VERSION`); plugin SDK (`PLUGIN_API_VERSION`); `errors.*`,
`config.validate_target_config`, `logging_setup`; documented CLI flags.

## Experimental (may change within a major)
External-adapter live-run behavior; `aakg.*` dict shapes beyond documented keys;
benchmark corpus schema; the Indicative Risk Index heuristic.

## Deprecation
Deprecated APIs emit a warning for one minor release before removal. Removal is a major
bump. The legacy `--no-aakg` engines (`posture/coverage/chain/trust`) are deprecated and
scheduled for removal in the next major.

## Pre-1.0 / RC
Release candidates may change any Experimental surface without a major bump.
