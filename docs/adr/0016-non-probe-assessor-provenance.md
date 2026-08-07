# ADR 0016 — Non-probe assessor provenance

Status: Accepted · Phase 2 / PR #17

Corrects a misreport in `coverage_provenance`, the module
[ADR 0002](0002-engine-surface-wiring.md) names as the source of the published
`runtime_coverage_ratio`. Supersedes nothing.

## Context
`coverage_provenance` exists, in its own words, *"so the report can state an honest runtime
coverage figure"*. It classified each canonical category by consulting `probes.REGISTRY`
alone:

```python
probes = [p for p in REGISTRY if p.owasp_id == cat]
if not probes:
    out[cat] = _NONE
```

**`mcp.analyze_manifest` is not a registered probe.** The engine calls it directly. Neither
is `architecture.assess`. So a category assessed only by one of them had no registry entry
and fell through to `not_tested`.

Measured at `v0.4.0-cli-surface`: `config_review_only` was `[]` and `not_tested` was
`['LLM04', 'MCP03', 'MCP07', 'MULTIMODAL']`, while `mcp.analyze_manifest` on the shipped
sample manifest emitted `{'MCP07': 2, 'MCP03': 1}`. Two categories were reported as untested
while being assessed.

The bucket that should have held them was structurally unreachable. `_probe_provenance`
returns `config_review` when a probe's source mentions a manifest or its class name mentions
MCP, but no registered probe carries an MCP `owasp_id` — across 22 probes, 19 classified
runtime and 3 questionnaire, **none** config_review. The module documented a bucket
(*"e.g. MCP"*) it could never fill.

[ADR 0010](0010-finding-node-identity.md) ruled an analogous misreport *"a fabricated
per-tool verdict and a breach of the evidence ceiling"* and fixed it rather than documenting
it. The same standard applies here.

## Decision

### Provenance derives from two declared sources, not one
The registry, plus an explicit declaration of categories assessed by something that is not a
registered probe. Strength order is unchanged — `runtime > config_review > questionnaire >
not_tested` — so a category a probe drives at runtime is never demoted by a declaration.

### The fix is reporting-layer only
MCP is **not** registered as a `Probe`. The battery stays at 22, no gated finding is
introduced, and `runtime_coverage_ratio` stays `0.54`. That last property is arithmetic, not
adjustment: the ratio is `runtime / universe = 7 / 13`, and moving MCP03 and MCP07 from
`not_tested` to `config_review` changes neither term. Registering an MCP probe would have
changed the battery and added a gated finding to every chat run; the honest coverage figure
did not require paying that price.

### The declaration lives in the reporting layer
`coverage_provenance` states its own inputs rather than importing a constant from `mcp.py`,
so the analysis module stays free of reporting concerns. Drift — the only real cost — is
caught by test in both directions: the declared set is checked against what
`mcp.analyze_manifest` emits, and against the `MCP\d\d` literals in `mcp.py`'s source, so a
category added or removed there fails the suite. This is the trade
[ADR 0014](0014-surface-binding.md)'s PR made when `diff.py` composed its own subject digest
rather than importing `aakg.build`: independence bounded by a parity test.

### `_probe_provenance`'s config_review branch is retained
It remains reachable even though no built-in probe hits it: `plugins.load` appends
third-party probes to the same registry, so a plugin whose class name or source mentions a
manifest is classified without this module knowing about it.

## Alternatives considered
1. **Register `mcp-analyzer` as a Probe.** Rejected: changes the battery from 22 to 23 and
   adds a gated `NOT ASSESSABLE` finding to every chat run — a behavioural change to buy a
   reporting correction.
2. **Export the category set from `mcp.py`.** Rejected: couples an analysis module to the
   reporting layer for a value the reporting layer can state itself.
3. **Infer the categories by importing `mcp` and calling it.** Rejected: provenance would
   depend on which manifest happened to be supplied, so a clean manifest would report MCP as
   untested.
4. **Leave it and document the gap.** Rejected on ADR 0010's precedent.

## Consequences
- **Positive:** two categories are no longer reported as untested while being assessed, and
  a documented bucket becomes usable. `not_tested` now contains only `LLM04` and
  `MULTIMODAL`, both of which genuinely have no assessor.
- **Unchanged:** `runtime_coverage_ratio` (0.54), `runtime_tested`, `universe` (13), battery
  composition (22 probes), gated-finding counts, graph identity, custody, SARIF, replay,
  benchmark and determinism — verified against `v0.4.0-cli-surface` by tree comparison. No
  existing test required modification.
- **Visible change:** the report's `coverage_provenance` field moves `MCP03` and `MCP07`
  from `not_tested` to `config_review_only`. A consumer reading `not_tested` sees two fewer
  entries.
- **Accepted:** `architecture.assess` is also a non-probe assessor and is deliberately not
  declared. Every category it covers is already runtime-tested or already
  questionnaire-covered, so declaring it changes no bucket — simulated and confirmed
  identical. The gap is latent, not active: if a future category were covered *only* by the
  questionnaire, it would misreport as `not_tested`. Recorded here rather than fixed, because
  fixing it today would change nothing and broaden this PR.
- **Follow-up (not this ADR):** `architecture.assess`'s questionnaire provenance, should a
  category ever depend on it alone.
