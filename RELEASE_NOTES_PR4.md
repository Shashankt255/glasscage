# Release Notes — PR #4: runtime surface attribution on findings

Phase 1 · merged on top of PR #1 (engine surface wiring), PR #2 (surface discovery) and
PR #3 (`--discover` inventory).

## Summary

Findings produced by target interaction now record **which surface they were observed
on**. `Finding` gains an additive `surface_id`, populated by the engine when a run is
surface-driven.

Before this release, a surface-driven run was indistinguishable from a direct run in
every artifact — that equivalence was PR #1's central correctness proof, but it left the
driven path unauditable. `surface_id` closes that gap.

**Configuration-review evidence is never attributed.** MCP-manifest findings and
architecture-questionnaire findings keep an empty `surface_id`, because they are not
observations on a surface. Tagging them would fabricate provenance.

## Architecture impact

Minimal and additive. The substantive decision recorded in
[ADR 0004](docs/adr/0004-attribution-before-binding.md) is one of **sequencing**, not
structure.

- `Finding` was **extended**, not paralleled: `surface_id` sits beside the existing
  `assessed_tier`, `source_framework` and `provenance` fields.
- The engine tags findings in a single pass placed **before** MCP and architecture
  findings are appended. That placement is what enforces the honesty rule — non-runtime
  evidence is untagged by construction, not by filtering.
- **No AAKG change.** No new node or edge type. Verified that `aakg/build.py`,
  `sarif.py` and `repro.py` read named `Finding` fields and never enumerate them via
  `asdict`, `vars()` or `__dataclass_fields__`, so graph serialization, SARIF, replay
  bundles and reproduction steps are unaffected. Asserted by test.
- **PR #1's one-authoritative-target guard is untouched**, as are `SurfaceTarget`,
  `chat_surface_of`, `Surface` and `ApplicationTarget`. The entire `targets/` package has
  a zero diff.
- No scoring, coverage, probe, detector or CLI change.

### Sequencing decision recorded in ADR 0004

Two Phase 1 candidates were compared from first principles. **Binding** — promoting a
discovered `SurfaceCandidate` into a concrete `Surface` — was rejected as not yet
buildable: `Surface` requires a bound `Driver`, `ChatDriver` is the only driver, and
discovery emits no CHAT candidates. Binding first would also have written into the same
list `chat_surface_of` indexes with `[0]`, which can silently change what the engine
drives, and would have pressured the attribution guard to relax before anything existed
to replace it.

Honest framing, stated in the ADR: **neither candidate removed a blocker.** Both are
preparation. Attribution is the strict prerequisite, and unlike binding it delivers
something observable on merge.

## User-visible changes

- **`<out>.json` gains one key per finding:** `surface_id`. Empty string unless the run
  was surface-driven.
- No other output changes. Markdown, HTML, SARIF, replay bundles, HAR export and
  reproduction steps are byte-identical to the previous release for the same run.
- No CLI change. `--discover` and every existing mode behave exactly as before. The
  capability is reachable through the Python API (`Engine(target, surface=...)`) only.

## Developer changes

- `glasscage.models.Finding.surface_id: str = ""` — appended last, defaulted.
- Populated by `Engine.run()` for probe-loop findings, tier-gated `NOT_ASSESSABLE`
  findings, and `--adaptive` / `--genetic` attacker findings.
- Probes and plugins do **not** set the field; the engine does. Third-party probes are
  attributed without any change to them.
- Tests: `tests/test_surface_attribution.py`, 12 tests. Suite total **282 passing**.
- Detector benchmark unchanged: P 0.9697 · R 0.9143 · F1 0.941 · reproducibility 1.0.

## Backward compatibility

**Fully preserved.**

- Additive dataclass field with a default; positional `Finding(...)` construction of
  every pre-existing field is unaffected.
- `Engine(target).run()` without `surface=` leaves every `surface_id` empty and changes
  nothing else.
- No existing function signature or return shape changed.
- No existing test file was modified; the full 270-test baseline passes unchanged.
- No deletions. No new runtime dependency — standard library only.

## Migration notes

**None required.**

- Existing scripts, configs and CI invocations are unaffected.
- If you validate `<out>.json` against a strict schema, add the `surface_id` string field
  to your finding schema. Every other key is unchanged in name, type and order.
- If you consume `surface_id`, note that an empty string means "not surface-driven" or
  "not a runtime observation" — it does not mean "unknown surface".

## Known limitations

- **No analysis consumer yet.** `surface_id` appears in the JSON report; no coverage,
  posture, narrative or graph analysis reads it. That is the accepted preparation cost
  recorded in ADR 0004.
- **Custody, HAR export and reproduction steps still read the supplied target**, not the
  driven surface. Moving reproduction attribution onto the surface is the next change.
- **One surface per run.** The one-authoritative-target guard still requires the driven
  surface to be bound to the supplied target, so `surface_id` currently takes one value
  per run.
- **Tier-gated findings carry the id** although nothing was sent to the surface. A
  reviewed judgment call — they describe whether that surface is assessable — documented
  in ADR 0004.
- Pre-existing, unrelated, recorded not fixed: `Finding` declares six fields twice
  (`source_framework`, `source_rule_id`, `cwe_id`, `capec_id`, `nist_id`, `raw_output`);
  `schema.from_openapi` raises `AttributeError` on a path whose value is not an object.
- The pre-existing Windows cp1252 failure in `tests/test_hardening.py` is unchanged; local
  full-suite runs still need `PYTHONIOENCODING=utf-8`.

## Future work

In dependency order, per ADR 0004:

1. **Reproduction attribution** — reproduction steps identify the surface a finding was
   observed on, giving `surface_id` its first consumer beyond raw JSON.
2. **Generalise the one-authoritative-target guard** to per-surface attribution, so a
   surface bound to a target other than the supplied one can be driven safely.
3. **Binding** — promoting a discovered `SurfaceCandidate` to a driven `Surface`.
4. **Non-chat drivers** (REST, GraphQL) — additionally blocked by the action model:
   `PromptAction` is the only `Action` kind and every probe is prompt-shaped.

## Related ADR

- [ADR 0004 — Attribution before binding](docs/adr/0004-attribution-before-binding.md):
  the sequencing decision, why binding cannot be built today, the
  `surfaces_of(CHAT)[0]` hazard, the reverse-order risks, and the scope of attribution in
  this release.
- [ADR 0002 — Engine surface wiring](docs/adr/0002-engine-surface-wiring.md): the
  attribution guard this release prepares to generalise.
- [ADR 0003 — Read-only surface discovery](docs/adr/0003-surface-discovery.md): the
  follow-up ordering this release executes.

## Related roadmap milestone

**Phase 1 — per-surface attribution**, the first of the three remaining items named in
ADR 0003 ("per-surface attribution, then binding and non-chat drivers").

Not a GA blocker. The Priority-0 items in [`docs/ROADMAP.md`](docs/ROADMAP.md) —
real-target validation, genuine external-tool ingestion, control verification, release
signing — are unaffected and remain open.
