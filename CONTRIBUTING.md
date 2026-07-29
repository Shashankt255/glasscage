# Contributing to GLASSCAGE

Thanks for helping. GLASSCAGE is stdlib-only in its core; do not add runtime
dependencies to the core (optional features go behind extras).

## Ground rules
- The architecture is frozen around the AI Attack Knowledge Graph. No new graph node/
  edge types, attack engines, or reporting redesigns without a maintainer RFC.
- Never fabricate results. Unavailable external tools must report "Not Tested"/"Pending
  External Validation" — never synthetic data.
- Preserve determinism: sorted traversal, deterministic ids, seeded randomness.

## Workflow
1. Fork, branch from `main`.
2. `python -m unittest discover -s tests -q` must pass (add tests for changes).
3. `python -m unittest tests.test_fuzz tests.test_property` for core changes.
4. Keep public APIs backward compatible (see `VERSIONING.md`).
5. Open a PR with a clear description and, for behavior changes, a CHANGELOG entry.

## Adding probes / adapters / plugins
See `docs/DEVELOPER.md` and `docs/PLUGIN_SDK.md`. Probes declare `min_tier`; adapters
never fabricate; plugins declare `GLASSCAGE_PLUGIN_API`.

## Code style
Prefer clarity over cleverness; document every public class; narrow exception handling.
