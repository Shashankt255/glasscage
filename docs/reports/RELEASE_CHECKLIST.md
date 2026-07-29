# Release Checklist — GLASSCAGE 1.0.0rc1

## Done
- [x] Architecture frozen (AAKG single source of truth).
- [x] Dead code removed; unused imports cleaned.
- [x] Typed errors, structured logging, config validation.
- [x] Plugin SDK versioned + validated + documented + example.
- [x] Graph analysis caching (bottleneck addressed).
- [x] Profiling + performance benchmarks + reports.
- [x] Developer docs, Plugin SDK doc, graph model, auto-generated API docs.
- [x] Fuzz tests, property-based tests, hardening tests, expanded regression.
- [x] Packaging (pyproject, extras, entry points, py.typed, `python -m glasscage`).
- [x] Developer CI (matrix 3.10–3.12), Makefile.
- [x] Semantic versioning + API stability report.
- [x] 125 tests passing, zero regressions.
- [x] Backward compatibility verified (`--no-aakg`).

## Release gates BEFORE GA (not satisfiable in this environment)
- [ ] **Item 20 — live validation against real garak/Promptfoo/PyRIT output.** Parsers
      are tested against representative fixtures; live runs require the tools installed
      and are **Not Tested** here. Run `--adapter-file tool=<real output>` and the
      cross-framework `--validate` against a live target, and record results.
- [ ] Make `ruff`/`mypy` gates blocking (currently advisory).
- [ ] Grow benchmark corpus and independent review.
- [ ] Security review of evidence-at-rest redaction (secrets in stored evidence — open
      item from the Phase-1 review, tracked separately).
- [ ] Publish artifacts + SBOM.


## Priority-0 GA blockers (implemented in 1.0.0rc2)
- [x] P0-1 Secure evidence: redaction by default, `--store-raw` consent, optional
      at-rest encryption (`crypto` extra), chain of custody preserved. Tests prove no
      secret appears in default artifacts.
- [x] P0-2 Governance: LICENSE (Apache-2.0), SECURITY.md, CONTRIBUTING.md,
      CODE_OF_CONDUCT.md, VERSIONING.md, GLASSCAGE-specific THREAT_MODEL, SBOM generator.
- [x] P0-3 Plugin security: `--allow-plugins` consent gate + trust warning. Tested.
- [x] P0-4 Posture: pseudo confidence interval removed; relabeled Indicative Risk Index
      [Estimated]; backward compatible (`risk_interval` = None).
- [x] P0-5 Adapter validation FRAMEWORK: `--validate-adapters`/`--genuine-output`.
      In this environment: 0 genuine, 5 **Pending External Validation** (honest).
- [x] Evidence Confidence Classification applied to every report section (8 classes).
- [x] 145 tests passing, backward compatible.

## STILL OPEN — cannot be closed in this environment (must close before GA)
- [ ] **C1 real-target efficacy validation** — requires live LLM/agent targets (no network here).
- [ ] **C2 genuine external-tool runs** — requires garak/PyRIT/Promptfoo installed; parsers
      are fixture-conformant only. Currently reported as Pending External Validation.
- [ ] Release signing / provenance attestation.
- [ ] Make ruff/mypy gates blocking; grow corpus; independent review.

## Recommendation
Ship as **1.0.0rc2** for evaluation. Evidence redaction, governance, plugin consent,
and honest scoring are now in place. **Do not tag GA until C1 (real-target validation)
and C2 (genuine external-tool runs) are closed** — both require environments unavailable
here and are explicitly Pending External Validation, not fabricated.
