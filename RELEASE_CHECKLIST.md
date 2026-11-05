# Release Checklist — GLASSCAGE

Status legend: [x] done · [ ] open · [!] release blocker

## Documentation
- [x] README, INSTALL, QUICKSTART, USER_GUIDE, COMMAND_REFERENCE present
- [x] All internal Markdown links resolve (66 files, 0 broken — CI-checkable)
- [x] Feature maturity marked throughout (Implemented / Experimental / Pending / Roadmap)
- [x] Known limitations documented (coverage 0.54, unvalidated efficacy, trusted controls)

## Legal / compliance (Apache-2.0)
- [x] LICENSE present (Apache-2.0)
- [x] NOTICE file present (added)
- [x] CITATION.cff present (added)
- [x] SPDX headers in all 64 source files

## Packaging
- [x] pyproject.toml: name, version (1.0.0rc3), requires-python (>=3.10), license
- [x] readme + classifiers set
- [x] Project URLs point to `Shashankt255/glasscage` (pyproject.toml, README, CITATION.cff, issue config)
- [x] `python -m build` verified — glasscage-1.0.0rc3.tar.gz and wheel built successfully
- [ ] PyPI publish deferred until release signing exists (Roadmap)

## Repository hygiene
- [x] .gitignore present (added) — excludes build + assessment artifacts
- [x] Assessment artifacts removed from version control (gitignored)

## CI / automation
- [x] Test matrix (3.10–3.12), fuzz + property tests, benchmark gate
- [x] Release workflow on tags (added) — build + SBOM + draft release
- [x] Dependabot for Actions (added)
- [ ] Make lint/type gates blocking (currently `|| true`, advisory during RC)

## Security
- [x] SECURITY.md present, scope + data-handling + plugin trust model documented
- [x] Security contact now routes to GitHub Security Advisory (always-available; no email needed)
- [ ] Release signing / provenance attestation (Roadmap)
- [x] Redaction on by default; consent-gated raw storage; custody hash pre-redaction

## Correctness / honesty (from prior review boards)
- [x] Coverage accounting: `runtime_coverage_ratio` (0.54) + provenance breakdown added
- [x] P0 coverage credibility verified end-to-end (CLI demo → JSON/MD/HTML all correct)
- [ ] Real-target validation campaign (blocks GA, not this RC)
- [ ] Stop trusting self-declared --architecture controls without verification

## Pre-tag verification
- [x] `pytest -q` → 997 passed, 89 subtests passed in ~17s
- [ ] Fresh-clone smoke test on Windows / Linux / macOS
- [ ] CHANGELOG updated for the tag
