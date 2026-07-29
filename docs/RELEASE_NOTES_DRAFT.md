# GLASSCAGE 1.0.0rc3 — Release Notes (DRAFT)

> Release candidate. GLASSCAGE builds an AI Attack Knowledge Graph from probe evidence
> and reasons about consequence — what a finding reaches, which trust boundary it
> crosses — while refusing to claim more than its evidence supports.

## Highlights
- **Attack Narratives + Assessment Story** reporting layer: evidence-gated, graph-cited,
  clamped to the weakest hop. Strategies with no supporting path print "Not demonstrated."
- **Five audience views** (executive, security, developer, incident_response, compliance).
- **Evidence Confidence Classification** enforced in code (a claim never exceeds its evidence).
- **Secret redaction on by default**; chain-of-custody hash computed pre-redaction;
  optional encrypted evidence at rest.
- **Zero runtime dependencies** (standard library only). **189 tests** (unit, fuzz,
  property, anti-hallucination) pass.

## Known limitations (read before relying on output)
- **Efficacy not independently validated.** Agentic "demonstrated" results come from the
  built-in deterministic reference harness. Treat findings as hypotheses.
- **Coverage accounting overstates runtime testing.** True runtime coverage is 7/13
  OWASP LLM categories (0.54); `coverage_ratio` may report 0.85. Quote 0.54.
- **MCP support is configuration review only** — GLASSCAGE never contacts an MCP server.
- **External-tool adapters are Pending External Validation** — no genuine tool output
  ingested at scale.
- **Self-declared architecture controls are trusted, not verified.**
- **Indicative Risk Index is an uncalibrated heuristic.**

## Before you tag this release (maintainer action required)
- Replace the `OWNER/REPO` sentinel in `pyproject.toml` (and CITATION.cff, issue config) with the real GitHub path.
- Replace the placeholder security contact in `SECURITY.md`.
- `git rm -r --cached` the committed assessment artifacts now covered by `.gitignore`.

## Install
See `docs/INSTALL.md`. Python ≥ 3.10; install from source for this RC.

## Verify
`python -m unittest discover -s tests -q` → `Ran 189 tests ... OK`
