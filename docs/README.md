# GLASSCAGE Documentation

**Version:** 1.0.0rc3 (Release Candidate) · **License:** Apache-2.0 · **Runtime deps:** 0 (stdlib only)

GLASSCAGE is a security assessment platform for LLM and agentic applications. It probes
an authorized target, records evidence, and builds an **AI Attack Knowledge Graph
(AAKG)** from which it derives attack paths, trust-boundary analysis, blast radius,
coverage, remediation, evidence-gated narratives, and a full assessment story.

> **Read this first.** GLASSCAGE is honest about what it can prove. Its findings are
> **hypotheses to confirm**, not conclusions, and several headline numbers carry
> important caveats. See [VALIDATION.md](VALIDATION.md) and the *Known Limitations*
> section of the [USER_GUIDE.md](USER_GUIDE.md) before quoting any result.

## Documentation map

| Document | For | Purpose |
|---|---|---|
| [INSTALL.md](INSTALL.md) | everyone | install on Windows / Linux / macOS, extras, verification |
| [QUICKSTART.md](QUICKSTART.md) | new users | first run in five minutes |
| [USER_GUIDE.md](USER_GUIDE.md) | everyone | core concepts, maturity matrix, **known limitations** |
| [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md) | operators | every CLI option, with examples |
| [REPORT_GUIDE.md](REPORT_GUIDE.md) | report readers | how to read each report and what you may not conclude |
| [ASSESSMENT_WORKFLOW.md](ASSESSMENT_WORKFLOW.md) | operators | end-to-end engagement workflow |
| [ADMIN_GUIDE.md](ADMIN_GUIDE.md) | platform/security teams | deployment, artifacts, encryption, upgrades |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | contributors | architecture, extension points, testing, CI |
| [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md) | plugin authors | writing and loading plugins safely |
| [ARCHITECTURE.md](ARCHITECTURE.md) | contributors | AAKG, module relationships, graph lifecycle |
| [NARRATIVES.md](NARRATIVES.md) | report readers | attack narratives & assessment story |
| [THREAT_MODEL.md](THREAT_MODEL.md) | security teams | threat model of the tool itself |
| [VALIDATION.md](VALIDATION.md) | evaluators | how to validate GLASSCAGE against real targets & other tools |
| [TUTORIALS.md](TUTORIALS.md) | learners | eight step-by-step tutorials |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | everyone | fixes for common problems |
| [FAQ.md](FAQ.md) | everyone | frequently asked questions |
| [ROADMAP.md](ROADMAP.md) | everyone | what is and is not planned |
| [CHANGELOG.md](CHANGELOG.md) | everyone | release history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | contributors | how to contribute |
| [PUBLISHING_TO_GITHUB.md](PUBLISHING_TO_GITHUB.md) | maintainers | download these docs & commit them |

## Feature maturity legend

Every feature in this documentation is marked with one of:

- **Implemented** — works today, tested.
- **Experimental** — works but indicative only; do not rely on it for load-bearing claims.
- **Pending External Validation** — the machinery exists but has not been run against
  real external tools/targets; no result is claimed.
- **Roadmap** — not implemented. Explicitly not supported today.

## The three things to know before you rely on GLASSCAGE

1. **Efficacy is not independently validated.** All agentic "demonstrated" results in
   this release come from a built-in deterministic reference harness. Treat findings as
   hypotheses. See [VALIDATION.md](VALIDATION.md).
2. **`coverage_ratio` overstates runtime testing.** It counts questionnaire and
   configuration-review findings as "tested". True runtime coverage is **7 of 13**
   OWASP LLM categories (0.54); the tool may report 0.85. See
   [REPORT_GUIDE.md](REPORT_GUIDE.md#coverage).
3. **The Indicative Risk Index is an uncalibrated heuristic.** Use it to prioritize
   within one target, never as an absolute or cross-target risk measure.
