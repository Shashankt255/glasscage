# GLASSCAGE

Security assessment platform for LLM and agentic applications.

Probes a target, records evidence, and builds an **AI Attack Knowledge Graph (AAKG)** —
a typed property graph from which it derives attack paths, trust boundaries, blast radius,
coverage, and remediation. Every claim in the report is cited to graph evidence and clamped
to the weakest link in its chain. If something wasn't tested, the report says so.

[![CI](https://github.com/Shashankt255/glasscage/actions/workflows/ci.yml/badge.svg)](https://github.com/Shashankt255/glasscage/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-997%20passed-brightgreen)](#)

> **Authorized use only.** Run this only against systems you own or have explicit written
> permission to test. `--authorized` is required for live targets.

---

## Why

Most AI security tools are probe batteries — they fire payloads and hand you a pass/fail
list. That's useful, but it's not an assessment.

GLASSCAGE does the rest of the pentest loop: it maps the attack surface into a graph,
traces what an attacker can actually reach from each finding, models trust boundaries and
privilege transitions, scores the result with honest evidence accounting, and writes a
remediation-focused report with reproduction steps. It tells you what to fix first and
why, not just what failed.

The whole thing runs on Python's standard library. No API keys, no cloud calls, no
dependencies to audit.

## Try it (30 seconds, no target needed)

```bash
pip install .
glasscage --demo --out report
```

That runs a full assessment against a built-in intentionally-weak bot and writes
`report.md`, `report.html`, and `report.json`. Open the HTML — it's a self-contained
app with severity dashboard, live search, and tabbed findings (Evidence / Remediation /
Verify / Reproduce / References).

For the full reference agent with agentic surfaces:

```bash
glasscage --harness --views all --out report
```

Against a live target:

```bash
glasscage --config target.json --authorized --out report
```

See [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md) for configuration details and
[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) for the full walkthrough.

## What it covers

| Category | Probes | What they test |
|---|---|---|
| LLM01 | direct-injection, indirect-injection-rag, multi-turn-erosion, encoded, payload-splitting, jailbreak-persona, multilingual | Prompt injection across delivery methods |
| LLM02 | sensitive-info-disclosure | Secret-shaped content leaking in responses |
| LLM03 | supply-chain-review | Model and plugin provenance, AI-BOM gaps |
| LLM05 | insecure-output-handling | Unescaped markup reaching downstream consumers |
| LLM06 | excessive-agency-review | Tool surface without least-privilege or human-in-the-loop |
| LLM07 | system-prompt-leak | Verbatim system prompt disclosure |
| LLM08 | vector-rag-review | RAG isolation and retrieval poisoning surface |
| LLM09 | misinformation-false-premise | Acceptance of planted false premises |
| LLM10 | unbounded-consumption-review | Missing rate, token, and quota limits |
| MCP03 | tool-poisoning, rug-pull | Hidden instructions in tool metadata, definition drift |
| MCP07 | SSRF/exfil | URL and path parameters reaching internal endpoints |

**Static analysis (no target needed):**

| Feature | Flag | What it checks |
|---|---|---|
| System prompt review | `--system-prompt FILE` | Embedded secrets, injection delimiters, over-permissive grants, missing refusal instructions, role confusion, sensitive data, prompt length, output constraints |
| Model card review | `--model-card FILE` | Untrusted model source, unverified fine-tuning, safety alignment, training data review, PII in training, version pinning, public deployment risk |
| Architecture review | `--architecture FILE` | Defense-in-depth controls across 15 categories |

Runtime coverage: **7 of 13 OWASP LLM categories** tested with actual payloads.
The remaining 6 are assessed via config review or architecture questionnaire — the
report separates the two and never labels a config-review finding as "measured."

## What makes it different

| | GLASSCAGE | garak | PyRIT |
|---|---|---|---|
| **Approach** | Graph-native assessment (recon → probe → graph → score → remediate → report) | Probe battery | Red-team orchestration |
| **Output** | Attack graph + narrative report with reproduction steps | Pass/fail probe results | Attack logs |
| **Coverage accounting** | Separates runtime-tested from config-review, reports both | Probe pass rate | Not tracked |
| **Remediation** | Ranked by measured impact (paths broken, blast reduced) | Not included | Not included |
| **Trust boundaries** | Mapped in graph with privilege transitions | Not modeled | Not modeled |
| **Blast radius** | "If this succeeds, what's reachable?" from graph relationships | Not modeled | Not modeled |
| **Dependencies** | Zero (stdlib only) | Multiple | Multiple |
| **Target types** | Chat, REST API, MCP | Chat, API | Chat, API |

garak has more probes and wider model coverage. PyRIT has stronger multi-turn
orchestration. Use them alongside GLASSCAGE — it can ingest their output via
`--adapter-file` and map their findings into the AAKG.

## Architecture

```
cli.py              CLI entry point, demo/harness modes
glasscage/
  engine.py         Orchestrates the full assessment pipeline
  aakg/             AI Attack Knowledge Graph (24 node types, 12 edge types)
    build.py        Graph construction from probe evidence
    coverage.py     Graph-native OWASP/ATLAS/CWE coverage
    posture.py      Risk scoring from graph evidence
    narrative.py    Evidence-gated attack narratives (8 strategies)
    story.py        Assessment story (13-section pentest report)
    remediation.py  Mitigations ranked by graph impact
    report.py       Graph-native Markdown renderer
    views.py        Audience views (exec/security/dev/IR/compliance)
  probes.py         Pluggable probe framework (@register)
  target.py         HTTP chat adapter (stdlib only)
  targets/          REST, MCP, surface binding
  audit.py          Hash-chained append-only custody log
  coverage.py       Coverage provenance and evidence accounting
  system_prompt_review.py  Static analysis of system prompts (8 checks)
  model_card_review.py     Model provenance and data poisoning review (7 checks)
  report.py         HTML/JSON/SARIF report generation
  adapters/         garak/PyRIT/Promptfoo/DeepTeam output normalization
```

## Writing custom probes

```python
from glasscage.probes import Probe, register
from glasscage.models import Status, Severity

@register
class MyProbe(Probe):
    name = "my-custom-check"
    owasp_id = "LLM01"
    category = "Custom"

    def run(self, target, recon):
        resp = target.send("test payload here")
        if self.canary_verdict(resp):
            return [self._finding(
                title="Custom finding",
                detail="What was observed",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=resp,
            )]
        return []
```

Drop the file in a directory, run with `--plugins ./that_dir --allow-plugins`.

See [`docs/PLUGIN_SDK.md`](docs/PLUGIN_SDK.md) for the full API.

## Limitations

Read these before relying on any output.

- **Efficacy is not independently validated.** The built-in harness uses a deterministic
  mock. Treat findings as hypotheses until confirmed against your actual target.
- **Runtime coverage is 7/13 OWASP categories.** The report separates this from
  config-review coverage. Quote `runtime_coverage_ratio`, not `coverage_ratio`.
- **MCP assessment is configuration review only.** No MCP server is contacted.
- **External-tool adapters are experimentally validated.** garak format verified;
  others are marked Experimental.
- **The risk index is an uncalibrated heuristic.** It gives directional signal,
  not a calibrated probability.

Full discussion: [`docs/METHODOLOGY_AND_LIMITATIONS.md`](docs/METHODOLOGY_AND_LIMITATIONS.md)
and [`docs/VALIDATION.md`](docs/VALIDATION.md).

## Documentation

| Doc | What it covers |
|---|---|
| [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md) | Setup and first assessment |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Full usage reference |
| [`docs/DEVELOPER.md`](docs/DEVELOPER.md) | Contributing and internals |
| [`docs/PLUGIN_SDK.md`](docs/PLUGIN_SDK.md) | Custom probe development |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Security model and evidence handling |
| [`docs/adr/`](docs/adr/) | Architecture decision records (ADR 0001–0032) |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). By submitting a PR you agree to the
[Contributor License Agreement](CLA.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).

Built by [Shashank Shekhar](https://github.com/Shashankt255).
