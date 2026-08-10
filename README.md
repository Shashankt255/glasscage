# GLASSCAGE

> Builds an evidence graph of what an attacker can reach in your LLM or agentic
> application — and refuses to claim more than it proved.

**Runtime coverage: 7 of 13 OWASP LLM categories** (see limitations). **Not a garak
replacement** — garak has more probes; use both. Zero runtime dependencies. 192 tests.

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

> WARNING: **Authorized use only.** Run only against systems you own or have written
> permission to test.

## Install
```bash
pip install .            # from source (Python >= 3.10)
```

## Try it in 30 seconds (no target needed)
```bash
python -m glasscage --demo --out report                    # built-in mock (L0)
python -m glasscage --harness --views all --out report     # built-in L2 reference agent
```
Open `report.md`. Full walkthrough: [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md).

## What it does
Probes an authorized target, records evidence, and builds an **AI Attack Knowledge
Graph** from which it derives attack paths, trust boundaries, blast radius, coverage,
remediation, and **evidence-gated attack narratives** — every claim cited to graph
nodes/edges and clamped to its weakest hop.

## Honest limitations (read before relying on output)
- **Efficacy is not independently validated** — agentic results come from a built-in
  deterministic harness. Treat findings as hypotheses.
- **Coverage accounting** — quote the runtime figure (7/13 = 0.54), reported as
  `runtime_coverage_ratio`; the legacy `coverage_ratio` counts questionnaire and
  config-review findings as tested.
- **MCP support is configuration review only** — no MCP server is contacted.
- **External-tool adapters are Pending External Validation.**
- **The Indicative Risk Index is an uncalibrated heuristic.**

Full detail: [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) §6 and [`docs/VALIDATION.md`](docs/VALIDATION.md).

## Documentation
Start at [`docs/README.md`](docs/README.md).

---

# Development history

The notes below track the project's staged construction and are retained for context.

## GLASSCAGE  v1.0.0rc3

**AI attack-surface recon + remediation for chatbots and agents.**
A defensive red-teaming framework that fingerprints an AI bot, runs
detection-oriented probes mapped to the **OWASP Top 10 for LLM Applications**,
analyzes **MCP/agentic** exposure, models **blast radius**, scores the result,
and produces a remediation-focused report. Zero third-party dependencies.

> ⚠️ **Authorized use only.** Run this only against systems you own or have
> explicit written permission to test.

## v1.0.0rc3 — Attack Narratives & Assessment Story (reporting layer)
See `docs/NARRATIVES.md` and `docs/examples/BEFORE_AFTER.md`. A **renderer-only** layer over the AAKG: no new analysis, node types, attack techniques, or scoring.
- **Attack Narratives**: 8 strategies (Highest Impact, Lowest Effort, Most Likely, Data Exfiltration, Tool Abuse, Privilege Escalation, Memory Poisoning, MCP Compromise) — all filters over *existing* graph paths. Strategies matching no path emit "Not demonstrated." and never synthesize one. Identical paths are deduped.
- **Assessment Story**: 13 sections (Overview → Lessons Learned) reading like a pentest report; each section independently evidence-classified.
- **Audience views**: `--views executive|security|developer|incident_response|compliance|all` — five lenses over the *same* models.
- **Evidence discipline**: every transition cites node ids, edge id, evidence ids, confidence and state; a narrative is clamped to its weakest hop and can never exceed Demonstrated.
- Integrated into markdown, HTML, JSON and the executive summary. **SARIF and replay bundles unchanged.**
Backward compatible (`write_json`/`to_html` narrative args optional; `--no-aakg` unaffected); 189 tests pass.

## v1.0.0rc2 — Priority-0 GA-blocker hardening (security & credibility)
See `RELEASE_NOTES_1.0.0rc2.md`, `MIGRATION_NOTES.md`, `docs/THREAT_MODEL.md`.
- **Secure evidence**: secret redaction ON BY DEFAULT in every artifact (stable `[REDACTED:<hex>]` tokens); raw only via `--store-raw`; optional at-rest encryption `--encrypt-evidence` (needs `glasscage[crypto]`; honest refusal, no homemade cipher). Chain of custody preserved (hash computed pre-redaction).
- **Evidence Confidence Classification**: 8 levels (Verified -> Pending External Validation) tagged on every report section, with a clamp so no claim exceeds its evidence. See `docs/EVIDENCE_CONFIDENCE.md`.
- **Indicative Risk Index** (was "Posture Score"): pseudo confidence interval REMOVED; relabeled as an uncalibrated heuristic [Estimated]. `risk_interval` kept as `None` for compat.
- **Plugin security**: `--plugins` now requires `--allow-plugins` + loud trust warning (no sandbox).
- **Adapter validation**: `--validate-adapters [--genuine-output tool=path]`; fixtures = Experimental, genuine output = Measured, otherwise **Pending External Validation**. Never fabricated.
- **Governance**: LICENSE (Apache-2.0), SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, VERSIONING.md, GLASSCAGE-specific threat model, SBOM generator.
Backward compatible; 145 tests pass. Real-target efficacy (C1) and genuine external-tool runs (C2) remain documented GA gates.

## v1.0.0rc1 — Release Candidate hardening
Engineering quality only (no new capabilities). Typed errors, structured logging, config
validation, formal Plugin SDK, graph analysis caching (~56x on repeat), fuzz + property +
hardening tests, developer + API docs, packaging (extras, `python -m glasscage`, py.typed),
developer CI, and eight RC reports (tech-debt, profiling, architecture/API stability,
performance, packaging, release checklist, changelog). Dead code removed. 125 tests pass.
Live validation against real garak/PyRIT/Promptfoo is a documented GA gate (tools not
installed here). See `docs/reports/`.

## v1.4 — single source of truth (Stage E5)
See `ARCHITECTURE_STAGE_E5.md`. Posture, coverage, reporting, and remediation now read the AAKG directly (no duplicate logic).
- **Graph posture**: score computed from graph evidence with a per-point contribution breakdown (each factor cites the nodes/edges behind it).
- **Graph coverage**: OWASP/ATLAS/CWE/CAPEC/NIST coverage from `mapped_to` edges, split Demonstrated/Hypothesized/Not-Assessable/Untested.
- **Graph remediation**: mitigations ranked by measured impact (attack paths broken, blast reduced, trust violations resolved), each citing graph nodes/edges.
- **Graph report**: markdown report queries the graph for every section.
- `--no-aakg` keeps the legacy path (still tested). Backward compatible; 104 tests pass. E6-E8 not started.

## v1.3 — AI Attack Knowledge Graph (Stage E, E1-E4)
See `ARCHITECTURE_STAGE_E.md`. The AAKG becomes the core substrate.
- **E1 graph engine** (`aakg/`): stdlib-only typed property graph — 24 node types, 12 edge types, edge epistemic state (demonstrated/hypothesized/not_assessable) with monotonic upgrade; deterministic traversal + exact serialization round-trip.
- **E2 attack paths**: dynamic traversal (User -> high-value assets) replaces template chains; a path's state is its weakest edge; every path carries evidence.
- **E3 trust boundary**: privilege transitions, boundary crossings, excessive privilege, least-privilege violations, reachable assets — all computed on the graph.
- **E4 blast radius**: "if this succeeds, what's reachable?" from observed graph relationships, not heuristics.
- Engine now derives trust/chains/blast from the AAKG (`--no-aakg` for legacy). `--out X` also writes `X_aakg.json`.
Backward compatible; 91 tests pass. E5-E8 (migrating posture/coverage/reporting/remediation onto the graph) not started.

## v1.2 — external integration & validation (Stage D)
See `ARCHITECTURE_STAGE_D.md` for full status labels. Focus: credibility, not features.
- **External adapters** normalize garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI native output into canonical Findings with full OWASP/ATLAS/CWE/CAPEC/NIST taxonomy. Feed real output via `--adapter-file tool=path`; garak format verified, others Experimental. Unavailable tools = **Not Tested** (never synthetic).
- **Corpus** expanded 18 -> 109 labeled cases incl. hard cases detectors are meant to miss.
- **Measurement**: precision/recall/F1 with **Wilson 95% CIs**, FP/FN lists, coverage, timing (`--benchmark`). Measured: P0.97 R0.91 F1.94 on the shipped corpus.
- **Cross-framework validation** (`--validate`): detection overlap, Jaccard agreement, reproducibility, honest Not-Tested — plus an auto-generated paper-quality `VALIDATION_REPORT.md`.
Backward compatible; 74 tests pass. AI Attack Knowledge Graph still deferred (Stage E).

## v1.1 — abstraction, statistics, validation (Stages A-C)
See `ARCHITECTURE_STAGE_ABC.md` for full status labels.
- **Target Abstraction Layer (L0-L3)**: every probe declares a min tier; targets below it get **NOT ASSESSABLE**, never a false pass/fail. Fixes the validity crisis.
- **Reference agent harness** (`--harness`): deterministic L2 target (planner/memory/retriever/MCP/tools) that lets agentic probes *confirm* exploitation via a real trace.
- **Statistical engine** (`--trials N --seed S`): Wilson CIs, variance, reproducibility, deterministic replay.
- **Benchmark harness** (`--benchmark corpus.json`): real precision/recall/F1 of detectors on a labeled corpus.
- **Adapter architecture** (`--orchestrate ...`): orchestrate/benchmark garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI (native+fake Implemented; external Roadmap, honest availability). GLASSCAGE = orchestration + analysis platform, not another scanner.
Backward compatible; 62 tests pass. AI Attack Knowledge Graph intentionally deferred to Stage D.

## v1.0 — platform upgrade
Major version. New capabilities (see `ARCHITECTURE_V1.md` for full status + rationale):
- **Exploit chains** (`chain.py`): multi-stage attack paths (Injection→Tool→Exfil, etc.) with likelihood + Mermaid.
- **Genetic attack engine** (`--genetic`): evolutionary payload search (selection/crossover/mutation, seeded).
- **Agent-security probes**: planner manipulation, memory poisoning, goal hijack, tool routing, loop/context pressure.
- **Trust-boundary analyzer** (`trust.py`): components/zones, privilege transitions, boundary-violation detection.
- **Dynamic posture score 0–100** (`posture.py`): 8 weighted factors, auditable, replacing the letter grade as headline.
- **Enterprise export**: SARIF 2.1.0 (`--sarif`), reproducible replay bundle + runner (`--replay`), CI templates (GitHub/GitLab/Azure).
Backward compatible: `Engine(target).run()` still works; new stages are additive.

## v0.5 — expert-review hardening
Applied a senior-review pass. Highlights:
- **Steerability vs. impact**: canary hits are a capped capability signal; only real
  disclosures / schema-confirmed tool firing drive high posture.
- **Transparent scoring**: documented CVSS-style vector per finding + confidence
  interval + indicative (not absolute) grade. See `cvss.py`, `scoring.py`.
- **Coverage statement**: every report lists tested vs NOT-tested categories; no
  false assurance. See `coverage.py`.
- **Adaptive attacker** (`--adaptive`): mutation loop replacing a single fixed string.
- **Schema-confirmed blast radius** (`--schema`): OpenAPI/function/MCP ingestion;
  self-reported tools never inflate the score. See `schema.py`.
- **Chain of custody**: hashed+timestamped exchanges, hash-chained audit log that detects
  alteration of any recorded field (it stores payload *digests*, not the payloads, and
  truncation needs an anchor kept outside the log), HAR export (`--har`, `--audit-log`).
  Scope allowlist (`--scope`) + rate limit (`--rate`).
- **Architecture assessment** (`--architecture`): defense-in-depth questionnaire,
  because architecture is what contains a compromised model.
- **Honesty**: see `METHODOLOGY_AND_LIMITATIONS.md` for what it does and does NOT prove.
 Probes use benign canaries and exist to
> help you *harden* a bot, not to attack third parties.

## Why it exists
Most open-source AI security tools are attack batteries. GLASSCAGE is the
pentester's full loop: **recon → probe → score → remediate → report**, with the
"suggest the fix" half that scanners skip.

## Quick start (Python 3.10+, no deps)
```bash
python cli.py --demo --out report                                  # full offline demo
python cli.py --config targets.example.json --authorized           # live chatbot
python cli.py --mcp-manifest samples/mcp_manifest.json             # MCP-only scan
python cli.py --mcp-manifest new.json --mcp-baseline old.json      # rug-pull diff
python cli.py --diff old.json new.json                             # regression diff
python cli.py --config t.json --authorized --judge --plugins ./p   # judge + plugins
python -m unittest discover -s tests -v                            # 13 tests
```
Outputs `.md` (with Mermaid graph), self-contained `.html`, and `.json`.

## Coverage
| ID | Probe / check | Detects |
|----|---------------|---------|
| LLM01 | direct-injection-canary | context-override injection |
| LLM01 | indirect-injection-rag | instructions inside untrusted retrieved content |
| LLM01 | multi-turn-erosion | crescendo-style guardrail erosion across turns |
| LLM02 | sensitive-info-disclosure | secret-shaped content in output |
| LLM05 | insecure-output-handling | unescaped active markup (downstream XSS) |
| LLM06 | excessive-agency-review | tool surface without least-privilege/HITL |
| LLM07 | system-prompt-leak | verbatim configuration disclosure |
| LLM10 | unbounded-consumption-review | missing rate/token/quota limits |
| LLM01 | encoded-injection | Base64/obfuscated instruction (filter bypass) |
| LLM01 | payload-splitting | instruction reassembled from parts |
| LLM01 | jailbreak-persona | persona/role-play bypass (AML.T0054) |
| LLM01 | multilingual-injection | non-English instruction bypass |
| LLM03 | supply-chain-review | model/plugin provenance & AI-BOM |
| LLM08 | vector-rag-review | RAG isolation & retrieval poisoning surface |
| LLM09 | misinformation-false-premise | acceptance of a false premise |
| MCP03 | mcp tool-poisoning | model-directed instructions / invisible chars in tool metadata |
| MCP03 | mcp rug-pull | tool definition changed since approval (hash-pinned diff) |
| MCP07 | mcp SSRF/exfil | URL/path params reaching internal/metadata endpoints |

Every finding carries: a plain-language **vulnerability reference**, **OWASP LLM Top 10 (2025)** id, **MITRE ATLAS** technique id (precise sub-techniques, e.g. AML.T0051.001 / AML.T0110), **false-positive verification steps**, concrete **remediation**, and **clickable standards links** (OWASP, ATLAS, CWE, NIST) - all URLs verified against the primary sources. See `glasscage/kb.py`.

**Interactive report + evidence.** The HTML report is a self-contained app with a severity dashboard, live search, severity/status filters, and collapsible findings; each finding has tabs for Evidence / Remediation / Verify / **Reproduce** / References. Every vulnerable/inconclusive finding gets a **screenshot-style SVG evidence card** (saved under `<out>_evidence/` and embedded inline) plus **numbered manual reproduction steps with a ready-to-run curl** (auth redacted) so a security team can re-validate by hand. A **refusal-aware, multilingual accuracy layer** stops the classic false positive where a bot *names* a canary while refusing. Use `--no-evidence` to skip cards.

## Architecture
```
recon.py       passive fingerprinting (model/guardrail/tool surface)
probes.py      pluggable detection probes (@register)
mcp.py         tool poisoning, rug-pull diff, SSRF surface
graph.py       attack-surface graph + blast radius + Mermaid
scoring.py     severity aggregation + agentic multiplier
remediation.py OWASP/MCP id -> concrete fixes
judge.py       optional LLM-as-judge (graceful fallback)
diff.py        regression diff across reports
plugins.py     load custom engagement probes from a directory
report.py      Markdown + self-contained HTML + JSON
engine.py      orchestrates the loop
target.py      generic HTTP chat adapter (stdlib only)
```

## Extending
```python
from glasscage.probes import Probe, register
from glasscage.models import Status, Severity

@register
class MyProbe(Probe):
    name = "my-probe"; owasp_id = "LLM01"; category = "Custom"
    def run(self, target, recon):
        r = target.send("...")
        # return [self._finding(...)]
```
Drop the file in a directory and load with `--plugins ./that_dir`.

## Roadmap
Multimodal injection (image/audio), OAuth/MCP-remote CVE checks, live agent
action-replay sandbox, CI/CD gating action, SARIF export.
