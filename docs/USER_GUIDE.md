# GLASSCAGE User Guide — 1.0.0rc3

> **Maturity of this release: Release Candidate.** GLASSCAGE is honest about what it
> can prove. Read [Known Limitations](#known-limitations) before you rely on any number
> in a report. Findings are **hypotheses to confirm**, not conclusions.

---

## 1. What GLASSCAGE is

GLASSCAGE is a zero-dependency (Python standard library only) security assessment
platform for LLM and agentic applications. It probes an authorized target, records
evidence, and builds an **AI Attack Knowledge Graph (AAKG)** — a typed graph of
findings, evidence, components, tools, assets, secrets, trust zones and taxonomy
mappings. Every downstream answer (attack paths, trust boundaries, blast radius,
coverage, remediation, narratives) is derived from that one graph.

**What makes it different:** other tools produce a *list of findings*. GLASSCAGE
answers *"so what?"* — what a finding reaches, which trust boundary it crosses, which
assets fall — and it refuses to claim more than its evidence supports.

**What it is not:** it is not a fleet scanner, not a validated efficacy measurement,
and not a substitute for an expert. See [Known Limitations](#known-limitations).

---

## 2. Install

```bash
# zero runtime dependencies
pip install glasscage

# optional extras
pip install cryptography         # encrypted evidence at rest (no 'crypto' extra in rc3)
pip install glasscage[llm]      # optional LLM-as-judge
pip install glasscage[yaml]     # YAML config
pip install glasscage[dev]      # pytest / ruff / mypy / build
```

Requires Python ≥ 3.10. Run via `glasscage`, `python -m glasscage`, or `python cli.py`.

---

## 3. Quickstart

```bash
# 1. Safe: run against the built-in mock (no network, nothing to authorize)
python -m glasscage --demo --out report

# 2. Safe: run against the built-in L2 reference agent (planner/memory/tools)
python -m glasscage --harness --out report

# 3. Real target (requires explicit authorization)
python -m glasscage --config targets.json --authorized --out report
```

Outputs: `report.md`, `report.html`, `report.json`, `report_aakg.json`, `report_evidence/`.

### Target config

```json
{
  "name": "my-support-bot-staging",
  "url": "https://your-bot.example.com/v1/chat",
  "method": "POST",
  "headers": { "Authorization": "Bearer REPLACE_WITH_YOUR_TOKEN" },
  "body_template": { "messages": [ { "role": "user", "content": "{{PROMPT}}" } ] },
  "response_path": "choices.0.message.content",
  "timeout": 30
}
```

`{{PROMPT}}` is substituted with each probe payload. `response_path` is a dotted path
into the JSON response. Config is validated on load; errors are actionable.

---

## 4. Core concepts (you must understand these to read a report)

### 4.1 Steerability vs Impact — **Implemented**
The single most important distinction in GLASSCAGE.
- **Steerability**: the model echoed a canary / followed an instruction. Interesting, capped severity.
- **Impact**: something real happened — a secret was disclosed, a tool fired.

Only **impact** drives high risk. A model that repeats a canary is not the same as one
that leaks your database credentials, and GLASSCAGE never conflates them.

### 4.2 Capability Tiers (L0–L3) — **Implemented**
| Tier | Target exposes | Consequence |
|---|---|---|
| L0 | text in / text out | agentic probes cannot run |
| L1 | + memory/session state | memory probes can run |
| L2 | + planner / tool traces | planner, tool-routing probes can run |
| L3 | + multimodal / logprobs | **Roadmap** |

**A probe above the target's tier returns `NOT ASSESSABLE` — never a pass.** This is
deliberate: GLASSCAGE reports what it could not determine instead of guessing.

> **Practical consequence:** most real black-box endpoints are L0/L1. The agentic
> analysis that differentiates GLASSCAGE will mostly return NOT ASSESSABLE against
> them. That is an honest result, not a defect — but set expectations accordingly.

### 4.3 Evidence Confidence Classification — **Implemented**
Every report section carries exactly one class. A claim can never exceed its evidence
(enforced in code, not by convention):

| Class | Meaning |
|---|---|
| **Verified** | confirmed against ground truth or a cryptographic check (custody hash) |
| **Measured** | quantified with a stated method (detector precision/recall on the corpus) |
| **Demonstrated** | observed on-target: impact-confirmed finding or fully-demonstrated path |
| **Observed** | seen in a response but not impact-confirmed |
| **Experimental** | from an Experimental component or small dataset; indicative only |
| **Estimated** | heuristic from an uncalibrated model (e.g. the Indicative Risk Index) |
| **Hypothesized** | architecturally reachable but not shown; confirm manually |
| **Pending External Validation** | framework implemented, not yet run against real external tools; no result claimed |

### 4.4 Graph edge states — **Implemented**
`demonstrated` · `hypothesized` · `not_assessable`. **A path's state is its weakest
hop.** One hypothesized hop makes the whole path hypothesized, however strong the rest.

### 4.5 Indicative Risk Index — **Implemented (as a heuristic)**
A 0–100 number where higher is worse. **It is an uncalibrated heuristic `[Estimated]`,
not a statistical or calibrated measure.** Every point is attributed to a graph factor
in the contribution breakdown. Use it to *prioritize between findings on one target*,
never to compare targets or to state absolute risk.

> **Do not put this number in front of a board as "our AI risk is 74".** It has never
> been calibrated against real outcomes.

---

## 5. Feature maturity matrix

| Feature | Maturity |
|---|---|
| AAKG graph engine (24 node types, 12 edge types) | **Implemented** |
| Attack path engine (dynamic traversal, weakest-link state) | **Implemented** |
| Trust boundary analysis | **Implemented** |
| Blast radius analysis | **Implemented** |
| Attack Narratives (8 strategies) | **Implemented** |
| Assessment Story (13 sections) | **Implemented** |
| Audience views (5) | **Implemented** |
| Evidence Confidence Classification | **Implemented** |
| Secret redaction (default-on) | **Implemented** |
| Encrypted evidence at rest | **Implemented** (requires the `cryptography` package; there is no `crypto` extra in rc3) |
| Chain of custody (hash-chained audit) | **Implemented** — detects alteration of a recorded entry; stores payload digests, not payloads; does not detect tail truncation (ADR 0019) |
| Capability tiers L0–L2 | **Implemented** |
| Prompt injection probes (9 techniques) | **Implemented** |
| Reference agent harness (L2) | **Implemented** |
| Graph-native reporting (MD/HTML/JSON) | **Implemented** |
| SARIF 2.1.0 export | **Implemented** |
| Replay bundles | **Implemented** |
| Plugin SDK (consent-gated) | **Implemented** |
| MCP manifest analysis (tool-poisoning, rug-pull, SSRF params) | **Implemented — configuration review only; no MCP server is contacted** |
| Wilson confidence intervals / trials | **Implemented** |
| Genetic + adaptive attack engines | **Implemented** |
| Indicative Risk Index | **Implemented — uncalibrated heuristic** |
| Detector benchmark corpus (n=109) | **Experimental** |
| Agentic exploitation capability | **Experimental** — demonstrated only against the built-in harness |
| External adapters (garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI) | **Pending External Validation** — parsers conform to fixtures; 0 of 5 genuine tool outputs ingested |
| Cross-framework validation | **Pending External Validation** |
| LLM-as-judge | **Experimental** (requires `llm` extra) |
| Runtime MCP interaction | **Roadmap** |
| Multimodal injection (L3) | **Roadmap** |
| LLM04 (Data & Model Poisoning) | **Roadmap** |
| Cross-agent abuse | **Roadmap** |
| Async / rate-limit backoff / resume | **Roadmap** |
| Trend reporting (requires persistence) | **Roadmap** |
| Risk index calibration | **Roadmap** |

---

## 6. Known Limitations

Read this section before quoting GLASSCAGE in any deliverable.

### 6.1 Coverage is currently overstated — **known defect**
`coverage_ratio` counts a category as "tested" if **any** finding carries its id,
regardless of how that finding was obtained. Verified breakdown for the full canonical
set of 13 categories:

| Evidence method | Count | Categories |
|---|---|---|
| **Runtime tested** (payload sent to the live target) | **7** | LLM01, LLM02, LLM05, LLM06, LLM07, LLM09, LLM10 |
| **Questionnaire only** (no target contact) | 2 | LLM03, LLM08 |
| **Configuration review** (manifest parsed; no target contact) | 2 | MCP03, MCP07 |
| **Not tested** | 2 | LLM04, MULTIMODAL |

**True runtime coverage is 7/13 = 0.54.** With an MCP manifest supplied, the tool
reports `0.85`. **Treat 0.54 as the honest figure and do not quote `coverage_ratio`
externally until this is corrected.** Tracked as a P0 release blocker.

### 6.2 Efficacy has not been independently validated
GLASSCAGE has **not** been evaluated against real hosted models or real agent
frameworks. All agentic "demonstrated" results come from the built-in reference
harness, which is deterministic and authored alongside the probes. **Treat every
finding as a hypothesis requiring manual confirmation.**

### 6.3 External tool orchestration is unproven
Adapters parse author-written fixtures. **Zero genuine tool outputs have ever been
ingested.** GLASSCAGE should not be described as "orchestrating" garak/PyRIT/Promptfoo.

### 6.4 Self-declared architecture answers are trusted
`--architecture` answers are taken at face value: a declared control creates a
Mitigation node, suppresses trust-boundary violations, and discounts the risk index.
**GLASSCAGE does not verify that declared controls exist.** Only supply answers you
know to be true; an inaccurate answer produces a falsely reassuring report.

### 6.5 Single-technique objectives
Several objectives are covered by exactly one technique — notably **prompt leakage**
and **data exfiltration**. A negative result there means "one technique did not
succeed", **not** "the target is not vulnerable".

### 6.6 Other limitations
- **Redaction is pattern-based** (API key / AWS / password / PEM shapes). Novel secret
  formats may pass through. Review artifacts before sharing.
- **Plugins are not sandboxed** — they run as arbitrary code with your privileges.
- **No release signing** yet.
- **Serial execution** — no async, no rate-limit backoff, no resume. Large engagements
  are slow and cannot resume on failure.
- **"Reproducibility" in benchmark output** measures detector determinism on fixed
  strings, not target repeatability.

---

## 7. Where to go next

| You are | Read |
|---|---|
| Running an assessment | [Operator Manual](COMMAND_REFERENCE.md) |
| Deploying / securing GLASSCAGE | [Administrator Guide](ADMIN_GUIDE.md) |
| Extending it | [Developer Guide](DEVELOPER_GUIDE.md) · [API Reference](DEVELOPER_GUIDE.md) |
| Choosing what to test | [Assessment Playbooks](ASSESSMENT_WORKFLOW.md) |
| Reading the output | [Report Interpretation Guide](REPORT_GUIDE.md) |
| Learning by doing | [Tutorials](TUTORIALS.md) |
