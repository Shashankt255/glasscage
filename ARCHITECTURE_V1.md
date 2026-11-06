# GLASSCAGE v1.0 — Architecture & Objective Status

An honest map of the v0.5 → v1.0 upgrade. Status legend:
**[DONE]** implemented + tested · **[PARTIAL]** working core, depth-limited ·
**[SCAFFOLD]** interface + hook, needs a live harness · **[ROADMAP]** designed, not built.

Backward compatibility: every v1.0 stage is additive. The old `Engine(target).run()`
call still works; new capabilities are opt-in flags or extra result keys. No existing
signature was broken (report functions gained optional trailing params only).


## 1. Platform (not just a scanner) — [PARTIAL]
The engine already runs recon → probes → adaptive/genetic → MCP → architecture →
enrichment → custody/evidence → graph → coverage → scoring → trust → chains →
posture. What makes it "platform" vs "scanner": trust modeling, exploit chains,
dynamic posture, SARIF/replay, CI templates, plugins. Still scanner-shaped at the
transport layer (single HTTP chat endpoint); a multi-adapter session/agent harness
is the remaining platform gap (see #4).

## 2. Multi-turn attack graphs / exploit chains — [DONE] `chain.py`
Rationale: single findings understate composed risk. Implementation: canonical
kill-chain templates (Injection→Tool→Exfil, Injection→Planner→PrivEsc,
Indirect→Memory→Persistence, Leak→Tailored-Injection, MCP-Poison→Auto-Invoke→Exfil)
instantiate only when preconditions hold (evidenced findings + trust reachability);
each chain has a likelihood (product of link confidences), inferred-link flags,
severity, narrative, and Mermaid. Complexity: medium. Extend by adding templates.

## 3. Adaptive/genetic engine — [DONE] `genetic.py` (+ `mutation.py`)
Rationale: fixed strings under-approximate adversaries. Implementation: GA with a
genome of transformation operators (encoding, roleplay, multilingual, base64,
nested-quote, authority…), tournament selection, crossover, mutation, elitism,
reinforcement-style fitness from responses, seeded/reproducible, budget-bounded,
optional LLM operator. Limitation: not gradient/GCG; benign canary objective only.
Complexity: medium-high.

## 4. Agent-security testing — [PARTIAL/SCAFFOLD] `agent_probes.py`
Rationale: agent loops fail differently. Implemented probes (steerability signals):
planner manipulation, memory poisoning (2-turn persistence check), goal hijack,
tool-routing manipulation, loop amplification (bounded), context-window pressure
(bounded). Honest limit: black-box single-endpoint testing observes *willingness*;
confirming a planner re-order, cross-session memory, or a real tool firing needs a
live agent harness (SCAFFOLD). Reflection poisoning and retrieval poisoning are
partially covered via indirect-injection/RAG probes. Complexity: high for the
harness.

## 5. Architecture / trust-boundary analyzer — [DONE] `trust.py`
Rationale: architecture, not a scanner, contains a compromised model. Implementation:
components grouped into trust zones (untrusted/semi/trusted), edges from schema +
MCP + base flow, privilege-transition detection, boundary-violation flags keyed to
missing architecture controls, Mermaid with zone subgraphs. Complexity: medium.

## 6. Dynamic risk model / posture 0–100 — [DONE] `posture.py`
Rationale: letter grades hide reasoning and don't compose. Implementation: eight
weighted factors (exploitability, privileges, reachable assets, automation,
persistence, blast radius, business impact, chain risk), each 0..1 with stated
inputs → Risk Index 0–100 → Posture Score = 100 − Risk Index, plus a
coverage/confidence interval. All factors/weights emitted for audit. Complexity:
medium. (Per-finding CVSS-style vector remains in `cvss.py`.)

## 7. Deployment-specific remediation — [DONE] `kb.py` + `remediation.py` + `architecture.py`
Least privilege, tool isolation, sandboxing, confirmation workflows, MCP permission
restrictions, memory protections, prompt hardening, tenant isolation, secrets
handling — mapped per OWASP id and per missing architecture control. Complexity: low.

## 8. Regression / drift — [PARTIAL] `diff.py`
Baseline comparison + REGRESSED/IMPROVED/NO-CHANGE verdicts + introduced/fixed/
severity-changed. [ROADMAP]: historical trend store, model/prompt/policy A–B
comparison matrices. Complexity: medium.

## 9. Enterprise integrations — [PARTIAL] `sarif.py`, `integrations/`
[DONE] SARIF 2.1.0, JSON, HTML, Markdown; GitHub Actions / GitLab CI / Azure
Pipelines templates. [ROADMAP] PDF (needs a rendering dep — conflicts with the
zero-dep core; recommend an optional extra), OpenTelemetry span export, native SIEM
(CEF/LEEF) connectors. Complexity: low–medium.

## 10. Plugin architecture — [PARTIAL] `plugins.py` + probe registry
Custom probes load from a directory via `@register` with no core changes. [ROADMAP]
formal entry-point discovery and registries for chains/reporters/adapters.
Complexity: low.

## 11. Reporting — [DONE] `report.py` + `sarif.py`
Executive summary, posture, attack-chain diagrams, trust-boundary diagram,
OWASP/ATLAS mapping, evidence cards, chain-of-custody hashes, reproduction scripts
(curl), and a replay bundle + runner. Interactive filtering/search/tabs. [ROADMAP]
business-impact $ modeling, evidence timeline view. Complexity: medium.

## 12. Zero-dependency / modular / production — [DONE]
Core remains standard-library only. New modules are small, single-responsibility,
documented, and covered by 43 tests. Optional extras (anthropic, pyyaml, rich) stay
optional; PDF/OTel would be additional optional extras.


## What to build next (highest leverage)
1. **Live agent harness** (adapter for multi-step tool-calling agents) — unlocks
   real impact confirmation and true agentic chain validation (#4, #1).
2. **Historical trend store** for drift dashboards (#8).
3. **OTel + SIEM exporters** and **optional PDF** extra (#9).
Everything else is incremental.
