# GLASSCAGE Assessment Playbooks — 1.0.0rc3

> **Scope note.** These are **operator methodology recipes** — repeatable ways to use
> the functionality that exists today. GLASSCAGE has **no Playbook code subsystem**;
> an objective-driven Playbook/Probe-Pack framework is **Roadmap**. Nothing here
> describes unimplemented software.

Each playbook states: objective · prerequisites · commands · **what GLASSCAGE can
prove** · **what it cannot** · how to confirm manually.


## Playbook 1 — Black-box chat endpoint (L0/L1)

**Objective:** assess a hosted chat API you own.
**Prereqs:** written authorization; target config; staging preferred.

```bash
python -m glasscage --config t.json --authorized --rate 2 \
  --trials 5 --seed 1 --views executive security --out engagement-l0
```

**Can prove:** prompt injection (9 techniques), system-prompt leak (1 technique),
sensitive-info disclosure (1 technique), insecure output handling, misinformation,
unbounded consumption. Wilson CIs across 5 trials.

**Cannot prove:** anything agentic. Planner/memory/tool probes return **NOT
ASSESSABLE** — the target is L0/L1. **This is the expected result, not a failure.**

**Confirm manually:** reproduce each finding with the curl in its Reproduce tab.


## Playbook 2 — Agentic application with a tool schema (L1/L2)

**Objective:** assess a target that calls tools; obtain a real blast radius.
**Prereqs:** authorization + an OpenAPI/function schema.

```bash
python -m glasscage --config t.json --authorized \
  --schema tools.json --architecture arch.json \
  --trials 5 --seed 1 --views all --sarif --out engagement-agent
```

**Can prove:** everything in Playbook 1, plus **schema-confirmed blast radius** —
which high-value assets each declared tool reaches; graph-derived trust-boundary
violations and excessive privilege.

**Cannot prove:** that a tool actually *fired*, unless the target exposes a trace
(L2). Without a trace, tool-reachability edges are **hypothesized**, and the path
narrative will say so.

**Watch for:** `--architecture` answers are **trusted, not verified**. A wrong answer
suppresses violations and *lowers* the risk index. Answer only what you know.


## Playbook 3 — Instrumented agent (L2) — the differentiating case

**Objective:** demonstrate agentic exploitation with confirmed impact.
**Prereqs:** a target that returns planner/tool/memory traces.

```bash
python -m glasscage --config agent.json --authorized \
  --schema tools.json --trials 5 --views all --out engagement-l2
```

**Can prove:** planner manipulation, memory poisoning, tool-routing manipulation, goal
hijack — each **impact-confirmed via the trace**, yielding `demonstrated` graph edges
and a demonstrated attack path to real assets.

**Cannot prove:** generalisation. A demonstration on your agent says nothing about
other agents.

**Baseline first:** `python -m glasscage --harness --views all --out /tmp/expected`
shows what a full L2 result looks like. **The harness is a test fixture, not evidence
about your system.**


## Playbook 4 — MCP manifest review — **configuration review only**

**Objective:** review an MCP manifest for tool poisoning, rug-pulls and SSRF-prone
parameters.

```bash
python -m glasscage --mcp-manifest tools_list.json --out mcp-review
python -m glasscage --mcp-manifest new.json --mcp-baseline approved.json --out rugpull
```

**Can prove:** model-directed instructions or invisible characters in tool metadata
(MCP03); tool definitions changed since approval (MCP03 rug-pull, hash-pinned);
URL/path parameters referencing internal or metadata endpoints (MCP07).

**Cannot prove — read carefully:** **GLASSCAGE never contacts an MCP server.** This is
static analysis of a JSON manifest. Findings evidence defects **in the manifest**, not
exploitation of a running server. Runtime MCP interaction is **Roadmap**. Do not report
these as "MCP server tested".

**Best use:** the rug-pull diff in CI — pin an approved manifest, alert on drift.


## Playbook 5 — Regression / drift assessment

**Objective:** did our posture change between releases?

```bash
python -m glasscage --config t.json --authorized --seed 1 --out run-A
# ... ship changes ...
python -m glasscage --config t.json --authorized --seed 1 --out run-B
python -m glasscage --diff run-A.json run-B.json
```

**Can prove:** findings appearing/disappearing between runs.
**Cannot prove:** that a change *caused* the difference — targets are nondeterministic
and GLASSCAGE has never measured target repeatability. Use `--trials 5` on both runs
and treat single-trial differences as noise.


## Playbook 6 — Detector benchmarking — **Experimental**

```bash
python -m glasscage --benchmark benchmark/corpus.json --out bench
```

**Can prove:** precision/recall/F1 of GLASSCAGE's detectors on a **109-case,
single-annotator corpus** with Wilson CIs.

**Cannot prove:** detector accuracy on real model output. The corpus was authored
alongside the detectors. `[Measured]` on an `[Experimental]` corpus — both labels
matter. Note: the benchmark's "reproducibility" figure measures **detector
determinism on fixed strings**, not target repeatability.


## Playbook 7 — External framework adapters — **Pending External Validation**

```bash
python -m glasscage --validate-adapters --out adapters
python -m glasscage --adapter-file garak=real_run.report.jsonl --out ingest
```

**Can prove:** that a parser normalizes a supplied file into GLASSCAGE findings.

**Cannot prove:** that GLASSCAGE orchestrates garak/PyRIT/Promptfoo. **Zero genuine
tool outputs have ever been ingested** — `--validate-adapters` will tell you so
honestly (`Genuine-validated: 0`). If you have real output, pass it with
`--genuine-output tool=path` and the status upgrades to `Measured` for that framework.


## Playbook 8 — Client engagement with live secrets

**Objective:** a consulting engagement where evidence must be retained.

```bash
export GLASSCAGE_EVIDENCE_PASSWORD='...'
python -m glasscage --config t.json --authorized \
  --store-raw --encrypt-evidence --replay --audit-log custody.log \
  --views all --out client-engagement
```

**Safety:** `--store-raw` writes **live secrets** to disk. Sandboxed host only.
`--encrypt-evidence` requires `pip install glasscage[crypto]`. Custody hashes are
computed **before** redaction, so integrity holds either way. Replay bundles strip auth.


## Objective coverage — what one run actually tests

| Objective | Techniques | Read this |
|---|---|---|
| Prompt Injection | 9 | Adequate breadth |
| **Prompt Leakage** | **1** | A negative result means *one technique failed* |
| **Data Exfiltration** | **1** | Same caveat |
| **Indirect Injection** | **1 channel (RAG)** | URL-fetch / inbound-message / file channels untested |
| Memory / Planner / Tool Abuse | 1 each (L1/L2) | Single-strategy |
| Goal Hijack | 1 (L0) | Single-strategy |
| MCP | 3 static, **0 runtime** | Configuration review only |
| Supply Chain (LLM03), Vector/RAG (LLM08) | **questionnaire only** | **No payload is sent** |
| LLM04, Multimodal, Cross-agent | **0** | Roadmap |

**Multi-technique aggregation per objective is Roadmap.** Until then, "not vulnerable"
should be read as "these specific techniques did not succeed."
