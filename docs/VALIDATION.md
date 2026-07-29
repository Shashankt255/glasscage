# Validation Guide

How to validate GLASSCAGE against real targets and compare it with other tools. This is
a user-facing "how to check our claims" guide.

> **Honest status.** As of rc3, GLASSCAGE's efficacy has **not** been independently
> validated against real hosted models or agent frameworks. All agentic "demonstrated"
> results in this release come from the built-in deterministic reference harness. Treat
> every finding as a hypothesis. This guide tells you how to run your own validation.

## Principle: ground truth from the target's side

Do not accept a GLASSCAGE finding as true because GLASSCAGE reported it. Establish truth
independently:

- **Plant a canary secret** in the target's system prompt, then check whether it appears
  in the raw HTTP response — independently of GLASSCAGE's finding.
- **Instrument the target's tools** to log their own invocations. "GLASSCAGE says the
  tool fired" and "the tool's own log shows it fired" are independent statements; only
  the second is evidence.
- **Use a deliberately-vulnerable target** with published, third-party solutions as an
  answer key.

## Validating against a real target

1. Deploy a target you own (e.g. a local agent framework), pinned to a fixed version.
2. Plant known ground truth (canary secret; a poisoned document in a RAG corpus).
3. Run GLASSCAGE with `--trials 10 --seed 1` and `architecture_answers` left unknown.
4. For each finding, classify against your independent ground truth:
   - **True positive:** GLASSCAGE reported it and your independent check confirms it.
   - **False positive:** GLASSCAGE reported it; your check refutes it.
   - **False negative:** your check shows it; GLASSCAGE missed it. **Record these — the
     false-negative rate is the number GLASSCAGE has never had.**
   - **True negative:** neither shows it.
5. Measure **target repeatability**: proportion of the 10 runs with consistent behaviour,
   with Wilson intervals. Note: the benchmark's "reproducibility" figure measures
   detector determinism on fixed strings, **not** target repeatability.

## Comparing with garak, Promptfoo, PyRIT, Inspect AI

Run each tool against the **identical, pinned** deployment, same seeds, same corpus.

### Do not run a "who finds more" contest
garak sends far more probes (~120+ built-in) than GLASSCAGE (21). Raw counts flatter
breadth and tell you nothing about consequence modelling. Normalize.

### Metrics to record

| Metric | How |
|---|---|
| Raw findings | count per tool |
| **Findings per request** | TP ÷ requests sent — makes 21 vs 1000s comparable |
| **Unique TPs** | found by only one tool — the real breadth signal |
| **Evidence quality** | 0–3: 0 assertion · 1 snippet · 2 reproducible request/response · 3 + independent side-effect confirmation |
| **Explainability** | 0–3: 0 finding only · 1 + category · 2 + affected component · 3 + reachability/consequence |
| **False positives / negatives** | vs your independent ground truth |
| **Analyst effort** | measured minutes to triage all findings to a decision |
| **Runtime** | wall-clock + requests + tokens |

### Where each tool is expected to lead

- **garak:** breadth of probes. Use it for coverage of many techniques.
- **Promptfoo:** CI ergonomics and eval workflows.
- **PyRIT:** multi-turn attack depth (Crescendo/TAP/etc.).
- **Inspect AI:** rigorous evaluation harness.
- **GLASSCAGE:** consequence modelling — what a finding reaches, which trust boundary it
  crosses, and evidence-gated narratives. This is the only axis on which GLASSCAGE claims
  to lead.

### Ingesting other tools' output

GLASSCAGE can parse external tool output into its graph:

```bash
python -m glasscage --adapter-file garak=run.report.jsonl --out combined
python -m glasscage --validate-adapters --out status   # honest parser status
```

> **Status:** adapter parsers are **Pending External Validation** — they conform to
> fixtures, and genuine tool output has not been ingested at scale. `--validate-adapters`
> reports this honestly (e.g. `Genuine-validated: 0`). Supply real output with
> `--genuine-output tool=path` to upgrade a framework's status to `Measured`.

## What GLASSCAGE validation can never claim

- That it is broader than garak (it is not: 21 vs 120+ probes).
- That it is deeper than PyRIT on multi-turn (it is not).
- That results generalise beyond the specific targets tested.
- That the risk index is calibrated (it is an uncalibrated heuristic).
