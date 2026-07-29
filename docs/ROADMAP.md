# Roadmap

This lists what is **not** implemented today, so nothing in this documentation is
mistaken for a current feature. Items are grouped by priority. Priorities reflect
release-readiness, not difficulty.

> Nothing here is available in rc3. If you need one of these, it is not currently
> supported.

## Before GA (Priority 0)
- **Real-target validation** — evaluate the full pipeline against real hosted models and
  agent frameworks; publish results separately from harness results.
- **Coverage accounting fix** — report a runtime-only ratio plus a provenance breakdown
  (runtime / configuration-review / questionnaire / not-tested), instead of the current
  `coverage_ratio` that counts non-runtime findings as tested.
- **Genuine external-tool ingestion** — ingest real garak/Promptfoo output (currently
  Pending External Validation).
- **Control verification** — stop trusting self-declared `--architecture` answers without
  verification.
- **Release signing / provenance.**
- **Real security contact** in SECURITY.md (currently a placeholder).

## Soon after GA (Priority 1)
- **Multi-technique aggregation** — objectives such as prompt leakage and data
  exfiltration currently rely on a single technique; aggregate multiple techniques into
  one finding.
- **Delivery-channel taxonomy** for indirect injection (URL-fetch, inbound message,
  file, tool-output — currently only the retrieval channel).
- **`edge(id)` accessor** to remove the narrative linear-scan performance cost; cap path
  enumeration.
- **Differential reporting surfaced** (the `--diff` capability exists; broader trend
  surfacing is planned).
- **Async execution, rate-limit backoff, resume.**

## Medium term (Priority 2)
- **Runtime MCP interaction** (today: static manifest review only).
- **Trend reporting** (requires results persistence, which does not exist today).
- Retire the legacy `graph.py` and `posture/coverage/chain/trust` shims.
- Consumer-grade generated API docs.

## Research (Priority 3)
- **Risk-index calibration** against real outcomes — or removal of the numeric index.
- **Multimodal (L3)** probes and **LLM04 (Data & Model Poisoning)** — no probes today.
- **Cross-agent abuse** — no probes today.
- Graph query language / storage backend.

## Explicitly not planned
- Fleet-scale / multi-tenant SaaS (the architecture is single-assessment).
- Classical-ML attack surface (evasion/poisoning of non-LLM classifiers).
- Reimplementing multi-turn algorithms that PyRIT already provides (integrate via
  adapter instead).
