# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Coverage accounting.

Fixes the "false assurance" risk: a clean report must state exactly what was
tested and what was NOT. This module maps executed probes to a canonical taxonomy
and produces an explicit coverage statement plus a not-tested list. PASSED means
"resisted the specific strings tried", never "robust".
"""

from __future__ import annotations

# Canonical taxonomy GLASSCAGE reasons about (OWASP LLM Top 10 2025 + MCP/agentic).
CANONICAL = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector & Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "MCP03": "MCP Tool Poisoning / Rug Pull",
    "MCP07": "MCP SSRF / Tool-Param Exfiltration",
    "MULTIMODAL": "Multimodal / Cross-modal Injection",
}

# Categories GLASSCAGE cannot meaningfully test black-box and does NOT claim.
KNOWN_GAPS = {
    "LLM04": "Data/model poisoning requires training-pipeline access (not black-box testable).",
    "MULTIMODAL": "Image/audio injection requires a multimodal input channel and payload crafting.",
}


def build(findings, probes_run) -> dict:
    assessable = [f for f in findings if getattr(f, "status", None) is None
                  or str(getattr(f.status, "value", f.status)) != "not_assessable"]
    tested_ids = {f.owasp_id for f in assessable}
    not_assessable_ids = sorted({f.owasp_id for f in findings
                                 if str(getattr(f.status, "value", f.status)) == "not_assessable"}
                                - tested_ids)
    technique_count = len({f.probe_name for f in assessable})
    tested = sorted(i for i in CANONICAL if i in tested_ids)
    not_tested = sorted(i for i in CANONICAL if i not in tested_ids)
    return {
        "techniques_run": technique_count,
        "categories_tested": tested,
        "categories_not_tested": not_tested,
        "categories_not_assessable": not_assessable_ids,
        "known_gaps": {k: KNOWN_GAPS[k] for k in KNOWN_GAPS if k in not_tested or k in tested_ids},
        "coverage_ratio": round(len(tested) / len(CANONICAL), 2),
    }


def statement(cov: dict) -> str:
    """The exported coverage claim (ADR 0028).

    This string is what the HTML export renders as its `Coverage:` line, so it is an
    operator-facing claim. It used to read "Tested N techniques across 10/13 taxonomy
    categories" — a count that includes categories reached only by questionnaire or
    configuration review. Runtime coverage on the same run was 7/13. PR #28 corrected the
    markdown renderer; this is the same correction for the shared statement.

    The runtime figures are read from the coverage dict when present, exactly as supplied
    by `coverage_provenance`; nothing is recomputed and no value is hard-coded. A legacy
    coverage dict (`--no-aakg`) carries none of them, so the runtime sentence is omitted
    rather than guessed, and the graph-derived count is still not called "tested".
    """
    tested = ", ".join(cov["categories_tested"]) or "none"
    missed = ", ".join(cov["categories_not_tested"]) or "none"
    graph_n = len(cov["categories_tested"])

    parts = []
    prov = cov.get("coverage_provenance") or {}
    if prov:
        universe = prov.get("universe") or 0
        runtime = len(prov.get("runtime_tested") or [])
        ratio = cov.get("runtime_coverage_ratio")
        if ratio is None:
            ratio = round(runtime / universe, 2) if universe else 0.0
        parts.append(
            f"Runtime-tested coverage: {runtime}/{universe} ({ratio}) — categories where a "
            f"payload was actually sent: "
            f"{', '.join(prov.get('runtime_tested') or []) or 'none'}. "
            f"Configuration-review only: "
            f"{', '.join(prov.get('config_review_only') or []) or 'none'}. "
            f"Questionnaire only: "
            f"{', '.join(prov.get('questionnaire_only') or []) or 'none'}. "
            f"Not tested: {', '.join(prov.get('not_tested') or []) or 'none'}.")

    # ADR 0029: the sentence above is a CAPABILITY - it is registry-derived and reads the
    # same whether the target answered or refused. This one is the measurement of this run.
    # Omitted entirely when the key is absent, so a synthetic or legacy dict is not padded
    # with a figure no run produced.
    run_block = cov.get("run_measured_coverage") or {}
    if run_block:
        vouched = "" if run_block.get("custody_complete", True) else (
            " NOT VOUCHED: custody was incomplete for this run, so the delivered exchanges "
            "behind this figure cannot be attested in full.")
        parts.append(
            f"Measured runtime coverage this run: {run_block.get('measured_count', 0)}/"
            f"{run_block.get('universe', 0)} ({run_block.get('run_coverage_ratio', 0.0)}) — "
            f"categories that actually delivered a payload to this target: "
            f"{', '.join(run_block.get('measured_categories') or []) or 'none'}. "
            f"The runtime figure above is capability (categories with a runtime-capable "
            f"probe), not a measurement of this run.{vouched}")

    # Contextual, mixed provenance. Deliberately not called "tested": this count includes
    # categories carrying a finding that no payload established.
    parts.append(
        f"Graph-derived coverage (contextual, mixed provenance): {graph_n}/{len(CANONICAL)} "
        f"taxonomy categories with a mapped finding ({tested}); "
        f"ran {cov['techniques_run']} techniques. No mapped finding this run: {missed}.")

    caveat = cov.get("coverage_ratio_caveat")
    if caveat:
        parts.append(caveat)

    parts.append("'Passed' means the target resisted the specific inputs tried in this "
                 "run - it is NOT a proof of robustness against adaptive attackers.")
    return " ".join(parts)


# --- run-derived measured coverage (ADR 0029) -------------------------------
# `coverage_provenance.summarize()` classifies the *registry*: it answers "which
# categories have a probe that would send a payload". That is a capability, and it reads
# the same whether the target answered every request or refused all of them. The figures
# below answer a different question - "which categories actually delivered a payload to
# THIS target on THIS run" - and are computed from delivered exchanges, never from the
# registry, the findings, or the posture. The two are reported side by side and neither
# redefines the other.

def is_delivered(exchange: dict) -> bool:
    """True when this exchange record shows a response actually came back.

    Every transport records `status` (`target.HTTPChatTarget._record`,
    `targets/rest.py`, `refagent`), and every one of them writes 0 when the payload never
    reached the target - a refused connection, a timeout, a DNS failure. A non-zero status
    is an HTTP status line, which the target could only have produced after receiving the
    request; that includes 4xx/5xx, where the payload was delivered and rejected. A scope
    refusal raises before any record is written, so it cannot appear here at all.
    """
    try:
        return int(exchange.get("status") or 0) > 0
    except (AttributeError, TypeError, ValueError):
        return False


def run_measured(delivered_categories, custody_complete: bool = True) -> dict:
    """Assemble the run-derived block from the categories that delivered a payload.

    `delivered_categories` is whatever the engine observed; it is filtered to CANONICAL
    so a plugin probe carrying an off-taxonomy id cannot inflate the count, and it is a
    set, so a category with nine probes counts once. The denominator is `len(CANONICAL)`
    - the same 13 the capability figure uses - so the two are directly comparable.
    """
    cats = sorted({c for c in (delivered_categories or ()) if c in CANONICAL})
    universe = len(CANONICAL)
    return {
        "universe": universe,
        "measured_categories": cats,
        "measured_count": len(cats),
        "run_coverage_ratio": round(len(cats) / universe, 2) if universe else 0.0,
        "custody_complete": bool(custody_complete),
    }
