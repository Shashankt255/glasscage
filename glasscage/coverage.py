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
