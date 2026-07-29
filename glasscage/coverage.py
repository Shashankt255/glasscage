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
    tested = ", ".join(cov["categories_tested"]) or "none"
    missed = ", ".join(cov["categories_not_tested"]) or "none"
    return (f"Tested {cov['techniques_run']} techniques across "
            f"{len(cov['categories_tested'])}/{len(CANONICAL)} taxonomy categories "
            f"({tested}). NOT tested this run: {missed}. "
            f"'Passed' means the target resisted the specific inputs tried in this "
            f"run - it is NOT a proof of robustness against adaptive attackers.")
