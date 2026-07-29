# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Taxonomy crosswalk (GLASSCAGE Stage D).

Status: Implemented (static reference table; NOT the AI Attack Knowledge Graph).

A flat, auditable crosswalk from OWASP LLM Top 10 (2025) to MITRE ATLAS, CWE,
CAPEC, and NIST AI RMF, plus heuristics to map external-framework rule/probe/
plugin identifiers onto an OWASP id. Used by the adapters to normalize imported
findings. Deliberately a lookup table, not a graph engine. CAPEC/NIST mappings
are best-effort advisory.
"""

from __future__ import annotations

import re

CROSSWALK = {
    "LLM01": {"name": "Prompt Injection", "atlas": "AML.T0051",
              "cwe": "CWE-1427", "capec": "CAPEC-248", "nist": "MEASURE-2.7"},
    "LLM02": {"name": "Sensitive Information Disclosure", "atlas": "AML.T0057",
              "cwe": "CWE-200", "capec": "CAPEC-118", "nist": "MEASURE-2.9"},
    "LLM03": {"name": "Supply Chain", "atlas": "AML.T0020",
              "cwe": "CWE-1357", "capec": "CAPEC-437", "nist": "MAP-4.1"},
    "LLM04": {"name": "Data & Model Poisoning", "atlas": "AML.T0020",
              "cwe": "CWE-1395", "capec": "CAPEC-586", "nist": "MEASURE-2.8"},
    "LLM05": {"name": "Improper Output Handling", "atlas": "",
              "cwe": "CWE-79", "capec": "CAPEC-63", "nist": "MEASURE-2.6"},
    "LLM06": {"name": "Excessive Agency", "atlas": "AML.T0053",
              "cwe": "CWE-250", "capec": "CAPEC-122", "nist": "GOVERN-1.1"},
    "LLM07": {"name": "System Prompt Leakage", "atlas": "AML.T0056",
              "cwe": "CWE-200", "capec": "CAPEC-116", "nist": "MEASURE-2.9"},
    "LLM08": {"name": "Vector & Embedding Weaknesses", "atlas": "AML.T0070",
              "cwe": "CWE-284", "capec": "CAPEC-121", "nist": "MEASURE-2.6"},
    "LLM09": {"name": "Misinformation", "atlas": "",
              "cwe": "CWE-1426", "capec": "", "nist": "MEASURE-2.3"},
    "LLM10": {"name": "Unbounded Consumption", "atlas": "AML.T0029",
              "cwe": "CWE-400", "capec": "CAPEC-125", "nist": "MEASURE-2.6"},
    "MCP03": {"name": "MCP Tool Poisoning", "atlas": "AML.T0110",
              "cwe": "CWE-829", "capec": "CAPEC-175", "nist": "MAP-4.1"},
    "MCP07": {"name": "MCP SSRF / Exfiltration", "atlas": "",
              "cwe": "CWE-918", "capec": "CAPEC-664", "nist": "MEASURE-2.7"},
}

_KEYWORD_MAP = [
    (r"ssrf|serverside", "MCP07"),
    (r"mcp.*poison|toolpoison|rugpull", "MCP03"),
    (r"inject|jailbreak|dan|prompt|encoding|latentinjection|suffix|autodan|gcg|"
     r"crescendo|tap|skeleton|artprompt|manyshot|roleplay", "LLM01"),
    (r"leak|pii|secret|sensitive|disclosure|privacy|exfil", "LLM02"),
    (r"supplychain|package|dependency|typosquat", "LLM03"),
    (r"poison|backdoor|trojan", "LLM04"),
    (r"xss|output|markup|htmlinjection|codeexec|sqli", "LLM05"),
    (r"agency|tool|function|excessive|autonomy", "LLM06"),
    (r"systemprompt|metaprompt|promptextraction|promptleak", "LLM07"),
    (r"rag|retrieval|embedding|vector", "LLM08"),
    (r"hallucinat|misinfo|factual", "LLM09"),
    (r"dos|denial|resource|flood|consumption", "LLM10"),
]


def classify(rule_name: str) -> str:
    low = (rule_name or "").lower()
    for pattern, owasp in _KEYWORD_MAP:
        if re.search(pattern, low):
            return owasp
    return "LLM01"


def enrich(owasp_id: str) -> dict:
    return CROSSWALK.get(owasp_id, {"name": "Uncategorized", "atlas": "", "cwe": "",
                                    "capec": "", "nist": ""})


def enrich_all(findings) -> None:
    """Fill cwe_id/capec_id/nist_id (and atlas_id if missing) from the crosswalk.

    Applied to native findings so every GLASSCAGE finding carries the full
    OWASP/ATLAS/CWE/CAPEC/NIST mapping, matching imported external findings.
    """
    for f in findings:
        x = CROSSWALK.get(getattr(f, "owasp_id", ""), None)
        if not x:
            continue
        if not getattr(f, "cwe_id", ""):
            f.cwe_id = x["cwe"]
        if not getattr(f, "capec_id", ""):
            f.capec_id = x["capec"]
        if not getattr(f, "nist_id", ""):
            f.nist_id = x["nist"]
        if not getattr(f, "atlas_id", "") and x["atlas"]:
            f.atlas_id = x["atlas"]
