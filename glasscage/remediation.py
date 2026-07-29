# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Remediation advisor: map each finding to concrete, actionable fixes.

This is the "suggest the fix" half of the tool. Keyed by OWASP LLM id so any new
probe automatically inherits guidance as long as it declares an owasp_id.
"""

from __future__ import annotations

from .models import Finding

_REMEDIATION: dict[str, list[str]] = {
    "LLM01": [  # Prompt Injection
        "Separate trusted instructions from untrusted input using structured "
        "roles/delimiters; never concatenate user text into the system prompt.",
        "Constrain output with strict schemas and validate before use.",
        "Apply an input/output guardrail layer (classifier or allow/deny policy).",
        "For indirect injection, sanitize and label retrieved/RAG content as untrusted.",
    ],
    "LLM02": [  # Sensitive Information Disclosure
        "Keep secrets, keys, and internal URLs out of prompts and context entirely; "
        "fetch them server-side at tool-execution time, never in the model context.",
        "Add output filters that redact secret-shaped patterns before returning text.",
        "Scope retrieval so the model can only see data the current user may access.",
    ],
    "LLM05": [  # Improper Output Handling
        "Treat all model output as untrusted; context-encode before rendering (HTML "
        "escape, JS-encode) to neutralize XSS.",
        "Never pass model output directly into eval(), shells, SQL, or DOM sinks.",
        "Use parameterized queries and sandboxing for any downstream execution.",
    ],
    "LLM06": [  # Excessive Agency
        "Apply least privilege: give each tool the minimum scope required.",
        "Allowlist tools/servers; deny by default.",
        "Add human-in-the-loop confirmation for high-impact actions (write, pay, delete).",
        "Bind the agent to an identity and log every tool call for audit.",
    ],
    "LLM07": [  # System Prompt Leakage
        "Assume the system prompt is discoverable; put no secrets or access rules in it.",
        "Enforce authorization in application code, not via prompt instructions.",
        "Add a guardrail that blocks verbatim disclosure of configuration text.",
    ],
    "LLM03": [  # Supply Chain
        "Maintain an AI-BOM; pin and verify (hash/signature) all models, datasets, plugins.",
        "Vet third-party model/plugin provenance; avoid unpinned auto-updating components.",
        "Scan model artifacts for tampering before deployment.",
    ],
    "LLM08": [  # Vector & Embedding
        "Enforce per-tenant/per-user partitioning and access control on the vector store.",
        "Validate and provenance-tag content before indexing; sign trusted sources.",
        "Treat retrieved chunks as untrusted; apply indirect-injection defenses at query time.",
    ],
    "LLM09": [  # Misinformation
        "Ground answers with citations/RAG and validate against authoritative sources.",
        "Constrain scope and add disclaimers for high-stakes domains; keep humans in the loop.",
        "Monitor for hallucinated entities and provide user-facing uncertainty signals.",
    ],
    "LLM10": [  # Unbounded Consumption
        "Enforce per-user rate limits, request quotas, and max output-token caps.",
        "Add cost/anomaly monitoring and circuit-breakers on spend.",
        "Reject or truncate oversized inputs before they reach the model.",
    ],
    "MCP03": [  # Tool Poisoning / rug pull
        "Pin (hash) tool descriptions and schemas at approval; block on drift.",
        "Allowlist MCP servers; deny by default and require re-approval for changes.",
        "Strip/deny invisible and bidi characters in tool metadata.",
        "Isolate untrusted servers from any agent holding filesystem/shell/cred access.",
    ],
    "MCP07": [  # SSRF / exfil via tool params
        "Validate and allowlist URL/host/path parameters; block internal ranges "
        "and cloud metadata endpoints (169.254.169.254).",
        "Run tool egress through a broker that enforces network policy.",
        "Never let a tool return raw credentials/metadata into the model context.",
    ],
    "MCP00": [
        "No MCP issues detected; keep baseline snapshots and re-scan on every change.",
    ],
    "LLM00": [  # Fallback
        "Manual review recommended; no automated remediation mapping for this class yet.",
    ],
}


def advise(finding: Finding) -> list[str]:
    return _REMEDIATION.get(finding.owasp_id, _REMEDIATION["LLM00"])


def apply_all(findings: list[Finding]) -> None:
    for f in findings:
        if not f.remediation:
            f.remediation = advise(f)
