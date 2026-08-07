# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Architecture / defense-in-depth assessment.

The most important review point: tools don't secure systems, architecture does.
Prompt injection has no complete fix, so the highest-value question is whether the
system is designed to CONTAIN a compromised model - least privilege on tools,
output encoding, human-in-the-loop on high-impact actions, tenant isolation,
secrets kept out of context, and monitoring.

This module scores a short architecture questionnaire (answers provided by the
engineer) and turns gaps into findings/recommendations mapped to OWASP mitigations.
It is assessed input, clearly labelled as such - not something GLASSCAGE can probe
black-box.
"""

from __future__ import annotations

from .models import Finding, Severity, Status

# id -> (question, owasp_id, severity_if_missing, remediation_if_missing)
CONTROLS = {
    "tool_least_privilege": (
        "Does each tool/function run with the minimum scope required (not a broad service identity)?",
        "LLM06", Severity.HIGH,
        "Scope every tool to least privilege; give the app its own tokens, handle privileged calls in code."),
    "hitl_high_impact": (
        "Are high-impact actions (write/delete/pay/exec) gated behind human confirmation?",
        "LLM06", Severity.HIGH,
        "Add human-in-the-loop confirmation for irreversible/high-impact actions."),
    "output_encoding": (
        "Is model output context-encoded/sanitized before rendering or passing to any sink?",
        "LLM05", Severity.HIGH,
        "Treat model output as untrusted; context-encode before HTML/SQL/shell sinks."),
    "untrusted_content_segregation": (
        "Is retrieved/tool/external content clearly delimited and treated as untrusted?",
        "LLM01", Severity.MEDIUM,
        "Segregate and label untrusted content; never merge it into trusted instructions."),
    "secrets_out_of_context": (
        "Are secrets/keys kept OUT of the prompt/context and fetched server-side at call time?",
        "LLM02", Severity.HIGH,
        "Remove secrets from prompts/system prompt; fetch server-side, never expose to the model."),
    "authz_in_code": (
        "Is authorization enforced in application code rather than via prompt instructions?",
        "LLM07", Severity.HIGH,
        "Enforce access control in code; assume the system prompt is discoverable."),
    "tenant_isolation": (
        "Does retrieval/RAG enforce per-user/per-tenant access control?",
        "LLM08", Severity.HIGH,
        "Partition the vector store; filter retrieval by the caller's authorization."),
    "rate_and_cost_limits": (
        "Are per-user rate limits, token caps, and cost/anomaly alerts in place?",
        "LLM10", Severity.MEDIUM,
        "Enforce quotas/token caps and add cost circuit-breakers."),
    "mcp_allowlist_pinning": (
        "Are MCP servers/tools allowlisted and their definitions pinned (hash) at approval?",
        "MCP03", Severity.HIGH,
        "Allowlist MCP servers; hash-pin tool definitions; re-approve on drift."),
    "monitoring_logging": (
        "Are all tool calls and model I/O logged and monitored for abuse?",
        "LLM06", Severity.MEDIUM,
        "Log every tool call and prompt/response; alert on anomalies."),
}


def template() -> dict:
    """A blank answers file the engineer fills in: yes / no / unknown."""
    return {k: "unknown" for k in CONTROLS}


def assess(answers: dict) -> list[Finding]:
    findings: list[Finding] = []
    for cid, (question, owasp, sev, fix) in CONTROLS.items():
        ans = str(answers.get(cid, "unknown")).lower()
        if ans in ("yes", "y", "true"):
            status, s, title = Status.PASSED, Severity.INFO, f"Control present: {cid}"
        elif ans in ("no", "n", "false"):
            status, s, title = Status.VULNERABLE, sev, f"Missing control: {question}"
        else:
            status, s, title = Status.INCONCLUSIVE, Severity.LOW, f"Unverified control: {question}"
        f = Finding(probe_name="architecture-review", owasp_id=owasp, title=title,
                    category="Architecture / Defense-in-Depth", status=status,
                    severity=s, confidence=0.9, dimension="informational",
                    prompt=f"(assessed) {cid}", response_excerpt=f"answer: {ans}",
                    # ADR 0010 follow-up: the control id is this finding's subject, carried
                    # contractually rather than only by convention in `prompt`.
                    source_rule_id=cid)
        if status is not Status.PASSED:
            f.remediation = [fix]
        findings.append(f)
    return findings


def summary(findings: list[Finding]) -> dict:
    arch = [f for f in findings if f.probe_name == "architecture-review"]
    missing = sum(1 for f in arch if f.status is Status.VULNERABLE)
    unknown = sum(1 for f in arch if f.status is Status.INCONCLUSIVE)
    present = sum(1 for f in arch if f.status is Status.PASSED)
    return {"controls_total": len(arch), "present": present,
            "missing": missing, "unverified": unknown}
