# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""System prompt static analysis — finds injection surface, embedded secrets,
and missing safety controls in a target's system prompt.

This is a config-review assessment: the user supplies the system prompt text and
GLASSCAGE analyzes it for common weaknesses. No target is contacted. Findings are
labelled as configuration review, not runtime measurements.
"""

from __future__ import annotations

import re

from .models import Finding, Severity, Status

_PROBE_NAME = "system-prompt-review"
_CATEGORY = "System Prompt Review"

_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (r"glpat-[a-zA-Z0-9\-_]{20,}", "GitLab personal access token"),
    (r"xox[bpsa]-[a-zA-Z0-9\-]{10,}", "Slack token"),
    (r"ya29\.[a-zA-Z0-9_\-]{50,}", "Google OAuth token"),
    (r"AIza[a-zA-Z0-9_\-]{35}", "Google API key"),
    (r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer token"),
    (r"(?i)password\s*[=:]\s*\S{4,}", "hardcoded password"),
    (r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?\S{8,}", "API key assignment"),
    (r"(?:mongodb|postgres|mysql|redis)://\S+:\S+@", "database connection string"),
]

_OVERPERMISSIVE_PATTERNS = [
    r"(?i)you\s+have\s+access\s+to\s+all",
    r"(?i)you\s+can\s+execute\s+any",
    r"(?i)use\s+whatever\s+tools",
    r"(?i)no\s+restrictions?\s+on\s+(?:tool|function|action)",
    r"(?i)you\s+(?:may|can|are\s+allowed\s+to)\s+(?:do\s+)?anything",
    r"(?i)unrestricted\s+access",
    r"(?i)full\s+access\s+to\s+(?:all|every|the\s+entire)",
]

_REFUSAL_MARKERS = [
    r"(?i)\bdo\s+not\b",
    r"(?i)\bnever\b",
    r"(?i)\brefuse\b",
    r"(?i)\bdecline\b",
    r"(?i)\byou\s+must\s+not\b",
    r"(?i)\byou\s+should\s+not\b",
    r"(?i)\bdo\s+not\s+(?:reveal|share|disclose|output|generate)\b",
    r"(?i)\bprohibited\b",
    r"(?i)\bforbidden\b",
    r"(?i)\bnot\s+allowed\b",
]

_OUTPUT_CONSTRAINT_MARKERS = [
    r"(?i)respond\s+(?:only\s+)?(?:with|in|using)",
    r"(?i)output\s+(?:must|should)\s+be",
    r"(?i)format\s+(?:your\s+)?(?:response|output|answer)",
    r"(?i)return\s+(?:only|just)",
    r"(?i)reply\s+(?:only\s+)?(?:with|in)",
    r"(?i)(?:JSON|markdown|XML|HTML)\s+(?:only|format)",
    r"(?i)structured\s+(?:output|response|format)",
]

_PII_PATTERNS = [
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "email address"),
    (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "possible SSN"),
    (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "possible credit card number"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone number"),
    (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "internal IP address"),
    (r"https?://[a-zA-Z0-9\-]+\.internal\b", "internal URL"),
    (r"(?:/(?:home|Users|etc|var|opt)/[a-zA-Z0-9_/\-\.]+)", "filesystem path"),
]

_INPUT_MARKER_PATTERNS = [
    r"\{\{(?:input|prompt|user|message|query)\}\}",
    r"(?i)^(?:User|Human|Customer|Client)\s*:",
    r"\{user_(?:input|message|query)\}",
    r"<user_input>",
    r"\[USER\s*INPUT\]",
]

_STRUCTURAL_DELIMITERS = [
    r"<\|(?:im_start|im_end|system|user|assistant)\|>",
    r"```(?:system|user|assistant)",
    r"---+\s*(?:system|user|instructions)",
    r"#{2,}\s+(?:System|Instructions|User)",
    r"<(?:system|instructions|context)>",
]


def _check_embedded_secrets(text: str) -> tuple[Status, str, list[str]]:
    found = []
    for pattern, label in _SECRET_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            redacted = matches[0][:8] + "..." if len(matches[0]) > 8 else matches[0]
            found.append(f"{label} ({redacted})")
    if found:
        return (Status.VULNERABLE,
                f"System prompt contains embedded secrets: {'; '.join(found)}",
                found)
    return Status.PASSED, "No embedded secrets detected", []


def _check_delimiter_weakness(text: str) -> tuple[Status, str]:
    has_input_markers = any(re.search(p, text, re.MULTILINE) for p in _INPUT_MARKER_PATTERNS)
    has_structural = any(re.search(p, text) for p in _STRUCTURAL_DELIMITERS)
    if has_input_markers and not has_structural:
        return (Status.VULNERABLE,
                "System prompt references user input without structural delimiters; "
                "injection payloads may blend into system instructions")
    if not has_input_markers:
        return Status.PASSED, "No inline user-input markers found"
    return Status.PASSED, "User-input sections use structural delimiters"


def _check_overpermissive_grants(text: str) -> tuple[Status, str]:
    for pattern in _OVERPERMISSIVE_PATTERNS:
        m = re.search(pattern, text)
        if m:
            return (Status.VULNERABLE,
                    f"Over-permissive tool grant detected: \"{m.group(0).strip()}\"")
    return Status.PASSED, "No over-permissive tool grants detected"


def _check_missing_refusal(text: str) -> tuple[Status, str]:
    for pattern in _REFUSAL_MARKERS:
        if re.search(pattern, text):
            return Status.PASSED, "Refusal/safety instructions present"
    return (Status.VULNERABLE,
            "System prompt contains no explicit refusal or safety instructions; "
            "the model may comply with harmful requests without guardrails")


def _check_role_confusion(text: str) -> tuple[Status, str]:
    persona_match = re.search(r"(?i)you\s+are\s+(?:a|an|the)\s+(\w[\w\s]{2,30})", text)
    if not persona_match:
        return Status.PASSED, "No strong persona definition detected"
    has_safety = any(re.search(p, text) for p in _REFUSAL_MARKERS)
    if has_safety:
        return Status.PASSED, "Persona defined with safety bounds"
    persona = persona_match.group(1).strip()
    return (Status.VULNERABLE,
            f"Strong persona \"{persona}\" defined without safety bounds; "
            "susceptible to jailbreak-persona attacks that override the role")


def _check_sensitive_data(text: str) -> tuple[Status, str, list[str]]:
    found = []
    for pattern, label in _PII_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            found.append(f"{label} ({len(matches)} instance(s))")
    if found:
        return (Status.VULNERABLE,
                f"Sensitive data in system prompt: {'; '.join(found)}",
                found)
    return Status.PASSED, "No sensitive data patterns detected", []


def _check_prompt_length(text: str) -> tuple[Status, str]:
    length = len(text)
    if length > 8000:
        return (Status.VULNERABLE,
                f"System prompt is very long ({length} chars); large prompts increase "
                "the injection surface and make boundary confusion more likely")
    if length > 4000:
        return (Status.INCONCLUSIVE,
                f"System prompt is moderately long ({length} chars); consider whether "
                "all content needs to be in the system prompt")
    return Status.PASSED, f"System prompt length ({length} chars) is within normal range"


def _check_output_constraints(text: str) -> tuple[Status, str]:
    for pattern in _OUTPUT_CONSTRAINT_MARKERS:
        if re.search(pattern, text):
            return Status.PASSED, "Output format constraints present"
    return (Status.INCONCLUSIVE,
            "System prompt has no explicit output format constraints; unconstrained "
            "output increases the surface for XSS and injection into downstream consumers")


# check_id -> (owasp_id, severity, check_fn, remediation)
CHECKS = {
    "embedded_secrets": (
        "LLM02", Severity.CRITICAL, _check_embedded_secrets,
        "Remove all secrets, API keys, and tokens from the system prompt; "
        "fetch them server-side at call time, never expose to the model."),
    "delimiter_weakness": (
        "LLM01", Severity.HIGH, _check_delimiter_weakness,
        "Use structural delimiters (XML tags, chat-ML markers) to separate system "
        "instructions from user input; never rely on plain-text markers alone."),
    "overpermissive_grants": (
        "LLM06", Severity.HIGH, _check_overpermissive_grants,
        "Scope tool grants to specific named tools with minimum required permissions; "
        "never grant blanket access to all tools or functions."),
    "missing_refusal": (
        "LLM01", Severity.MEDIUM, _check_missing_refusal,
        "Add explicit refusal instructions for harmful, illegal, or out-of-scope "
        "requests; specify what the model should decline and how."),
    "role_confusion": (
        "LLM01", Severity.MEDIUM, _check_role_confusion,
        "When defining a persona, include explicit safety boundaries that persist "
        "regardless of how users address the model."),
    "sensitive_data": (
        "LLM02", Severity.HIGH, _check_sensitive_data,
        "Remove PII, internal URLs, and filesystem paths from the system prompt; "
        "these can be extracted via prompt-leak attacks."),
    "prompt_length": (
        "LLM01", Severity.LOW, _check_prompt_length,
        "Reduce system prompt length; move static reference data to retrieval or "
        "tool calls rather than embedding it in the prompt."),
    "output_constraints": (
        "LLM05", Severity.LOW, _check_output_constraints,
        "Add explicit output format constraints (e.g., 'respond only in JSON') "
        "to reduce the surface for downstream injection."),
}


def analyze(prompt_text: str) -> list[Finding]:
    """Run all static checks against a system prompt. Returns findings."""
    if not prompt_text or not prompt_text.strip():
        return []
    findings: list[Finding] = []
    for check_id, (owasp, severity, check_fn, remedy) in CHECKS.items():
        result = check_fn(prompt_text)
        if len(result) == 3:
            status, detail, _extras = result
        else:
            status, detail = result
        if status is Status.PASSED:
            title = f"System prompt check passed: {check_id}"
            sev = Severity.INFO
        elif status is Status.INCONCLUSIVE:
            title = detail
            sev = Severity.LOW
        else:
            title = detail
            sev = severity
        f = Finding(
            probe_name=_PROBE_NAME,
            owasp_id=owasp,
            title=title,
            category=_CATEGORY,
            status=status,
            severity=sev,
            confidence=0.85,
            dimension="informational",
            prompt=f"(config-review) {check_id}",
            response_excerpt=detail,
            source_rule_id=check_id,
        )
        if status is not Status.PASSED:
            f.remediation = [remedy]
        findings.append(f)
    return findings


def summary(findings: list[Finding]) -> dict:
    """Summary stats for the system prompt review."""
    sp = [f for f in findings if f.probe_name == _PROBE_NAME]
    vulnerable = sum(1 for f in sp if f.status is Status.VULNERABLE)
    inconclusive = sum(1 for f in sp if f.status is Status.INCONCLUSIVE)
    passed = sum(1 for f in sp if f.status is Status.PASSED)
    return {"checks_total": len(sp), "passed": passed,
            "vulnerable": vulnerable, "inconclusive": inconclusive}
