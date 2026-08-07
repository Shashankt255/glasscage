# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""MCP security module.

Analyzes a Model Context Protocol server's tool manifest (the JSON you get from a
`tools/list` call) for the dominant 2026 agentic attack classes:

  * Tool poisoning  - hidden imperative instructions inside tool descriptions that
                      the agent reads but the user never sees.
  * Rug pull        - a previously-approved tool whose description/schema silently
                      changed (diff against a pinned baseline snapshot).
  * SSRF / secret   - tools that accept URLs or file paths reaching internal
    exfil surface     metadata endpoints or credential stores.

This is static analysis of a manifest you provide. It does not connect to or
execute any server.

References: OWASP MCP Top 10 (beta), OWASP Agentic Top 10 (ASI0x), NSA MCP
hardening guidance.
"""

from __future__ import annotations

import hashlib
import json
import re

from .models import Finding, Severity, Status

# Imperative phrasing aimed at the *model* rather than describing the tool.
_POISON_PATTERNS = [
    r"\bignore\b.{0,30}\b(previous|prior|above|instructions)\b",
    r"\bdo not (tell|inform|mention|reveal).{0,20}\b(user|the user)\b",
    r"\bbefore (using|calling|invoking)\b.{0,40}\btool\b",
    r"\b(read|open|cat)\b.{0,30}\b(file|/etc/|\.env|id_rsa|secret)\b",
    r"\b(send|post|exfiltrate|forward|upload)\b.{0,30}\b(to|http|https)\b",
    r"\bas an ai\b|\byou must\b|\byou should always\b",
    r"<important>|<system>|\[system\]",
]

# SSRF-prone internal targets an attacker steers a URL/path param toward.
_SSRF_TARGETS = [
    "169.254.169.254",            # cloud instance metadata
    "metadata.google.internal",
    "localhost", "127.0.0.1", "0.0.0.0",
    "file://", "/proc/", "/etc/",
]

_URLISH_PARAM = re.compile(r"(url|uri|endpoint|host|path|file|src|target|callback)",
                           re.IGNORECASE)

# Zero-width / bidi characters used to hide instructions from human reviewers.
_INVISIBLE = re.compile(r"[\u200b\u200c\u200d\u2060\u202a-\u202e\ufeff]")


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _finding(status, title, severity, owasp_id, tool, evidence, conf) -> Finding:
    return Finding(
        probe_name="mcp-analyzer",
        title=title,
        owasp_id=owasp_id,
        category="MCP / Agentic",
        status=status,
        severity=severity,
        confidence=conf,
        prompt=f"tool: {tool}",
        # ADR 0010 follow-up: the tool name is this finding's subject, carried
        # contractually rather than only by convention in `prompt`.
        source_rule_id=str(tool),
        response_excerpt=evidence[:400],
        atlas_id="AML.T0110" if owasp_id == "MCP03" else "",
        references=["OWASP Agentic Security Initiative"],
    )


def _iter_tools(manifest: dict):
    tools = manifest.get("tools", manifest if isinstance(manifest, list) else [])
    for t in tools:
        name = t.get("name", "<unnamed>")
        desc = t.get("description", "") or ""
        schema = json.dumps(t.get("inputSchema", t.get("input_schema", {})))
        yield name, desc, schema


def analyze_manifest(manifest: dict) -> list[Finding]:
    findings: list[Finding] = []
    for name, desc, schema in _iter_tools(manifest):
        blob = f"{desc}\n{schema}"
        low = blob.lower()

        # 1. Tool poisoning: imperative instructions in metadata.
        hits = [p for p in _POISON_PATTERNS if re.search(p, low)]
        if hits:
            findings.append(_finding(
                Status.VULNERABLE,
                f"Tool '{name}' description contains model-directed instructions (poisoning)",
                Severity.CRITICAL, "MCP03", name, desc, min(0.6 + 0.1 * len(hits), 0.95)))

        # 2. Hidden/invisible characters concealing content from reviewers.
        if _INVISIBLE.search(blob):
            findings.append(_finding(
                Status.VULNERABLE,
                f"Tool '{name}' metadata contains invisible/bidi characters",
                Severity.HIGH, "MCP03", name, repr(desc[:120]), 0.8))

        # 3. SSRF / credential exfil surface.
        if _URLISH_PARAM.search(schema):
            ssrf = [t for t in _SSRF_TARGETS if t in low]
            sev = Severity.HIGH if ssrf else Severity.MEDIUM
            title = (f"Tool '{name}' takes a URL/path param"
                     + (f" referencing internal targets ({', '.join(ssrf)})" if ssrf
                        else "; validate against SSRF"))
            findings.append(_finding(
                Status.VULNERABLE if ssrf else Status.INCONCLUSIVE,
                title, sev, "MCP07", name, schema, 0.75 if ssrf else 0.45))

    if not findings:
        findings.append(_finding(
            Status.PASSED, "No poisoning, hidden-character, or SSRF indicators in manifest",
            Severity.INFO, "MCP00", "(manifest)", "", 0.5))
    return findings


def snapshot(manifest: dict) -> dict:
    """Pin tool descriptions/schemas for later rug-pull detection."""
    return {name: _hash(f"{desc}\n{schema}")
            for name, desc, schema in _iter_tools(manifest)}


def detect_rug_pull(baseline: dict, current: dict) -> list[Finding]:
    """Compare a pinned baseline snapshot to a current manifest."""
    cur = snapshot(current)
    findings: list[Finding] = []
    for name, h in cur.items():
        if name in baseline and baseline[name] != h:
            findings.append(_finding(
                Status.VULNERABLE,
                f"Tool '{name}' definition changed since approval (possible rug pull)",
                Severity.HIGH, "MCP03", name,
                f"baseline={baseline[name]} current={h}", 0.9))
    for name in cur:
        if name not in baseline:
            findings.append(_finding(
                Status.INCONCLUSIVE,
                f"New tool '{name}' appeared since baseline; requires re-approval",
                Severity.MEDIUM, "MCP03", name, "", 0.6))
    if not findings:
        findings.append(_finding(
            Status.PASSED, "No tool definitions changed since baseline",
            Severity.INFO, "MCP00", "(manifest)", "", 0.6))
    return findings
