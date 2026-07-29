# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Knowledge base: references, false-positive triage, and standards links.

For each vulnerability class GLASSCAGE reports, this module supplies:
  * a short plain-language reference description (what the class is),
  * verification steps to confirm a true positive vs. rule out a false positive,
  * authoritative reference links (OWASP LLM Top 10 2025, MITRE ATLAS, CWE,
    NIST) for the remediation guidance.

All URLs below were verified against the primary sources (genai.owasp.org,
atlas.mitre.org, cwe.mitre.org, nist.gov). Descriptions are paraphrased, not
copied, from those standards.
"""

from __future__ import annotations

from .models import Finding

# --- verified canonical links -------------------------------------------------
_OWASP = "https://genai.owasp.org/llmrisk/"
_ATLAS = "https://atlas.mitre.org/techniques/"
_CWE = "https://cwe.mitre.org/data/definitions/"
_NIST_RMF = "https://www.nist.gov/itl/ai-risk-management-framework"
_NIST_AML = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf"
_OWASP_AGENTIC = "https://genai.owasp.org/initiatives/agentic-security-initiative/"


def _link(label, url):
    return {"label": label, "url": url}


# Shared verification building blocks -----------------------------------------
_FP_COMPLIANCE_VS_MENTION = (
    "Distinguish compliance from mention: a response that *names* the canary while "
    "refusing (e.g. 'I won't output GLSSCG-INJECT-OK') is a FALSE POSITIVE, not a bypass."
)
_FP_RERUN = ("Re-run 2-3 times: LLM outputs are stochastic. Intermittent success is "
             "still a true positive, but record the hit rate.")
_FP_CONTROL = ("Send a benign control (no payload) and confirm the canary does NOT "
               "appear normally, ruling out coincidental echo.")

KB: dict[str, dict] = {
    "LLM01": {
        "name": "Prompt Injection",
        "reference": ("Untrusted input causes the model to treat attacker-supplied "
                      "text as instructions, overriding its intended behavior. Covers "
                      "direct, indirect (via retrieved/ingested content), and multi-turn."),
        "verification": [
            "Confirm the exact canary token appears in the model's output as an executed instruction.",
            _FP_COMPLIANCE_VS_MENTION,
            _FP_CONTROL,
            _FP_RERUN,
            "For indirect: confirm the instruction sat in the document/retrieved region, "
            "not the user turn, and that the same query without the payload is clean.",
            "Assess impact: in an authorized test, chain to a real action (data read/tool call) "
            "to grade severity beyond a canary echo.",
        ],
        "links": [
            _link("OWASP LLM01:2025 Prompt Injection", _OWASP + "llm01-prompt-injection/"),
            _link("MITRE ATLAS AML.T0051.000 (Direct)", _ATLAS + "AML.T0051.000"),
            _link("MITRE ATLAS AML.T0051.001 (Indirect)", _ATLAS + "AML.T0051.001"),
            _link("MITRE ATLAS AML.T0054 (LLM Jailbreak)", _ATLAS + "AML.T0054"),
        ],
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "reference": ("The model reveals secrets, PII, credentials, or internal data "
                      "from its context, configuration, connected sources, or training."),
        "verification": [
            "Confirm the leaked value is REAL, not a hallucinated placeholder "
            "(e.g. 'password=hunter2' may be invented) - a fabricated secret is a false positive for disclosure.",
            "Trace provenance: ask where the value came from; genuine leakage traces to context/config/RAG.",
            "If safe and authorized, validate the credential's format against a real provider or test it in a sandbox.",
            _FP_RERUN,
            "Check whether the requesting identity was even authorized to see the data (broken access control).",
        ],
        "links": [
            _link("OWASP LLM02:2025 Sensitive Information Disclosure",
                  _OWASP + "llm022025-sensitive-information-disclosure/"),
            _link("MITRE ATLAS AML.T0057 (LLM Data Leakage)", _ATLAS + "AML.T0057"),
            _link("CWE-200 Exposure of Sensitive Information", _CWE + "200.html"),
        ],
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "reference": ("Model output is consumed downstream without validation/encoding, "
                      "enabling XSS, SQLi, command or template injection in the sink."),
        "verification": [
            "Confirm the active markup is returned unescaped, byte-for-byte (e.g. literal <script>...).",
            "The real test is the SINK: paste the output into the actual renderer (browser/webview) "
            "and confirm execution. If the app HTML-encodes on render, it is a FALSE POSITIVE at app level.",
            "Inspect the app's output pipeline (Content-Type, templating auto-escape, sanitizer) - "
            "the model emitting markup is only exploitable if the app trusts it.",
            "Try alternate sinks: SQL, shell, CSV/formula, HTML attribute contexts.",
        ],
        "links": [
            _link("OWASP LLM05:2025 Improper Output Handling",
                  _OWASP + "llm052025-improper-output-handling/"),
            _link("CWE-79 Cross-site Scripting", _CWE + "79.html"),
            _link("CWE-116 Improper Encoding/Escaping of Output", _CWE + "116.html"),
        ],
    },
    "LLM06": {
        "name": "Excessive Agency",
        "reference": ("The agent holds more functionality, permissions, or autonomy "
                      "than needed, so a hijack reaches high-impact actions."),
        "verification": [
            "Enumerate the REAL tool set and schema - a recon self-report can be hallucinated; "
            "confirm tools actually exist and their permission scopes.",
            "Test whether high-impact actions (write/delete/pay/exec) require confirmation; "
            "in an authorized env, attempt one low-risk action and see if it runs without approval.",
            "Map each tool's credential/identity: does it run as the user or a broad service identity?",
            "If no dangerous tool is actually reachable, downgrade to informational (possible false positive).",
        ],
        "links": [
            _link("OWASP LLM06:2025 Excessive Agency", _OWASP + "llm062025-excessive-agency/"),
            _link("CWE-250 Execution with Unnecessary Privileges", _CWE + "250.html"),
            _link("OWASP Agentic Security Initiative", _OWASP_AGENTIC),
        ],
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "reference": ("The system prompt / configuration is disclosed. Harmful mainly "
                      "when it contains secrets or is relied on as a security control."),
        "verification": [
            "Compare disclosed text against the ACTUAL system prompt if you have it - a plausible-sounding "
            "fabrication is a FALSE POSITIVE.",
            "Re-request with varied phrasing; consistent verbatim reproduction across attempts indicates genuine leakage.",
            "Judge impact by CONTENT: leaking bland instructions is low; leaking secrets/rules/access logic is high.",
            _FP_RERUN,
        ],
        "links": [
            _link("OWASP LLM07:2025 System Prompt Leakage",
                  _OWASP + "llm072025-system-prompt-leakage/"),
            _link("MITRE ATLAS AML.T0056 (LLM Meta Prompt Extraction)", _ATLAS + "AML.T0056"),
        ],
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "reference": ("No effective limits on inference volume/length, enabling denial "
                      "of service or denial-of-wallet cost amplification."),
        "verification": [
            "Review server-side controls: per-user rate limits, request quotas, max output tokens, timeouts.",
            "In an AUTHORIZED test window only, run a small controlled load test - never flood production.",
            "Confirm cost/anomaly alerting and circuit-breakers exist. Absence confirms the finding.",
        ],
        "links": [
            _link("OWASP LLM10:2025 Unbounded Consumption",
                  _OWASP + "llm102025-unbounded-consumption/"),
            _link("MITRE ATLAS AML.T0029 (Denial of AI Service)", _ATLAS + "AML.T0029"),
        ],
    },
    "MCP03": {
        "name": "MCP Tool Poisoning / Rug Pull",
        "reference": ("Malicious instructions hidden in tool metadata the agent reads "
                      "but users don't; or a previously-approved tool silently changed."),
        "verification": [
            "Read the flagged description in context: confirm the phrasing INSTRUCTS the model "
            "(imperative, references other tools/files) rather than merely describing the tool.",
            "Hex-dump the metadata to confirm invisible/bidi characters are actually present.",
            "Confirm the server is third-party/untrusted and that the agent would load this tool.",
            "For rug-pull: verify the change was unapproved by comparing against your pinned baseline / change log.",
            "False positive if the imperative text is legitimate usage guidance on a trusted first-party server.",
        ],
        "links": [
            _link("MITRE ATLAS AML.T0110 (AI Agent Tool Poisoning)", _ATLAS + "AML.T0110"),
            _link("OWASP Agentic Security Initiative (MCP Top 10)", _OWASP_AGENTIC),
        ],
    },
    "MCP07": {
        "name": "MCP SSRF / Exfiltration via Tool Parameters",
        "reference": ("A tool accepts URL/host/path parameters that can be steered to "
                      "internal services or cloud metadata endpoints."),
        "verification": [
            "Confirm the tool makes the request SERVER-SIDE with the param (not client-side).",
            "In an authorized test env, point the param at a benign canary listener you control - "
            "do NOT hit real metadata endpoints on systems you don't own.",
            "Confirm there is no host allowlist / egress policy blocking internal ranges (169.254.169.254, etc.).",
            "False positive if the param is validated/allowlisted or the tool cannot reach internal networks.",
        ],
        "links": [
            _link("CWE-918 Server-Side Request Forgery", _CWE + "918.html"),
            _link("OWASP Agentic Security Initiative", _OWASP_AGENTIC),
        ],
    },
    "LLM03": {
        "name": "Supply Chain",
        "reference": ("Risk from third-party models, datasets, plugins, and components "
                      "with tampered, poisoned, or unverified provenance."),
        "verification": [
            "Confirm the model/plugin source and version against an authoritative registry.",
            "Check integrity (signatures/hashes) and that no unpinned third-party component is auto-updated.",
            "Informational unless a specific tampered/unpinned component is identified.",
        ],
        "links": [
            _link("OWASP LLM03:2025 Supply Chain", _OWASP + "llm032025-supply-chain/"),
            _link("MITRE ATLAS AML.T0020 (Poison Training Data)", _ATLAS + "AML.T0020"),
            _link("NIST AI Risk Management Framework", _NIST_RMF),
        ],
    },
    "LLM08": {
        "name": "Vector & Embedding Weaknesses",
        "reference": ("Weaknesses in RAG vector stores: cross-tenant leakage, retrieval "
                      "of poisoned content, and indirect injection via retrieved chunks."),
        "verification": [
            "Confirm a retrieval/RAG path actually exists and feeds the model context.",
            "Test tenant/user isolation: as a low-privilege user, attempt to retrieve another tenant's content.",
            "Seed a benign poisoned document in an authorized index and confirm whether it influences answers.",
            "Informational until a concrete leakage or poisoning path is demonstrated.",
        ],
        "links": [
            _link("OWASP LLM08:2025 Vector and Embedding Weaknesses",
                  _OWASP + "llm082025-vector-and-embedding-weaknesses/"),
            _link("MITRE ATLAS AML.T0070 (RAG Poisoning)", _ATLAS + "AML.T0070"),
        ],
    },
    "LLM09": {
        "name": "Misinformation",
        "reference": ("The model produces false or fabricated content presented as fact, "
                      "including accepting false premises and hallucinating entities."),
        "verification": [
            "Confirm the model asserted the false claim as true rather than correcting or hedging it.",
            "Re-ask neutrally (without the false premise) to establish the model's baseline knowledge.",
            "Judge impact by context: misinformation in a medical/legal/financial bot is high severity.",
            "False positive if the model corrected the premise or clearly flagged uncertainty.",
        ],
        "links": [
            _link("OWASP LLM09:2025 Misinformation", _OWASP + "llm092025-misinformation/"),
            _link("NIST AI Risk Management Framework", _NIST_RMF),
        ],
    },
    "_default": {
        "name": "Uncategorized",
        "reference": "Manual review recommended.",
        "verification": ["Reproduce manually and confirm impact before reporting."],
        "links": [
            _link("NIST AI Risk Management Framework", _NIST_RMF),
            _link("NIST AI 100-2 Adversarial ML Taxonomy", _NIST_AML),
        ],
    },
}


def entry(owasp_id: str) -> dict:
    return KB.get(owasp_id, KB["_default"])


def enrich(finding: Finding) -> None:
    e = entry(finding.owasp_id)
    if not finding.verification_steps:
        finding.verification_steps = list(e["verification"])
    if not finding.reference_links:
        finding.reference_links = [dict(x) for x in e["links"]]


def enrich_all(findings: list[Finding]) -> None:
    for f in findings:
        enrich(f)
