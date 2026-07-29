# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Core data models for GLASSCAGE."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Status(str, Enum):
    VULNERABLE = "vulnerable"      # probe confirmed a weakness
    PASSED = "passed"              # target resisted the probe
    INCONCLUSIVE = "inconclusive" # could not determine (manual review needed)
    NOT_ASSESSABLE = "not_assessable"  # target tier too low to test this honestly
    ERROR = "error"               # probe failed to execute


class Dimension(str, Enum):
    """What a finding actually demonstrates.

    STEERABILITY: the model can be pushed off-policy (e.g. emits a canary). This
      is a capability signal, NOT proof an attacker can cause harm.
    IMPACT: a real, consented consequence was demonstrated (data returned, a
      sandboxed tool actually fired). Only these justify high/critical severity.
    INFORMATIONAL: review item / configuration observation.
    """
    STEERABILITY = "steerability"
    IMPACT = "impact"
    INFORMATIONAL = "informational"


@dataclass
class ReconResult:
    """What we learned about the target before attacking it."""

    reachable: bool = False
    model_hints: list[str] = field(default_factory=list)
    guardrail_signals: list[str] = field(default_factory=list)
    tool_surface: list[str] = field(default_factory=list)   # self-reported tool names
    schema_tools: list[dict] = field(default_factory=list)  # schema-confirmed {name,capability,provenance,side_effect}
    refusal_style: str | None = None                        # how the bot declines
    latency_ms: float | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single result from a probe."""

    probe_name: str
    title: str
    owasp_id: str                 # e.g. "LLM01" or "MCP03"
    category: str                 # human-readable category
    status: Status
    severity: Severity
    confidence: float = 0.5       # 0..1 heuristic confidence
    prompt: str = ""              # what we sent (evidence)
    response_excerpt: str = ""    # what came back (evidence, truncated)
    atlas_id: str = ""            # MITRE ATLAS technique id, when applicable
    cwe_id: str = ""              # CWE id (e.g. CWE-1427)
    capec_id: str = ""            # CAPEC id or "N/A"
    nist_id: str = ""             # NIST AI 100-2 / AML class ref
    source_framework: str = "glasscage"   # D1: which tool produced this
    source_rule_id: str = ""      # D1: original rule/probe id in that framework
    raw_output: str = ""          # D1: raw native output for provenance
    dimension: str = "informational"   # steerability | impact | informational
    impact_confirmed: bool = False     # a real consented consequence was shown
    cvss_vector: str = ""              # transparent severity vector (see scoring)
    cvss_score: float = 0.0
    remediation: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)  # false-positive triage
    reproduction_steps: list[str] = field(default_factory=list)  # manual re-validation
    reference_links: list[dict] = field(default_factory=list)    # {label, url} standards
    references: list[str] = field(default_factory=list)
    evidence_path: str = ""       # saved screenshot/evidence file (relative)
    evidence_svg: str = ""        # inline evidence card (dropped from JSON)
    raw_request: str = ""         # chain of custody: exact bytes sent
    raw_response: str = ""        # chain of custody: exact bytes received
    evidence_hash: str = ""       # sha256 of raw_request+raw_response
    timestamp: str = ""           # ISO8601 capture time
    # Stage A: capability tier this finding was assessed at
    assessed_tier: str = "L0"
    required_tier: str = "L0"
    # Stage B: statistical aggregation over repeated trials
    trials_run: int = 1
    success_rate: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    reproducibility: float | None = None
    status_distribution: dict = field(default_factory=dict)
    # Stage D: external framework provenance + extended taxonomy
    source_framework: str = "glasscage-native"
    source_rule_id: str = ""
    cwe_id: str = ""
    capec_id: str = ""
    nist_id: str = ""
    raw_output: str = ""
    turns: list[dict] = field(default_factory=list)  # multi-turn evidence trail
    # ADR 0004: id of the Surface this finding was observed on. Empty unless the run was
    # surface-driven. Configuration-review (MCP manifest) and questionnaire
    # (architecture) findings are never attributed to a surface - they are not
    # observations on one.
    surface_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d
