# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""GLASSCAGE - AI attack-surface recon + remediation for chatbots and agents.

A defensive red-teaming framework for AUTHORIZED testing of AI systems you own
or have explicit written permission to assess. It fingerprints a target chatbot,
runs a battery of detection-oriented probes mapped to the OWASP Top 10 for LLM
Applications (plus MCP/agentic checks and a blast-radius graph), scores findings,
and generates a remediation-focused report.

Do NOT run this against systems you are not authorized to test.
"""

__version__ = "1.0.0rc3"

from . import (
    adapters,
    agent_probes,
    architecture,
    audit,
    benchmark,
    chain,
    coverage,
    cvss,
    diff,
    evidence,
    genetic,
    graph,
    judge,
    kb,
    mcp,
    mutation,
    orchestrator,
    plugins,
    posture,
    refagent,
    repro,
    sarif,
    schema,
    stats,
    tal,
    targets,
    taxonomy,
    trust,
    validation,
)
from .engine import Engine
from .models import Finding, ReconResult, Severity, Status
from .target import ChatResponse, HTTPChatTarget
from .targets import (
    ApplicationTarget,
    ChatSurface,
    Driver,
    Observation,
    Surface,
    SurfaceKind,
)

__all__ = [
    "ApplicationTarget",
    "ChatResponse",
    "ChatSurface",
    "Driver",
    "Engine",
    "Finding",
    "HTTPChatTarget",
    "Observation",
    "ReconResult",
    "Severity",
    "Status",
    "Surface",
    "SurfaceKind",
    "aakg",
    "adapter_validation",
    "adapters",
    "agent_probes",
    "architecture",
    "audit",
    "benchmark",
    "chain",
    "config",
    "coverage",
    "cvss",
    "diff",
    "errors",
    "evidence",
    "evidence_confidence",
    "genetic",
    "graph",
    "judge",
    "kb",
    "logging_setup",
    "mcp",
    "mutation",
    "orchestrator",
    "plugins",
    "posture",
    "redaction",
    "refagent",
    "repro",
    "sarif",
    "schema",
    "stats",
    "tal",
    "targets",
    "taxonomy",
    "trust",
    "validation",
]
