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

from .models import Finding, ReconResult, Severity, Status
from .target import HTTPChatTarget, ChatResponse
from .engine import Engine
from . import targets
from .targets import (
    ApplicationTarget, Surface, SurfaceKind, Driver, Observation, ChatSurface,
)
from . import mcp, graph, diff, plugins, judge, kb, evidence, repro, cvss, coverage, mutation, schema, audit, architecture, chain, posture, trust, genetic, sarif, agent_probes, tal, stats, refagent, benchmark, orchestrator, adapters, taxonomy, validation

__all__ = [
    "Finding", "ReconResult", "Severity", "Status",
    "HTTPChatTarget", "ChatResponse", "Engine",
    "mcp", "graph", "diff", "plugins", "judge", "kb", "evidence", "repro", "cvss", "coverage", "mutation", "schema", "audit", "architecture", "chain", "posture", "trust", "genetic", "sarif", "agent_probes", "tal", "stats", "refagent", "benchmark", "orchestrator", "adapters", "taxonomy", "validation", "aakg", "errors", "logging_setup", "config", "redaction", "evidence_confidence", "adapter_validation",
    "targets", "ApplicationTarget", "Surface", "SurfaceKind", "Driver", "Observation", "ChatSurface",
]
