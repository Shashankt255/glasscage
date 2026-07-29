# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""AAKG typed nodes, edges, and states (GLASSCAGE Stage E1).

Status: Implemented.

Strongly-typed vocabulary for the AI Attack Knowledge Graph. Node and edge ids are
deterministic functions of their type + key so the same inputs always build the same
graph (reproducibility requirement). Every node and edge carries metadata, a
timestamp, confidence, evidence references, and source provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    FINDING = "Finding"
    EVIDENCE = "Evidence"
    ASSET = "Asset"
    COMPONENT = "Component"
    USER = "User"
    LLM = "LLM"
    PLANNER = "Planner"
    MEMORY = "Memory"
    RETRIEVER = "Retriever"
    MCP = "MCP"
    TOOL = "Tool"
    API = "API"
    DATABASE = "Database"
    FILESYSTEM = "Filesystem"
    SECRETS = "Secrets"
    TRUST_ZONE = "TrustZone"
    MITIGATION = "Mitigation"
    OWASP = "OWASP"
    ATLAS = "ATLAS"
    CAPEC = "CAPEC"
    CWE = "CWE"
    NIST = "NIST"
    CAPABILITY_TIER = "CapabilityTier"


class EdgeType(str, Enum):
    ENABLES = "enables"
    REQUIRES = "requires"
    INVOKES = "invokes"
    ACCESSES = "accesses"
    CROSSES = "crosses"
    TRUSTS = "trusts"
    MITIGATES = "mitigates"
    MAPPED_TO = "mapped_to"
    VERIFIED_BY = "verified_by"
    HYPOTHESIZED_BY = "hypothesized_by"
    OBSERVED_ON = "observed_on"
    AFFECTS = "affects"


class EdgeState(str, Enum):
    """Epistemic status of a relationship (E2 requirement)."""
    DEMONSTRATED = "demonstrated"      # backed by a real observed finding/impact
    HYPOTHESIZED = "hypothesized"      # architecturally reachable, not shown
    NOT_ASSESSABLE = "not_assessable"  # target tier too low to determine

    @property
    def rank(self) -> int:
        return {"demonstrated": 2, "hypothesized": 1, "not_assessable": 0}[self.value]


def node_id(ntype: NodeType, key: str) -> str:
    return f"{ntype.value}:{key}"


def edge_id(src: str, etype: EdgeType, dst: str) -> str:
    return f"{src}-[{etype.value}]->{dst}"


@dataclass
class Node:
    """A typed vertex. `id` is deterministic; equality/hash by id."""
    id: str
    ntype: NodeType
    label: str = ""
    metadata: dict = field(default_factory=dict)
    timestamp: str = ""
    confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)
    provenance: str = ""

    def to_dict(self) -> dict:
        d = {"id": self.id, "ntype": self.ntype.value, "label": self.label,
             "metadata": self.metadata, "timestamp": self.timestamp,
             "confidence": self.confidence, "evidence_refs": self.evidence_refs,
             "provenance": self.provenance}
        return d


@dataclass
class Edge:
    """A typed, directed, stateful relationship. Equality/hash by id."""
    id: str
    src: str
    dst: str
    etype: EdgeType
    state: EdgeState = EdgeState.HYPOTHESIZED
    metadata: dict = field(default_factory=dict)
    timestamp: str = ""
    confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)
    provenance: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "src": self.src, "dst": self.dst,
                "etype": self.etype.value, "state": self.state.value,
                "metadata": self.metadata, "timestamp": self.timestamp,
                "confidence": self.confidence, "evidence_refs": self.evidence_refs,
                "provenance": self.provenance}
