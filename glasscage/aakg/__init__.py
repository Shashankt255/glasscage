# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""AI Attack Knowledge Graph (AAKG) - GLASSCAGE Stage E.

The single graph substrate that the attack-path (E2), trust-boundary (E3), and
blast-radius (E4) engines read from. E1 graph engine is Implemented; downstream
subsystem migration continues in later stages.
"""

from .engine import PropertyGraph
from .types import Node, Edge, NodeType, EdgeType, EdgeState, node_id, edge_id
from . import build, paths, trust_graph, blast
from . import narrative, story, views

__all__ = ["PropertyGraph", "Node", "Edge", "NodeType", "EdgeType", "EdgeState",
           "node_id", "edge_id", "build", "paths", "trust_graph", "blast", "narrative", "story", "views"]
