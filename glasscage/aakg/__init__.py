# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""AI Attack Knowledge Graph (AAKG) - GLASSCAGE Stage E.

The single graph substrate that the attack-path (E2), trust-boundary (E3), and
blast-radius (E4) engines read from. E1 graph engine is Implemented; downstream
subsystem migration continues in later stages.
"""

from . import blast, build, narrative, paths, story, trust_graph, views
from .engine import PropertyGraph
from .types import Edge, EdgeState, EdgeType, Node, NodeType, edge_id, node_id

__all__ = [
           "Edge",
           "EdgeState",
           "EdgeType",
           "Node",
           "NodeType",
           "PropertyGraph",
           "blast",
           "build",
           "edge_id",
           "narrative",
           "node_id",
           "paths",
           "story",
           "trust_graph",
           "views",
]
