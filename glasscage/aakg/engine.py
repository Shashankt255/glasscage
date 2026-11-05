# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Property-graph engine (GLASSCAGE Stage E1).

Status: Implemented.

A lightweight, dependency-free directed property graph. Design goals:
  * Determinism/reproducibility: every traversal iterates in sorted id order, so
    identical inputs yield identical node lists, edge lists, and path enumerations.
  * Idempotent construction: adding a node/edge with an existing id merges metadata
    and upgrades edge state monotonically (never silently downgrades a demonstrated
    edge to hypothesized).
  * Serialization: to_dict/from_dict for replay and for embedding in reports.

This is the single substrate the attack-path (E2), trust-boundary (E3), and
blast-radius (E4) engines read from.
"""

from __future__ import annotations

import json

from .types import Edge, EdgeState, EdgeType, Node, NodeType, edge_id, node_id


class PropertyGraph:
    """Directed property graph keyed by deterministic node/edge ids."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[str, Edge] = {}
        self._out: dict[str, set[str]] = {}
        self._in: dict[str, set[str]] = {}
        self._cache: dict = {}   # RC: memoize expensive read-only analyses

    def cached(self, key, compute):
        """Return a memoized analysis result; cache is cleared on any mutation.

        Safe because the graph is built once then read many times by the posture,
        coverage, remediation, and report engines.
        """
        if key not in self._cache:
            self._cache[key] = compute()
        return self._cache[key]

    # ---- construction ---------------------------------------------------- #
    def add_node(self, node: Node) -> Node:
        self._cache.clear()
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            self._out.setdefault(node.id, set())
            self._in.setdefault(node.id, set())
            return node
        # merge: keep first identity, union metadata/evidence, keep max confidence
        existing.metadata.update(node.metadata)
        for r in node.evidence_refs:
            if r not in existing.evidence_refs:
                existing.evidence_refs.append(r)
        if node.confidence is not None:
            existing.confidence = (node.confidence if existing.confidence is None
                                   else max(existing.confidence, node.confidence))
        if node.label and not existing.label:
            existing.label = node.label
        return existing

    def ensure(self, ntype: NodeType, key: str, label: str = "", **attrs) -> Node:
        return self.add_node(Node(id=node_id(ntype, key), ntype=ntype,
                                  label=label or key, **attrs))

    def add_edge(self, src: str, etype: EdgeType, dst: str,
                 state: EdgeState = EdgeState.HYPOTHESIZED, **attrs) -> Edge:
        self._cache.clear()
        assert src in self._nodes, f"unknown src node {src}"
        assert dst in self._nodes, f"unknown dst node {dst}"
        eid = edge_id(src, etype, dst)
        existing = self._edges.get(eid)
        if existing is None:
            edge = Edge(id=eid, src=src, dst=dst, etype=etype, state=state, **attrs)
            self._edges[eid] = edge
            self._out[src].add(eid)
            self._in[dst].add(eid)
            return edge
        # monotonic state upgrade + metadata/evidence merge
        if state.rank > existing.state.rank:
            existing.state = state
        existing.metadata.update(attrs.get("metadata", {}))
        for r in attrs.get("evidence_refs", []):
            if r not in existing.evidence_refs:
                existing.evidence_refs.append(r)
        return existing

    # ---- access (deterministic) ----------------------------------------- #
    def node(self, nid: str) -> Node | None:
        return self._nodes.get(nid)

    def has_node(self, nid: str) -> bool:
        return nid in self._nodes

    def nodes(self, ntype: NodeType | None = None):
        out = [n for n in self._nodes.values() if ntype is None or n.ntype is ntype]
        return sorted(out, key=lambda n: n.id)

    def edges(self, etype: EdgeType | None = None):
        out = [e for e in self._edges.values() if etype is None or e.etype is etype]
        return sorted(out, key=lambda e: e.id)

    def out_edges(self, nid: str, etype: EdgeType | None = None):
        eids = sorted(self._out.get(nid, ()))
        return [self._edges[e] for e in eids
                if etype is None or self._edges[e].etype is etype]

    def in_edges(self, nid: str, etype: EdgeType | None = None):
        eids = sorted(self._in.get(nid, ()))
        return [self._edges[e] for e in eids
                if etype is None or self._edges[e].etype is etype]

    def neighbors(self, nid: str, etype: EdgeType | None = None, direction: str = "out"):
        edges = self.out_edges(nid, etype) if direction == "out" else self.in_edges(nid, etype)
        return [self._nodes[e.dst if direction == "out" else e.src] for e in edges]

    def find(self, ntype: NodeType | None = None, predicate=None):
        return [n for n in self.nodes(ntype) if predicate is None or predicate(n)]

    # ---- traversal (deterministic) -------------------------------------- #
    def simple_paths(self, src: str, dst_ids, edge_types=None, max_depth: int = 6):
        """All simple (cycle-free) paths from src to any node in dst_ids.

        Returns a list of paths, each a list of Edge objects, sorted for
        determinism. edge_types optionally restricts which edge types may be
        traversed.
        """
        dst_set = set(dst_ids)
        allowed = set(edge_types) if edge_types else None
        results: list[list[Edge]] = []

        def dfs(current: str, visited: set[str], trail: list[Edge]):
            if len(trail) > max_depth:
                return
            if current in dst_set and trail:
                results.append(list(trail))
                # continue: a dst may also be intermediate to a further dst
            for e in self.out_edges(current):
                if allowed is not None and e.etype not in allowed:
                    continue
                if e.dst in visited:
                    continue
                visited.add(e.dst)
                trail.append(e)
                dfs(e.dst, visited, trail)
                trail.pop()
                visited.discard(e.dst)

        if src in self._nodes:
            dfs(src, {src}, [])
        # deterministic ordering: by (length, concatenated edge ids)
        results.sort(key=lambda p: (len(p), "|".join(e.id for e in p)))
        return results

    def reachable(self, src: str, edge_types=None, max_depth: int = 8) -> set[str]:
        """Set of node ids reachable from src along allowed edge types (BFS)."""
        allowed = set(edge_types) if edge_types else None
        seen = {src}
        frontier = [src]
        depth = 0
        while frontier and depth < max_depth:
            nxt = []
            for nid in frontier:
                for e in self.out_edges(nid):
                    if allowed is not None and e.etype not in allowed:
                        continue
                    if e.dst not in seen:
                        seen.add(e.dst)
                        nxt.append(e.dst)
            frontier = sorted(nxt)
            depth += 1
        seen.discard(src)
        return seen

    # ---- serialization --------------------------------------------------- #
    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes()],
                "edges": [e.to_dict() for e in self.edges()]}

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict) -> PropertyGraph:
        g = cls()
        for nd in data.get("nodes", []):
            g.add_node(Node(id=nd["id"], ntype=NodeType(nd["ntype"]),
                            label=nd.get("label", ""), metadata=nd.get("metadata", {}),
                            timestamp=nd.get("timestamp", ""),
                            confidence=nd.get("confidence"),
                            evidence_refs=nd.get("evidence_refs", []),
                            provenance=nd.get("provenance", "")))
        for ed in data.get("edges", []):
            g.add_edge(ed["src"], EdgeType(ed["etype"]), ed["dst"],
                       state=EdgeState(ed.get("state", "hypothesized")),
                       metadata=ed.get("metadata", {}), timestamp=ed.get("timestamp", ""),
                       confidence=ed.get("confidence"),
                       evidence_refs=ed.get("evidence_refs", []),
                       provenance=ed.get("provenance", ""))
        return g

    def stats(self) -> dict:
        from collections import Counter
        nt = Counter(n.ntype.value for n in self._nodes.values())
        et = Counter(e.etype.value for e in self._edges.values())
        st = Counter(e.state.value for e in self._edges.values())
        return {"nodes": len(self._nodes), "edges": len(self._edges),
                "by_node_type": dict(nt), "by_edge_type": dict(et),
                "by_edge_state": dict(st)}
