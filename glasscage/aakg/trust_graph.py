# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Trust-boundary engine on the AAKG (GLASSCAGE Stage E3).

Status: Implemented.

Refactors trust analysis to operate entirely on the graph. Detects privilege
transitions (edges from a lower to a higher trust zone), trust-boundary crossings,
excessive privilege (a semi-trusted component reaching multiple trusted assets),
least-privilege violations (a demonstrated/hypothesized reach into a trusted asset
with no mitigating control present), and assets reachable from the untrusted user.
Emits the legacy trust dict shape for backward compatibility plus new graph fields.
"""

from __future__ import annotations

from .build import high_value_assets
from .types import EdgeState, EdgeType, NodeType

_ZONE_RANK = {"untrusted": 0, "semi-trusted": 1, "trusted": 2}
_FLOW = {EdgeType.CROSSES, EdgeType.INVOKES, EdgeType.ACCESSES}


def _zone(n) -> str:
    return (n.metadata or {}).get("zone", "semi-trusted")


def analyze(g) -> dict:
    return g.cached("trust", lambda: _analyze(g))


def _analyze(g) -> dict:
    comp_types = {NodeType.USER, NodeType.LLM, NodeType.PLANNER, NodeType.MEMORY,
                  NodeType.MCP, NodeType.TOOL, NodeType.API, NodeType.DATABASE,
                  NodeType.FILESYSTEM, NodeType.SECRETS, NodeType.RETRIEVER}
    comps = [n for n in g.nodes() if n.ntype in comp_types]
    nodes_out = [{"id": n.label or n.id, "zone": _zone(n)} for n in comps]

    edges_out, transitions = [], []
    for e in g.edges():
        s, d = g.node(e.src), g.node(e.dst)
        if s is None or d is None or s.ntype not in comp_types or d.ntype not in comp_types:
            continue
        if e.etype not in _FLOW:
            continue
        edges_out.append({"from": s.label or s.id, "to": d.label or d.id})
        sz, dz = _zone(s), _zone(d)
        if _ZONE_RANK[dz] > _ZONE_RANK[sz]:
            transitions.append({"from": s.label or s.id, "to": d.label or d.id,
                                "from_zone": sz, "to_zone": dz, "state": e.state.value,
                                "violation": dz == "trusted" and e.state is not EdgeState.NOT_ASSESSABLE})

    # assets reachable from the untrusted user
    users = g.find(NodeType.USER)
    reachable_ids = set()
    for u in users:
        reachable_ids |= g.reachable(u.id, edge_types=_FLOW)
    hv = high_value_assets(g)
    reachable_assets = sorted({a.label or a.id for a in hv if a.id in reachable_ids})

    # mitigations present
    has_mitigation = bool(g.find(NodeType.MITIGATION))
    violations = []
    for t in transitions:
        if t["violation"] and not has_mitigation:
            violations.append(f"Untrusted-influenced {t['from']} reaches TRUSTED "
                              f"{t['to']} ({t['state']}) with no mitigating control")

    # excessive privilege: a semi-trusted node accessing >1 trusted asset
    excessive = []
    for c in comps:
        if _zone(c) != "semi-trusted":
            continue
        reach = g.reachable(c.id, edge_types=_FLOW)
        hits = [a.label or a.id for a in hv if a.id in reach]
        if len(hits) > 1:
            excessive.append({"component": c.label or c.id, "reaches": sorted(hits)})

    # least-privilege violations: demonstrated access into a trusted asset
    lpv = []
    for e in g.edges(EdgeType.ACCESSES):
        d = g.node(e.dst)
        if d and _zone(d) == "trusted" and e.state is EdgeState.DEMONSTRATED and not has_mitigation:
            lpv.append({"edge": e.id, "asset": d.label or d.id})

    return {
        "nodes": nodes_out, "edges": edges_out, "transitions": transitions,
        "violations": violations, "reachable_trusted_assets": reachable_assets,
        "agentic": bool(g.find(NodeType.PLANNER) or g.find(NodeType.TOOL)),
        "excessive_privilege": excessive, "least_privilege_violations": lpv,
        "source": "aakg",
    }


def to_mermaid(model: dict) -> str:
    zone_nodes = {"untrusted": [], "semi-trusted": [], "trusted": []}
    for n in model["nodes"]:
        zone_nodes.setdefault(n["zone"], []).append(n["id"])
    lines = ["graph LR"]
    labels = {"untrusted": "Untrusted", "semi-trusted": "Semi-trusted", "trusted": "Trusted"}
    for zone, ids in zone_nodes.items():
        if not ids:
            continue
        lines.append(f'  subgraph {labels.get(zone, zone)}')
        for i in sorted(set(ids)):
            lines.append(f'    {_san(i)}["{i}"]')
        lines.append("  end")
    viol = {(t["from"], t["to"]) for t in model["transitions"] if t["violation"]}
    for e in model["edges"]:
        arrow = "-. VIOLATION .->" if (e["from"], e["to"]) in viol else "-->"
        lines.append(f'  {_san(e["from"])} {arrow} {_san(e["to"])}')
    return "\n".join(lines)


def _san(s: str) -> str:
    return "n" + "".join(c if c.isalnum() else "_" for c in s)[:40]
