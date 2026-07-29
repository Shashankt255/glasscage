# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Blast-radius simulation on the AAKG (GLASSCAGE Stage E4).

Status: Implemented.

Answers: "if this finding succeeds, what becomes reachable?" by traversing
enables/invokes/accesses/affects edges from the finding (or the component it
enables) and collecting reachable components, tools, secrets, and assets. The
radius is computed from OBSERVED graph relationships, not static heuristics, and
distinguishes demonstrated reach from hypothesized reach.
"""

from __future__ import annotations

from .types import EdgeState, EdgeType, NodeType

_TRAVERSE = {EdgeType.ENABLES, EdgeType.INVOKES, EdgeType.ACCESSES, EdgeType.AFFECTS}
_HIGH = {NodeType.SECRETS, NodeType.DATABASE, NodeType.FILESYSTEM}


def blast_radius(g, finding_id: str) -> dict:
    """Blast radius from a single finding node."""
    if not g.has_node(finding_id):
        return {"finding": finding_id, "error": "unknown finding node"}
    reach = g.reachable(finding_id, edge_types=_TRAVERSE)
    reached = [g.node(n) for n in reach]
    tools = sorted(n.label or n.id for n in reached if n.ntype is NodeType.TOOL)
    secrets = sorted(n.label or n.id for n in reached if n.ntype is NodeType.SECRETS)
    assets = sorted(n.label or n.id for n in reached if n.ntype in _HIGH)
    components = sorted(n.label or n.id for n in reached
                        if n.ntype in {NodeType.LLM, NodeType.PLANNER, NodeType.MEMORY,
                                       NodeType.MCP, NodeType.TOOL})
    return {"finding": finding_id, "reachable_components": components,
            "reachable_tools": tools, "reachable_secrets": secrets,
            "reachable_assets": assets, "asset_count": len(assets)}


def summary(g) -> dict:
    return g.cached("blast", lambda: _summary(g))


def _summary(g) -> dict:
    """Run-level blast radius: worst reachable set across demonstrated enablers.

    Uses demonstrated ENABLES edges (e.g. a confirmed injection enabling the model)
    where available; otherwise falls back to the strongest finding present.
    """
    findings = g.find(NodeType.FINDING)
    if not findings:
        return {"assets": [], "asset_count": 0, "multiplier": 1.0,
                "basis": "no findings", "reason": "no findings to originate a blast"}
    # prefer findings with a demonstrated ENABLES edge
    def enable_state(f):
        outs = g.out_edges(f.id, EdgeType.ENABLES)
        if any(e.state is EdgeState.DEMONSTRATED for e in outs):
            return 2
        if any(e.state is EdgeState.HYPOTHESIZED for e in outs):
            return 1
        return 0
    ranked = sorted(findings, key=lambda f: (-enable_state(f), f.id))
    best = ranked[0]
    br = blast_radius(g, best.id)
    n_assets = br.get("asset_count", 0)
    state = enable_state(best)
    # multiplier scales with reachable high-value assets, discounted if only hypothesized
    factor = 1.0 + 0.5 * n_assets * (1.0 if state == 2 else 0.5 if state == 1 else 0.0)
    return {"origin_finding": best.id, "origin_label": best.label,
            "basis": "demonstrated" if state == 2 else "hypothesized" if state == 1 else "unconfirmed",
            "assets": br.get("reachable_assets", []),
            "secrets": br.get("reachable_secrets", []),
            "tools": br.get("reachable_tools", []),
            "asset_count": n_assets, "multiplier": round(factor, 2),
            "reason": (f"{best.label[:50]} can reach {n_assets} high-value asset(s) "
                       f"({'demonstrated' if state==2 else 'hypothesized' if state==1 else 'unconfirmed'})")}
