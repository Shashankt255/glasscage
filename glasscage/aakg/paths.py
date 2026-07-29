# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Attack-path engine (GLASSCAGE Stage E2).

Status: Implemented.

Replaces template-based exploit chains with dynamic traversal over the AAKG. Paths
run from the untrusted User to high-value assets (Secrets/Database/Filesystem) along
crosses/invokes/accesses edges. Each path's epistemic state is the WEAKEST edge on it
(a path is only Demonstrated if every hop is Demonstrated), and every path carries the
supporting evidence gathered from its edges. Deterministic (graph traversal is sorted).
"""

from __future__ import annotations

from .build import high_value_assets
from .types import EdgeState, EdgeType, NodeType

_FLOW = {EdgeType.CROSSES, EdgeType.INVOKES, EdgeType.ACCESSES}
_ATLAS_HINT = {"Secrets": "AML.T0057", "Database": "AML.T0057",
               "Filesystem": "AML.T0053"}


def _path_state(edges) -> EdgeState:
    ranks = [e.state.rank for e in edges]
    m = min(ranks) if ranks else 1
    return {2: EdgeState.DEMONSTRATED, 1: EdgeState.HYPOTHESIZED,
            0: EdgeState.NOT_ASSESSABLE}[m]


def build_paths(g, max_depth: int = 6) -> list[dict]:
    return g.cached(("paths", max_depth), lambda: _build_paths(g, max_depth))


def _build_paths(g, max_depth: int = 6) -> list[dict]:
    users = g.find(NodeType.USER)
    assets = high_value_assets(g)
    if not users or not assets:
        return []
    asset_ids = [a.id for a in assets]
    paths = []
    seen = set()
    for u in users:
        for edge_path in g.simple_paths(u.id, asset_ids, edge_types=_FLOW, max_depth=max_depth):
            key = "|".join(e.id for e in edge_path)
            if key in seen:
                continue
            seen.add(key)
            state = _path_state(edge_path)
            evidence = sorted({r for e in edge_path for r in e.evidence_refs if r})
            nodes = [u] + [g.node(e.dst) for e in edge_path]
            terminal = nodes[-1]
            links = []
            for e in edge_path:
                dst = g.node(e.dst)
                links.append({"phase": e.etype.value, "evidence": dst.label or dst.id,
                              "probe": None, "state": e.state.value,
                              "inferred": e.state is not EdgeState.DEMONSTRATED})
            demonstrated = sum(1 for e in edge_path if e.state is EdgeState.DEMONSTRATED)
            conf = [e.confidence for e in edge_path if e.confidence is not None]
            likelihood = round((sum(conf) / len(conf)) if conf else
                               (0.9 if state is EdgeState.DEMONSTRATED else
                                0.5 if state is EdgeState.HYPOTHESIZED else 0.1), 3)
            severity = ("critical" if state is EdgeState.DEMONSTRATED and terminal.ntype is NodeType.SECRETS
                        else "high" if state is EdgeState.DEMONSTRATED
                        else "medium" if state is EdgeState.HYPOTHESIZED else "info")
            paths.append({
                "id": f"path:{key}",
                "title": f"{u.label} -> {terminal.label} ({state.value})",
                "atlas": _ATLAS_HINT.get(terminal.ntype.value, ""),
                "links": links,
                "_edge_ids": [e.id for e in edge_path],
                "state": state.value,
                "likelihood": likelihood,
                "evidenced_links": demonstrated,
                "total_links": len(edge_path),
                "severity": severity,
                "evidence_refs": evidence,
                "narrative": " -> ".join(
                    [u.label] + [f"{g.node(e.dst).label}[{e.state.value}]" for e in edge_path]),
            })
    # deterministic: demonstrated first, then by likelihood, then id
    order = {"demonstrated": 0, "hypothesized": 1, "not_assessable": 2}
    paths.sort(key=lambda p: (order[p["state"]], -p["likelihood"], p["id"]))
    return paths


def to_mermaid(path: dict) -> str:
    lines = ["graph LR"]
    prev = None
    for i, l in enumerate(path["links"]):
        nid = f"s{i}"
        cls = "" if not l["inferred"] else ":::inferred"
        lines.append(f'  {nid}["{l["phase"]}<br/>{l["evidence"][:36]}<br/>({l["state"]})"]{cls}')
        if prev is not None:
            lines.append(f"  {prev} --> {nid}")
        prev = nid
    lines.append("  classDef inferred stroke-dasharray: 5 5;")
    return "\n".join(lines)
