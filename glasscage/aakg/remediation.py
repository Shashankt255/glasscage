# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Graph-native remediation engine (GLASSCAGE Stage E5-4).

Status: Implemented. Instead of generic per-finding advice, this ranks candidate
mitigations by their measured effect on the graph:
  * how many attack paths the mitigation would break,
  * how much blast radius (reachable high-value assets) it removes,
  * how many trust-boundary violations it resolves.
Every recommendation cites the specific graph nodes/edges that justify it. Effects
are simulated by inspecting current graph structure (no mutation), so results are
deterministic. The per-finding `remediation` text from kb.py is retained and is
complementary (not duplicated) - this engine answers "what should I fix first".
"""

from __future__ import annotations

from .types import EdgeState, EdgeType, NodeType
from . import paths as paths_mod, trust_graph, blast as blast_mod

# Mitigation catalog: key -> (human title, which edges it neutralizes).
# A neutralizer is a predicate over an Edge given the graph.
_CATALOG = {
    "prompt_injection_defenses": (
        "Harden against prompt injection (delimiting, spotlighting, input/output filtering)",
        lambda g, e: e.etype is EdgeType.ENABLES and g.node(e.src)
        and g.node(e.src).metadata.get("status") and "LLM01" in e.src),
    "tool_least_privilege": (
        "Apply least privilege to tools (scope, allowlist, drop unneeded capabilities)",
        lambda g, e: e.etype is EdgeType.ACCESSES and _dst_zone(g, e) == "trusted"),
    "secrets_out_of_context": (
        "Keep secrets out of model/tool context (broker, short-lived creds)",
        lambda g, e: e.etype is EdgeType.ACCESSES and g.node(e.dst)
        and g.node(e.dst).ntype is NodeType.SECRETS),
    "hitl_high_impact": (
        "Require human-in-the-loop confirmation for high-impact tool calls",
        lambda g, e: e.etype is EdgeType.INVOKES and e.state is EdgeState.DEMONSTRATED
        and g.node(e.dst) and g.node(e.dst).ntype is NodeType.TOOL),
    "tenant_isolation": (
        "Enforce tenant/data isolation on database access",
        lambda g, e: e.etype is EdgeType.ACCESSES and g.node(e.dst)
        and g.node(e.dst).ntype is NodeType.DATABASE),
}


def _dst_zone(g, e):
    d = g.node(e.dst)
    return (d.metadata or {}).get("zone") if d else None


def _edge_key(e):
    return e.id


def prioritize(g) -> list[dict]:
    present = {m.id.split(":", 1)[1] for m in g.find(NodeType.MITIGATION)}
    all_paths = paths_mod.build_paths(g)
    trust = trust_graph.analyze(g)
    hv_assets = set(trust["reachable_trusted_assets"])
    violations = trust["violations"]

    recs = []
    for key, (title, neutralizes) in _CATALOG.items():
        neutralized_edges = [e for e in g.edges() if _safe(neutralizes, g, e)]
        if not neutralized_edges:
            continue
        killed_edge_ids = {e.id for e in neutralized_edges}
        # paths broken: any path whose link edge ids intersect neutralized set
        paths_broken = [p for p in all_paths
                        if _path_edge_ids(p) & killed_edge_ids]
        # blast reduction: trusted assets no longer reachable via neutralized access edges
        removed_assets = sorted({g.node(e.dst).label or g.node(e.dst).id
                                 for e in neutralized_edges
                                 if e.etype is EdgeType.ACCESSES and g.node(e.dst)
                                 and (g.node(e.dst).metadata or {}).get("zone") == "trusted"})
        # violations resolved: those mentioning a removed asset
        viol_resolved = [v for v in violations
                         if any(a in v for a in removed_assets)] if removed_assets else []
        impact = (2 * len(paths_broken) + 3 * len(removed_assets) + 4 * len(viol_resolved))
        status = "in place" if key in present else "recommended"
        if status == "in place":
            impact = 0
        recs.append({
            "mitigation": key, "title": title, "status": status,
            "impact_score": impact,
            "paths_affected": len(paths_broken),
            "blast_reduction_assets": removed_assets,
            "violations_resolved": len(viol_resolved),
            "cited_edges": sorted(killed_edge_ids)[:8],
            "cited_nodes": sorted({g.node(e.dst).id for e in neutralized_edges
                                   if g.node(e.dst)})[:8],
            "rationale": (f"Neutralizes {len(neutralized_edges)} edge(s); breaks "
                          f"{len(paths_broken)} attack path(s); removes "
                          f"{len(removed_assets)} reachable trusted asset(s); resolves "
                          f"{len(viol_resolved)} trust violation(s)."),
        })
    recs.sort(key=lambda r: (-r["impact_score"], r["mitigation"]))
    return recs


def _safe(pred, g, e):
    try:
        return bool(pred(g, e))
    except Exception:
        return False


def _path_edge_ids(path):
    return set(path.get("_edge_ids", []))


def to_markdown(recs: list) -> str:
    L = ["## Prioritized Remediation (graph-derived)"]
    if not recs:
        L.append("- No graph-justified mitigations identified.")
        return "\n".join(L)
    for r in recs:
        if r["status"] == "in place":
            continue
        L.append(f"- **{r['title']}** (impact {r['impact_score']})")
        L.append(f"  - {r['rationale']}")
        if r["blast_reduction_assets"]:
            L.append(f"  - Removes access to: {', '.join(r['blast_reduction_assets'])}")
        if r["cited_edges"]:
            L.append(f"  - Justified by edges: {', '.join(r['cited_edges'][:4])}")
    return "\n".join(L)
