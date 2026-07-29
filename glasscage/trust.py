# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Trust-boundary & privilege-transition analyzer (GLASSCAGE v1.0, objective 5).

Design rationale
----------------
The highest-leverage question in AI-app security is not "can the model be tricked"
but "when it is, what does it reach?". That is an *architecture* question. This
module models the system as a graph of components grouped into trust zones,
derives the edges (data/control flow), flags boundary crossings and
privilege transitions, and marks violations where untrusted influence reaches a
trusted asset without a mitigating control.

Inputs (all optional, best-effort):
  * recon.schema_tools   - schema-confirmed tools (capability -> component)
  * mcp_manifest         - MCP servers/tools
  * architecture answers - which controls exist (from architecture.py)

Zero-dependency. Backward compatible: purely additive, produces its own result.
"""

from __future__ import annotations

# Trust zones, lowest -> highest privilege.
UNTRUSTED = "untrusted"
SEMI = "semi-trusted"
TRUSTED = "trusted"
_ZONE_RANK = {UNTRUSTED: 0, SEMI: 1, TRUSTED: 2}

# Canonical components and their default zone.
COMPONENTS = {
    "User": UNTRUSTED, "ExternalAPI": UNTRUSTED, "Web": UNTRUSTED,
    "EmailInbound": UNTRUSTED, "Retriever": UNTRUSTED, "VectorDB": UNTRUSTED,
    "LLM": SEMI, "Planner": SEMI, "Memory": SEMI, "MCP": SEMI,
    "Database": TRUSTED, "Filesystem": TRUSTED, "Cloud": TRUSTED,
    "Secrets": TRUSTED, "CICD": TRUSTED, "EmailOutbound": TRUSTED,
}

# Tool capability -> component it touches.
_CAP_COMPONENT = {
    "data": "Database", "network": "ExternalAPI", "exec": "Filesystem",
    "cred": "Secrets", "write": "Database", "unknown": "ExternalAPI",
}

# Which architecture control mitigates a crossing into a given component.
_CONTROL_FOR = {
    "Database": "tenant_isolation", "Secrets": "secrets_out_of_context",
    "Filesystem": "tool_least_privilege", "Cloud": "tool_least_privilege",
    "ExternalAPI": "untrusted_content_segregation", "EmailOutbound": "hitl_high_impact",
    "CICD": "hitl_high_impact",
}


def _yes(answers, key):
    return str((answers or {}).get(key, "")).lower() in ("yes", "y", "true")


def build(recon, mcp_manifest=None, architecture_answers=None) -> dict:
    nodes = {"User": UNTRUSTED, "LLM": SEMI}
    edges = []

    schema_tools = getattr(recon, "schema_tools", []) or []
    has_agentic = bool(schema_tools or mcp_manifest or recon.tool_surface)
    if has_agentic:
        nodes["Planner"] = SEMI
        nodes["Memory"] = SEMI
    if mcp_manifest:
        nodes["MCP"] = SEMI

    # Base flow: User -> LLM -> (Planner) -> tools
    edges.append(("User", "LLM"))
    if "Planner" in nodes:
        edges.append(("LLM", "Planner"))
        edges.append(("Planner", "Memory"))

    reachable_trusted = set()
    for t in schema_tools:
        comp = _CAP_COMPONENT.get(t.get("capability", "unknown"), "ExternalAPI")
        nodes[comp] = COMPONENTS.get(comp, TRUSTED)
        src = "Planner" if "Planner" in nodes else "LLM"
        edges.append((src, comp))
        if nodes[comp] == TRUSTED:
            reachable_trusted.add(comp)

    if mcp_manifest:
        edges.append(("LLM", "MCP"))
        for t in mcp_manifest.get("tools", []):
            edges.append(("MCP", "ExternalAPI"))
            nodes.setdefault("ExternalAPI", UNTRUSTED)

    # Classify crossings + violations
    transitions, violations = [], []
    for src, dst in edges:
        sz, dz = nodes.get(src, SEMI), nodes.get(dst, SEMI)
        crosses = _ZONE_RANK[dz] > _ZONE_RANK[sz]
        control = _CONTROL_FOR.get(dst)
        control_present = _yes(architecture_answers, control) if control else True
        violation = crosses and dz == TRUSTED and not control_present
        if crosses:
            transitions.append({"from": src, "to": dst, "from_zone": sz,
                                 "to_zone": dz, "control": control,
                                 "control_present": control_present,
                                 "violation": violation})
        if violation:
            violations.append(
                f"Untrusted-influenced {src} can reach TRUSTED {dst} without "
                f"control '{control}'")

    return {
        "nodes": [{"id": n, "zone": z} for n, z in nodes.items()],
        "edges": [{"from": a, "to": b} for a, b in edges],
        "transitions": transitions,
        "violations": violations,
        "reachable_trusted_assets": sorted(reachable_trusted),
        "agentic": has_agentic,
    }


def to_mermaid(model: dict) -> str:
    zone_nodes = {UNTRUSTED: [], SEMI: [], TRUSTED: []}
    for n in model["nodes"]:
        zone_nodes[n["zone"]].append(n["id"])
    lines = ["graph LR"]
    labels = {UNTRUSTED: "Untrusted", SEMI: "Semi-trusted", TRUSTED: "Trusted"}
    for zone, ids in zone_nodes.items():
        if not ids:
            continue
        lines.append(f'  subgraph {labels[zone]}')
        for i in ids:
            lines.append(f'    {i}')
        lines.append("  end")
    viol_pairs = {(t["from"], t["to"]) for t in model["transitions"] if t["violation"]}
    for e in model["edges"]:
        arrow = "-. VIOLATION .->" if (e["from"], e["to"]) in viol_pairs else "-->"
        lines.append(f'  {e["from"]} {arrow} {e["to"]}')
    return "\n".join(lines)


def summary_line(model: dict) -> str:
    return (f"Trust model: {len(model['nodes'])} components, "
            f"{len(model['transitions'])} privilege transitions, "
            f"{len(model['violations'])} boundary violation(s); "
            f"reachable trusted assets: "
            f"{', '.join(model['reachable_trusted_assets']) or 'none'}")
