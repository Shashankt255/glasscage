# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Attack-surface graph + blast-radius.

Builds a small graph of  agent -> tools -> reachable data/actions  from recon and
(optionally) an MCP manifest, then estimates blast radius: what an attacker can
reach if they win a prompt-injection primitive on the agent. Renders to Mermaid
so it drops straight into the Markdown/HTML report.
"""

from __future__ import annotations

import re

# Capability weights: how damaging a tool is if the agent is hijacked.
_HIGH_IMPACT = {
    "exec": ["shell", "exec", "run", "code", "python", "bash", "eval"],
    "write": ["write", "delete", "update", "create", "send", "email", "post", "pay"],
    "data": ["sql", "query", "db", "database", "file", "read", "fetch", "browse", "search"],
    "cred": ["secret", "key", "token", "credential", "auth", "vault"],
}


def _classify(tool_name: str) -> list[str]:
    low = tool_name.lower()
    caps = [cap for cap, kws in _HIGH_IMPACT.items() if any(k in low for k in kws)]
    return caps or ["unknown"]


def build_graph(recon, mcp_manifest: dict | None = None) -> dict:
    # Schema-confirmed tools carry a real capability; self-reported are unverified.
    confirmed = {t["name"]: t for t in getattr(recon, "schema_tools", [])}
    names = list(confirmed.keys())
    for t in recon.tool_surface:
        if t not in confirmed:
            names.append(t)
    if mcp_manifest:
        for t in mcp_manifest.get("tools", []):
            n = t.get("name")
            if n and n not in names:
                names.append(n)

    nodes = [{"id": "agent", "type": "agent", "label": "AI Agent"}]
    edges = []
    reach = set()
    for t in names:
        if t in confirmed:
            caps = [confirmed[t]["capability"]]
            prov = "schema-confirmed"
        else:
            caps = _classify(t)
            prov = "self-reported"
        nodes.append({"id": t, "type": "tool", "label": t, "caps": caps, "provenance": prov})
        edges.append(("agent", t))
        # Only schema-confirmed capabilities count toward blast radius.
        if prov == "schema-confirmed":
            for c in caps:
                if c != "unknown":
                    reach.add(c)

    cap_risk = {"exec": 10, "cred": 9, "write": 7, "network": 6, "data": 5, "unknown": 1}
    blast = sum(cap_risk.get(c, 1) for c in reach)
    tier = ("severe" if blast >= 20 else "elevated" if blast >= 10
            else "moderate" if blast >= 5 else "contained")
    unverified = [n["label"] for n in nodes if n.get("provenance") == "self-reported"]

    return {
        "nodes": nodes, "edges": edges,
        "reachable_capabilities": sorted(reach),
        "blast_radius_score": blast, "blast_tier": tier,
        "unverified_tools": unverified,
    }


def to_mermaid(graph: dict) -> str:
    lines = ["graph LR", "  agent([AI Agent]):::agent"]
    color = {"exec": "exec", "cred": "cred", "write": "write",
             "data": "data", "unknown": "unk"}
    for n in graph["nodes"]:
        if n["type"] != "tool":
            continue
        nid = re.sub(r"\W", "_", n["id"])
        caps = n.get("caps", ["unknown"])
        cls = color.get(caps[0], "unk")
        lines.append(f'  agent --> {nid}["{n["label"]}<br/>{"/".join(caps)}"]:::{cls}')
    lines += [
        "  classDef agent fill:#0ea5e9,color:#fff;",
        "  classDef exec fill:#7f1d1d,color:#fff;",
        "  classDef cred fill:#b91c1c,color:#fff;",
        "  classDef write fill:#b45309,color:#fff;",
        "  classDef data fill:#3f6212,color:#fff;",
        "  classDef unk fill:#334155,color:#fff;",
    ]
    return "\n".join(lines)


def summary_line(graph: dict) -> str:
    base = (f"Blast radius: {graph['blast_tier']} "
            f"(score {graph['blast_radius_score']}); reachable (schema-confirmed): "
            f"{', '.join(graph['reachable_capabilities']) or 'none'}")
    if graph.get("unverified_tools"):
        base += (f". Unverified self-reported tools (not counted): "
                 f"{', '.join(graph['unverified_tools'])} — provide --schema to confirm")
    return base
