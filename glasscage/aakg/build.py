# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Assemble the AAKG from an assessment run (GLASSCAGE Stage E1).

Status: Implemented.

Turns recon + findings + schema tools + MCP + architecture answers + taxonomy into
a single property graph. Edge epistemic state is derived from evidence:
  * DEMONSTRATED  - an impact-confirmed finding proves the relationship
  * HYPOTHESIZED  - architecturally reachable (e.g. a schema tool exists) but unshown
  * NOT_ASSESSABLE - a probe that would prove it was tier-gated at this target tier

This is the function every downstream engine (paths/trust/blast) reads from.
"""

from __future__ import annotations

import hashlib
import re

from .engine import PropertyGraph
from .types import EdgeState, EdgeType, NodeType
from .. import taxonomy

_WS = re.compile(r"\s+")

# tool capability -> asset node type
_CAP_ASSET = {
    "data": NodeType.DATABASE, "network": NodeType.API, "exec": NodeType.FILESYSTEM,
    "cred": NodeType.SECRETS, "write": NodeType.DATABASE, "unknown": NodeType.API,
}
_ZONE = {  # node type -> trust zone label
    NodeType.USER: "untrusted", NodeType.API: "untrusted",
    NodeType.RETRIEVER: "untrusted",
    NodeType.LLM: "semi-trusted", NodeType.PLANNER: "semi-trusted",
    NodeType.MEMORY: "semi-trusted", NodeType.MCP: "semi-trusted",
    NodeType.DATABASE: "trusted", NodeType.FILESYSTEM: "trusted",
    NodeType.SECRETS: "trusted",
}
_HIGH_VALUE = {NodeType.SECRETS, NodeType.DATABASE, NodeType.FILESYSTEM}


def _status(f):
    return getattr(f.status, "value", f.status)


def _subject_digest(prompt: str) -> str:
    """First 12 hex chars of sha256 over the whitespace-normalised prompt (ADR 0010).

    The prompt is the only existing Finding field carrying *what the finding is about*:
    `mcp.py` writes "tool: <name>", `architecture.py` writes "(assessed) <control>", and
    probes write the payload sent. Digested rather than used raw so no payload, canary or
    unredacted text ever enters a node id - node ids are not covered by the redaction pass
    that processes finding fields.
    """
    return hashlib.sha256(_WS.sub(" ", prompt or "").strip().encode("utf-8")).hexdigest()[:12]


def _finding_key(f) -> str:
    """Finding-node identity (ADR 0010, extended by ADR 0011): category, probe, surface,
    assessed subject.

    `owasp_id:probe_name` alone is not unique - `mcp.analyze_manifest` emits one finding
    per flagged tool and `architecture.assess` one per control, so findings collapsed into
    a single node whose label described one finding and whose status described another.

    Every component is intrinsic to the finding, so the key is content-derived rather than
    order-derived: reordering probes or changing the probe selection cannot re-key another
    finding's node. No component depends on the target's response, so a behavioural change
    updates a node's metadata instead of re-keying it.

    `surface_id` was excluded by ADR 0010 because it was empty on every run and including
    it would have broken the direct/surface graph equivalence of ADR 0002. ADR 0011
    restores it: multiple runtime surfaces now exist, every probe sends a fixed prompt, so
    without it every finding would collide across surfaces. ADR 0011 supersedes the
    *representational* clause of ADRs 0002/0004/0008 while preserving their behavioural
    intent - a direct run (`surface_id` empty) is unchanged.
    """
    return f"{f.owasp_id}:{f.probe_name}:{getattr(f, 'surface_id', '')}:{_subject_digest(f.prompt)}"


def build_graph(recon, findings, mcp_manifest=None, architecture_answers=None,
                target_tier="L0", ts="") -> PropertyGraph:
    g = PropertyGraph()

    # --- core components + trust zones ---
    for zone in ("untrusted", "semi-trusted", "trusted"):
        g.ensure(NodeType.TRUST_ZONE, zone, label=zone)
    user = g.ensure(NodeType.USER, "end-user", metadata={"zone": "untrusted"})
    llm = g.ensure(NodeType.LLM, "model", metadata={"zone": "semi-trusted"})
    g.add_edge(user.id, EdgeType.CROSSES, llm.id, EdgeState.DEMONSTRATED,
               provenance="user input reaches the model", timestamp=ts)

    schema_tools = getattr(recon, "schema_tools", []) or []
    agentic = bool(schema_tools or mcp_manifest or getattr(recon, "tool_surface", []))
    planner = None
    if agentic:
        planner = g.ensure(NodeType.PLANNER, "planner", metadata={"zone": "semi-trusted"})
        mem = g.ensure(NodeType.MEMORY, "memory", metadata={"zone": "semi-trusted"})
        g.add_edge(llm.id, EdgeType.INVOKES, planner.id, EdgeState.HYPOTHESIZED, timestamp=ts)
        g.add_edge(planner.id, EdgeType.ACCESSES, mem.id, EdgeState.HYPOTHESIZED, timestamp=ts)
    invoker = planner or llm

    # --- was agentic tool-firing demonstrated / assessable? ---
    tool_state = EdgeState.HYPOTHESIZED
    if any(f.probe_name in ("tool-routing-manipulation", "planner-manipulation")
           and _status(f) == "vulnerable" and getattr(f, "impact_confirmed", False)
           for f in findings):
        tool_state = EdgeState.DEMONSTRATED
    elif any(f.probe_name in ("tool-routing-manipulation", "planner-manipulation")
             and _status(f) == "not_assessable" for f in findings):
        tool_state = EdgeState.NOT_ASSESSABLE

    # --- tools + assets ---
    for t in schema_tools:
        cap = t.get("capability", "unknown")
        tool = g.ensure(NodeType.TOOL, t.get("name", "tool"),
                        metadata={"capability": cap, "zone": "semi-trusted"})
        g.add_edge(invoker.id, EdgeType.INVOKES, tool.id, tool_state,
                   provenance="schema-confirmed tool", timestamp=ts)
        atype = _CAP_ASSET.get(cap, NodeType.API)
        asset = g.ensure(atype, t.get("name", "asset") + ":asset",
                         label=f"{atype.value} via {t.get('name','tool')}",
                         metadata={"zone": _ZONE.get(atype, "trusted")})
        acc_state = (EdgeState.DEMONSTRATED if t.get("side_effect")
                     else EdgeState.HYPOTHESIZED)
        if tool_state is EdgeState.NOT_ASSESSABLE:
            acc_state = EdgeState.NOT_ASSESSABLE
        g.add_edge(tool.id, EdgeType.ACCESSES, asset.id, acc_state,
                   provenance="tool capability -> asset", timestamp=ts)

    if mcp_manifest:
        mcp = g.ensure(NodeType.MCP, "mcp-server", metadata={"zone": "semi-trusted"})
        g.add_edge(llm.id, EdgeType.INVOKES, mcp.id, EdgeState.HYPOTHESIZED, timestamp=ts)

    # --- findings + taxonomy + evidence ---
    for f in findings:
        st = _status(f)
        if st not in ("vulnerable", "inconclusive", "not_assessable"):
            continue
        fkey = _finding_key(f)
        estate = (EdgeState.DEMONSTRATED if (st == "vulnerable" and getattr(f, "impact_confirmed", False))
                  else EdgeState.NOT_ASSESSABLE if st == "not_assessable"
                  else EdgeState.HYPOTHESIZED)
        fnode = g.ensure(NodeType.FINDING, fkey, label=f.title[:80],
                         confidence=f.confidence, timestamp=getattr(f, "timestamp", "") or ts,
                         evidence_refs=[getattr(f, "evidence_hash", "")] if getattr(f, "evidence_hash", "") else [],
                         metadata={"status": st, "dimension": f.dimension,
                                   "severity": f.severity.value,
                                   "impact_confirmed": getattr(f, "impact_confirmed", False)},
                         provenance=getattr(f, "source_framework", "glasscage-native"))
        # taxonomy mapping nodes
        for nt, val in ((NodeType.OWASP, f.owasp_id), (NodeType.ATLAS, getattr(f, "atlas_id", "")),
                        (NodeType.CWE, getattr(f, "cwe_id", "")), (NodeType.CAPEC, getattr(f, "capec_id", "")),
                        (NodeType.NIST, getattr(f, "nist_id", ""))):
            if val:
                tnode = g.ensure(nt, val)
                g.add_edge(fnode.id, EdgeType.MAPPED_TO, tnode.id, EdgeState.DEMONSTRATED, timestamp=ts)
        # evidence node
        eh = getattr(f, "evidence_hash", "")
        if eh:
            ev = g.ensure(NodeType.EVIDENCE, eh, label=f"evidence {eh[:8]}")
            etype = EdgeType.VERIFIED_BY if getattr(f, "impact_confirmed", False) else EdgeType.OBSERVED_ON
            g.add_edge(fnode.id, etype, ev.id, EdgeState.DEMONSTRATED, timestamp=ts)
        # capability tier
        rt = getattr(f, "required_tier", "L0")
        tiern = g.ensure(NodeType.CAPABILITY_TIER, rt)
        g.add_edge(fnode.id, EdgeType.REQUIRES, tiern.id, EdgeState.DEMONSTRATED, timestamp=ts)
        # a prompt-injection finding enables the model to be steered
        if f.owasp_id == "LLM01":
            g.add_edge(fnode.id, EdgeType.ENABLES, llm.id, estate,
                       evidence_refs=fnode.evidence_refs, timestamp=ts,
                       provenance="injection enables model steering")

    # --- mitigations from architecture answers ---
    for key, val in (architecture_answers or {}).items():
        if str(val).lower() in ("yes", "y", "true"):
            m = g.ensure(NodeType.MITIGATION, key, label=key)
            g.add_edge(m.id, EdgeType.MITIGATES, llm.id, EdgeState.DEMONSTRATED,
                       provenance="declared control present", timestamp=ts)

    g.ensure(NodeType.CAPABILITY_TIER, target_tier, label=f"target tier {target_tier}")
    return g


def high_value_assets(g) -> list:
    return [n for n in g.nodes() if n.ntype in _HIGH_VALUE]
