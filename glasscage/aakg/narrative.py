# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Attack Narrative model (GLASSCAGE reporting layer).

Status: Implemented (renderer only).

This module NEVER performs analysis. It selects among the attack paths that
`aakg.paths.build_paths` already produced and renders them as prose. It creates no
paths, no nodes, no edges, and no relationships. Every transition carries the node
ids, edge id, evidence ids, confidence and epistemic state taken verbatim from the
graph.

Evidence discipline
-------------------
* A transition's evidence class is mapped from the graph edge state via
  `evidence_confidence.from_state` and then CLAMPED so a narrative can never claim
  more than its weakest transition supports.
* Structural edges (e.g. `User -[crosses]-> LLM`) are recorded in the graph with
  provenance but with NO evidence id. We say so explicitly ("no evidence id
  (structural edge)") rather than inventing one.
* If no existing path matches a requested strategy we return an unsupported model
  whose prose is exactly "Not demonstrated." - we do not synthesize a path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..evidence_confidence import EvidenceClass as EC
from ..evidence_confidence import from_state
from .types import EdgeState, EdgeType, NodeType

# Presentation-only lookup: how to say an edge out loud. Adds no semantics.
_VERBS = {
    EdgeType.CROSSES: "crosses the trust boundary into",
    EdgeType.INVOKES: "invokes",
    EdgeType.ACCESSES: "reaches",
    EdgeType.ENABLES: "enables",
    EdgeType.AFFECTS: "affects",
    EdgeType.REQUIRES: "requires",
    EdgeType.MAPPED_TO: "is classified as",
    EdgeType.MITIGATES: "mitigates",
    EdgeType.VERIFIED_BY: "is verified by",
    EdgeType.OBSERVED_ON: "was observed on",
    EdgeType.TRUSTS: "trusts",
    EdgeType.HYPOTHESIZED_BY: "is hypothesized by",
}
_ZONE_RANK = {"untrusted": 0, "semi-trusted": 1, "trusted": 2}


@dataclass
class Transition:
    """One hop of a narrative, fully cited from the graph."""
    src_id: str
    dst_id: str
    edge_id: str
    edge_type: str
    state: str
    confidence: float | None
    evidence_ids: list = field(default_factory=list)
    provenance: str = ""
    prose: str = ""

    @property
    def evidence_class(self) -> EC:
        return from_state(self.state)

    def citation(self) -> str:
        ev = ", ".join(self.evidence_ids[:2]) if self.evidence_ids else \
            "no evidence id (structural edge)"
        conf = f"{self.confidence:.2f}" if self.confidence is not None else "n/a"
        return (f"nodes `{self.src_id}` -> `{self.dst_id}` · edge `{self.edge_id}` · "
                f"evidence {ev} · confidence {conf} · [{self.evidence_class.value}]")


@dataclass
class NarrativeModel:
    """A selected existing path rendered as a citable story. No new analysis."""
    strategy: str
    supported: bool
    reason: str = ""
    path_id: str = ""
    title: str = ""
    transitions: list = field(default_factory=list)
    terminal_id: str = ""
    terminal_label: str = ""
    state: str = ""
    likelihood: float | None = None
    atlas: str = ""
    evidence_ids: list = field(default_factory=list)
    owasp_ids: list = field(default_factory=list)
    capec_ids: list = field(default_factory=list)
    cwe_ids: list = field(default_factory=list)

    @property
    def evidence_class(self) -> EC:
        """Clamped to the weakest transition: a narrative never over-claims."""
        if not self.supported:
            return EC.PENDING_EXTERNAL_VALIDATION
        if not self.transitions:
            return EC.HYPOTHESIZED
        weakest = min(self.transitions, key=lambda t: t.evidence_class.rank)
        return weakest.evidence_class


# ---- strategy selectors: filters over EXISTING paths only ------------------ #
_TERMINAL_VALUE = {NodeType.SECRETS.value: 3, NodeType.DATABASE.value: 2,
                   NodeType.FILESYSTEM.value: 1}
_STATE_RANK = {"demonstrated": 2, "hypothesized": 1, "not_assessable": 0}


def _terminal_type(g, path) -> str:
    n = g.node(_terminal_id(g, path))
    return n.ntype.value if n else ""


def _terminal_id(g, path) -> str:
    eids = path.get("_edge_ids") or []
    if not eids:
        return ""
    last = _edge_by_id(g, eids[-1])
    return last.dst if last else ""


def _edge_by_id(g, eid):
    for e in g.edges():
        if e.id == eid:
            return e
    return None


def _path_nodes(g, path):
    out = []
    for eid in path.get("_edge_ids") or []:
        e = _edge_by_id(g, eid)
        if e:
            out.append(g.node(e.src))
            out.append(g.node(e.dst))
    return [n for n in out if n]


def _has_node_type(g, path, ntype) -> bool:
    return any(n.ntype is ntype for n in _path_nodes(g, path))


def _has_edge(g, path, etype, dst_ntype=None) -> bool:
    for eid in path.get("_edge_ids") or []:
        e = _edge_by_id(g, eid)
        if e and e.etype is etype:
            if dst_ntype is None:
                return True
            d = g.node(e.dst)
            if d and d.ntype is dst_ntype:
                return True
    return False


def _crosses_privilege(g, path) -> bool:
    for eid in path.get("_edge_ids") or []:
        e = _edge_by_id(g, eid)
        if not e:
            continue
        s, d = g.node(e.src), g.node(e.dst)
        if not s or not d:
            continue
        sz = (s.metadata or {}).get("zone", "semi-trusted")
        dz = (d.metadata or {}).get("zone", "semi-trusted")
        if _ZONE_RANK.get(dz, 1) > _ZONE_RANK.get(sz, 1):
            return True
    return False


def _impact_key(g, p):
    return (_STATE_RANK[p["state"]],
            _TERMINAL_VALUE.get(_terminal_type(g, p), 0),
            p["likelihood"])


STRATEGIES = {
    "highest_impact": {
        "title": "Highest Impact Path",
        "filter": lambda g, p: True,
        "rank": lambda g, p: _impact_key(g, p),
    },
    "lowest_effort": {
        "title": "Lowest Effort Path",
        "filter": lambda g, p: True,
        # fewest hops first, then strongest state (negate for max-ranking)
        "rank": lambda g, p: (-p["total_links"], _STATE_RANK[p["state"]]),
    },
    "most_likely": {
        "title": "Most Likely Path",
        "filter": lambda g, p: True,
        "rank": lambda g, p: (p["likelihood"], _STATE_RANK[p["state"]]),
    },
    "data_exfiltration": {
        "title": "Data Exfiltration Narrative",
        "filter": lambda g, p: _terminal_type(g, p) in (NodeType.SECRETS.value,
                                                        NodeType.DATABASE.value),
        "rank": lambda g, p: _impact_key(g, p),
    },
    "tool_abuse": {
        "title": "Tool Abuse Narrative",
        "filter": lambda g, p: _has_edge(g, p, EdgeType.INVOKES, NodeType.TOOL),
        "rank": lambda g, p: _impact_key(g, p),
    },
    "privilege_escalation": {
        "title": "Privilege Escalation Narrative",
        "filter": lambda g, p: _crosses_privilege(g, p),
        "rank": lambda g, p: _impact_key(g, p),
    },
    "memory_poisoning": {
        "title": "Memory Poisoning Narrative",
        "filter": lambda g, p: _has_node_type(g, p, NodeType.MEMORY),
        "rank": lambda g, p: _impact_key(g, p),
    },
    "mcp_compromise": {
        "title": "MCP Compromise Narrative",
        "filter": lambda g, p: _has_node_type(g, p, NodeType.MCP),
        "rank": lambda g, p: _impact_key(g, p),
    },
}


def _taxonomy_for(g, path):
    """OWASP/CAPEC/CWE ids reachable from findings that ENABLE nodes on this path."""
    owasp, capec, cwe = set(), set(), set()
    node_ids = {n.id for n in _path_nodes(g, path)}
    for f in g.find(NodeType.FINDING):
        enabled = {e.dst for e in g.out_edges(f.id, EdgeType.ENABLES)}
        if not (enabled & node_ids):
            continue
        for e in g.out_edges(f.id, EdgeType.MAPPED_TO):
            d = g.node(e.dst)
            if not d:
                continue
            if d.ntype is NodeType.OWASP:
                owasp.add(d.label or d.id)
            elif d.ntype is NodeType.CAPEC:
                capec.add(d.label or d.id)
            elif d.ntype is NodeType.CWE:
                cwe.add(d.label or d.id)
    return sorted(owasp), sorted(capec), sorted(cwe)


def build_narrative(g, paths, strategy: str) -> NarrativeModel:
    """Render an EXISTING path under a strategy. Never creates a path."""
    spec = STRATEGIES.get(strategy)
    if spec is None:
        return NarrativeModel(strategy=strategy, supported=False,
                              reason=f"unknown strategy '{strategy}'")
    candidates = [p for p in paths if spec["filter"](g, p)]
    if not candidates:
        return NarrativeModel(
            strategy=strategy, supported=False,
            reason=("Not demonstrated. No existing graph path matches this strategy; "
                    "no path was synthesized. [Not Supported by Current Evidence]"))
    best = max(candidates, key=lambda p: spec["rank"](g, p))

    transitions = []
    for eid in best.get("_edge_ids") or []:
        e = _edge_by_id(g, eid)
        if not e:
            continue
        s, d = g.node(e.src), g.node(e.dst)
        verb = _VERBS.get(e.etype, e.etype.value)
        prose = f"{(s.label or s.id) if s else e.src} {verb} {(d.label or d.id) if d else e.dst}"
        if e.state is not EdgeState.DEMONSTRATED:
            prose += (" — not demonstrated on this target"
                      if e.state is EdgeState.NOT_ASSESSABLE
                      else " — hypothesized, not shown on-target")
        transitions.append(Transition(
            src_id=e.src, dst_id=e.dst, edge_id=e.id, edge_type=e.etype.value,
            state=e.state.value, confidence=e.confidence,
            evidence_ids=list(e.evidence_refs), provenance=e.provenance, prose=prose))

    term_id = _terminal_id(g, best)
    term = g.node(term_id)
    owasp, capec, cwe = _taxonomy_for(g, best)
    return NarrativeModel(
        strategy=strategy, supported=True, path_id=best["id"],
        title=spec["title"], transitions=transitions, terminal_id=term_id,
        terminal_label=(term.label or term_id) if term else term_id,
        state=best["state"], likelihood=best["likelihood"], atlas=best.get("atlas", ""),
        evidence_ids=sorted({x for t in transitions for x in t.evidence_ids}),
        owasp_ids=owasp, capec_ids=capec, cwe_ids=cwe)


def build_all(g, paths) -> list:
    """One model per strategy (unsupported ones included, honestly marked)."""
    return [build_narrative(g, paths, s) for s in STRATEGIES]


def dedupe(models) -> list:
    """Group models that selected the SAME path.

    Several strategies frequently resolve to one path (e.g. the shortest path is also
    the highest impact). Rendering it once per strategy would duplicate the report
    without adding information, so we render each distinct path once and list the
    strategies that selected it. Unsupported strategies are grouped separately.

    Returns a list of {"model", "strategies", "supported"} in a deterministic order.
    """
    groups: dict = {}
    for m in models:
        key = m.path_id if m.supported else f"__unsupported__{m.reason}"
        g_ = groups.setdefault(key, {"model": m, "strategies": [], "supported": m.supported})
        title = STRATEGIES.get(m.strategy, {}).get("title", m.strategy)
        g_["strategies"].append(title)
    out = list(groups.values())
    # supported first, then strongest evidence, then most strategies, then id
    out.sort(key=lambda gg: (not gg["supported"],
                             -gg["model"].evidence_class.rank,
                             -len(gg["strategies"]),
                             gg["model"].path_id))
    return out


def group_to_markdown(group) -> str:
    """Render one deduped group: the path once, with the strategies that chose it."""
    m = group["model"]
    strategies = ", ".join(group["strategies"])
    if not group["supported"]:
        return f"### {strategies}  [Not Supported by Current Evidence]\n\n{m.reason}"
    body = to_markdown(m)
    first_nl = body.find("\n")
    return f"### {strategies}  [{m.evidence_class.value}]" + body[first_nl:]


def to_markdown(model: NarrativeModel) -> str:
    """Default (security-team) rendering of a single narrative."""
    spec = STRATEGIES.get(model.strategy, {})
    title = model.title or spec.get("title", model.strategy)
    if not model.supported:
        return f"### {title}  [Not Supported by Current Evidence]\n\n{model.reason}"
    L = [f"### {title}  [{model.evidence_class.value}]", "",
         f"_Path `{model.path_id}` · overall state **{model.state}** · "
         f"likelihood {model.likelihood} · every hop cited from the graph._", ""]
    for i, t in enumerate(model.transitions, 1):
        L.append(f"{i}. {t.prose}")
        L.append(f"   - {t.citation()}")
        if t.provenance:
            L.append(f"   - provenance: {t.provenance}")
    if model.atlas:
        L.append(f"\n- MITRE ATLAS: {model.atlas}")
    if model.owasp_ids:
        L.append(f"- OWASP LLM: {', '.join(model.owasp_ids)}")
    if model.capec_ids:
        L.append(f"- CAPEC: {', '.join(model.capec_ids)}")
    if model.cwe_ids:
        L.append(f"- CWE: {', '.join(model.cwe_ids)}")
    if not model.evidence_ids:
        L.append("- Evidence ids: none on these edges (structural relationships); see the "
                 "Evidence Ledger for finding-level evidence.")
    return "\n".join(L)


def to_dict(model: NarrativeModel) -> dict:
    return {
        "strategy": model.strategy, "title": model.title, "supported": model.supported,
        "reason": model.reason, "path_id": model.path_id, "state": model.state,
        "likelihood": model.likelihood, "evidence_class": model.evidence_class.value,
        "terminal": model.terminal_label, "atlas": model.atlas,
        "owasp": model.owasp_ids, "capec": model.capec_ids, "cwe": model.cwe_ids,
        "evidence_ids": model.evidence_ids,
        "transitions": [{
            "src": t.src_id, "dst": t.dst_id, "edge_id": t.edge_id,
            "edge_type": t.edge_type, "state": t.state, "confidence": t.confidence,
            "evidence_ids": t.evidence_ids, "evidence_class": t.evidence_class.value,
            "prose": t.prose, "provenance": t.provenance,
        } for t in model.transitions],
    }
