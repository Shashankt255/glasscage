# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Assessment Story (GLASSCAGE reporting layer).

Status: Implemented (renderer only).

One complete engagement narrative, told the way a penetration tester would tell it,
assembled ENTIRELY from data the analysis pipeline already produced (graph, paths,
trust, blast, coverage, posture, remediation). It performs no analysis, creates no
paths, and adds no relationships.

Honest limitations (see docs/NARRATIVES.md):
* **Business Impact is qualitative.** The graph records asset TYPES (Secrets/Database/
  Filesystem) but GLASSCAGE has no source of asset criticality or monetary value. We
  therefore describe impact in terms of what is reachable and mark it [Estimated]; we
  never invent financial figures or criticality ratings.
* **Root Cause** is limited to findings that carry an `enables` edge into a node on the
  path. Where none exists we say "Not demonstrated." rather than guess.
* **Residual Risk** is derived from remediation's measured path/blast effects and is
  therefore [Estimated], not a probability.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..evidence_confidence import EvidenceClass as EC
from ..evidence_confidence import from_state
from . import narrative as narr_mod
from .types import EdgeType, NodeType

_NOT_DEMONSTRATED = "Not demonstrated."


@dataclass
class Section:
    """One story section: prose + its evidence class + graph citations."""
    key: str
    title: str
    evidence_class: EC
    body: list = field(default_factory=list)
    citations: list = field(default_factory=list)

    def to_markdown(self) -> str:
        L = [f"### {self.title}  [{self.evidence_class.value}]", ""]
        L += self.body or [_NOT_DEMONSTRATED]
        if self.citations:
            L.append("")
            L.append(f"_Cited: {', '.join(f'`{c}`' for c in self.citations[:6])}_")
        return "\n".join(L)

    def to_dict(self) -> dict:
        return {"key": self.key, "title": self.title,
                "evidence_class": self.evidence_class.value,
                "body": self.body, "citations": self.citations}


@dataclass
class StoryModel:
    target: str
    sections: list = field(default_factory=list)

    def section(self, key):
        return next((s for s in self.sections if s.key == key), None)

    def to_markdown(self) -> str:
        L = ["## Assessment Story", "",
             "_A narrative account of this engagement. Every statement is derived from "
             "the AI Attack Knowledge Graph; nothing is inferred beyond it. Each section "
             "carries its evidence classification._", ""]
        for s in self.sections:
            L.append(s.to_markdown())
            L.append("")
        return "\n".join(L)

    def to_dict(self) -> dict:
        return {"target": self.target, "sections": [s.to_dict() for s in self.sections]}


def _findings_by_state(g):
    demo, hypo, na = [], [], []
    for f in g.find(NodeType.FINDING):
        md = f.metadata or {}
        if md.get("impact_confirmed"):
            demo.append(f)
        elif md.get("status") == "not_assessable":
            na.append(f)
        else:
            hypo.append(f)
    return demo, hypo, na


def build_story(g, results, target_name: str = "target") -> StoryModel:
    posture = results.get("posture") or {}
    _coverage = results.get("coverage") or {}
    chains = results.get("chains") or []
    trust = results.get("trust") or {}
    br = results.get("blast") or {}
    recs = results.get("remediation_priorities") or []
    recon = results.get("recon")
    tier = (results.get("tier") or {})
    demo, hypo, na = _findings_by_state(g)
    sections = []

    # 1. Assessment Overview -------------------------------------------------
    stats = g.stats()
    sections.append(Section(
        "overview", "1. Assessment Overview", EC.VERIFIED,
        [f"- Target: **{target_name}**",
         f"- Assessed capability tier: **{tier.get('assessed', 'unknown')}** "
         f"(probes above this tier are reported Not Assessable, never guessed)",
         f"- Knowledge graph built for this run: **{stats['nodes']} nodes, "
         f"{stats['edges']} edges**",
         f"- Findings recorded: **{len(demo)} demonstrated**, {len(hypo)} hypothesized, "
         f"{len(na)} not assessable",
         "- Scope: only what the target exposed to the probes below. Absence of a "
         "finding is not evidence of absence."],
        [f"graph:{stats['nodes']}n/{stats['edges']}e"]))

    # 2. Reconnaissance Summary ---------------------------------------------
    rbody, rcite = [], []
    if recon is not None:
        tools = getattr(recon, "schema_tools", []) or []
        surface = getattr(recon, "tool_surface", []) or []
        rbody.append(f"- Declared tools ingested from schema: **{len(tools)}**"
                     if tools else "- No tool schema was supplied.")
        if tools:
            rcite += [f"Tool:{t.get('name')}" for t in tools[:4]]
            rbody.append(f"- Tool names: {', '.join(t.get('name', '?') for t in tools)}")
        if surface:
            rbody.append(f"- Tool surface inferred from responses: {len(surface)} item(s)")
        comps = [n for n in g.nodes() if n.ntype in
                 (NodeType.LLM, NodeType.PLANNER, NodeType.MEMORY, NodeType.MCP,
                  NodeType.RETRIEVER)]
        if comps:
            rbody.append(f"- Components represented in the graph: "
                         f"{', '.join(sorted(c.label or c.id for c in comps))}")
            rcite += [c.id for c in comps[:4]]
    sections.append(Section("recon", "2. Reconnaissance Summary",
                            EC.OBSERVED if rbody else EC.HYPOTHESIZED,
                            rbody or [_NOT_DEMONSTRATED], rcite))

    # 3. Key Findings --------------------------------------------------------
    kbody, kcite = [], []
    if demo:
        kbody.append("**Demonstrated (impact confirmed on-target):**")
        for f in demo[:5]:
            kbody.append(f"- {f.label} — severity "
                         f"{(f.metadata or {}).get('severity', '?')}, confidence "
                         f"{f.confidence if f.confidence is not None else 'n/a'}")
            kcite.append(f.id)
    else:
        kbody.append(f"**Demonstrated:** {_NOT_DEMONSTRATED} No finding reached "
                     "impact confirmation on this target.")
    if hypo:
        kbody.append("")
        kbody.append(f"**Hypothesized ({len(hypo)}):** signals observed without "
                     "confirmed impact; confirm manually before acting.")
    if na:
        kbody.append(f"**Not Assessable ({len(na)}):** the target's capability tier "
                     "did not permit these checks; no claim is made either way.")
    sections.append(Section("findings", "3. Key Findings",
                            EC.DEMONSTRATED if demo else EC.OBSERVED, kbody, kcite))

    # 4. Attack Progression --------------------------------------------------
    top = narr_mod.build_narrative(g, chains, "highest_impact")
    if top.supported:
        abody = [f"The highest-impact path in the graph is `{top.path_id}` "
                 f"(overall state **{top.state}**, likelihood {top.likelihood}). "
                 f"It proceeds as follows; each hop is cited:", ""]
        for i, t in enumerate(top.transitions, 1):
            abody.append(f"{i}. {t.prose}")
            abody.append(f"   - {t.citation()}")
        acls = top.evidence_class
        acite = [t.edge_id for t in top.transitions]
    else:
        abody, acls, acite = [top.reason], EC.PENDING_EXTERNAL_VALIDATION, []
    sections.append(Section("progression", "4. Attack Progression", acls, abody, acite))

    # 5. Trust Boundary Crossings -------------------------------------------
    tbody, tcite = [], []
    transitions = trust.get("transitions", [])
    if transitions:
        tbody.append(f"- Privilege transitions observed in the graph: "
                     f"**{len(transitions)}**")
        for t in transitions[:5]:
            tbody.append(f"  - {t['from']} ({t['from_zone']}) -> {t['to']} "
                         f"({t['to_zone']}) — {t['state']}")
    else:
        tbody.append(_NOT_DEMONSTRATED)
    for v in trust.get("violations", []):
        tbody.append(f"- **VIOLATION:** {v}")
    for ex in trust.get("excessive_privilege", []):
        tbody.append(f"- **Excessive privilege:** {ex['component']} reaches "
                     f"{', '.join(ex['reaches'])}")
        tcite.append(ex["component"])
    ra = trust.get("reachable_trusted_assets", [])
    tbody.append(f"- Trusted assets reachable from the untrusted user: "
                 f"{', '.join(ra) if ra else 'none'}")
    sections.append(Section("trust", "5. Trust Boundary Crossings",
                            EC.DEMONSTRATED if transitions else EC.HYPOTHESIZED,
                            tbody, tcite))

    # 6. Blast Radius --------------------------------------------------------
    basis = br.get("basis", "")
    bcls = from_state(basis) if basis in ("demonstrated", "hypothesized") else EC.ESTIMATED
    bbody = [f"- {br.get('reason', _NOT_DEMONSTRATED)}"]
    if br.get("assets"):
        bbody.append(f"- High-value assets reachable: {', '.join(br['assets'])}")
    if br.get("secrets"):
        bbody.append(f"- Secrets reachable: {', '.join(br['secrets'])}")
    if br.get("tools"):
        bbody.append(f"- Tools reachable: {', '.join(br['tools'])}")
    sections.append(Section("blast", "6. Blast Radius", bcls, bbody,
                            [br.get("origin_finding", "")] if br.get("origin_finding") else []))

    # 7. Business Impact -----------------------------------------------------
    # HONEST: the graph has asset TYPES but no criticality/valuation source.
    assets = br.get("assets", []) or ra
    if assets:
        kinds = sorted({a.split(" via ")[0] if " via " in a else a for a in assets})
        bi = [f"- Reachable asset classes: **{', '.join(kinds)}**.",
              "- In business terms, an attacker who achieves the path above could act "
              "on the data or capability those assets represent.",
              "- **Qualitative only.** GLASSCAGE has no asset-criticality or valuation "
              "input, so no monetary or severity rating is asserted here. Rate these "
              "assets against your own crown-jewel inventory."]
        bicls = EC.ESTIMATED
    else:
        bi = [f"{_NOT_DEMONSTRATED} No high-value asset was shown reachable, so no "
              "business impact is claimed."]
        bicls = EC.HYPOTHESIZED
    sections.append(Section("business_impact", "7. Business Impact", bicls, bi,
                            assets[:4]))

    # 8. Root Cause Analysis -------------------------------------------------
    rcbody, rccite = [], []
    for f in g.find(NodeType.FINDING):
        outs = g.out_edges(f.id, EdgeType.ENABLES)
        if not outs:
            continue
        for e in outs:
            _d = g.node(e.dst)
            rcbody.append(f"- `{f.id}` enables `{e.dst}` ({e.state.value}) — "
                          f"{e.provenance or 'see finding evidence'}")
            rccite.append(e.id)
    if rcbody:
        rcbody.insert(0, "Root causes are limited to findings that carry an `enables` "
                         "edge in the graph:")
        rccls = EC.DEMONSTRATED if any("demonstrated" in b for b in rcbody) else EC.HYPOTHESIZED
    else:
        rcbody = [f"{_NOT_DEMONSTRATED} No finding in the graph carries an `enables` "
                  "edge, so no root cause is asserted."]
        rccls = EC.HYPOTHESIZED
    sections.append(Section("root_cause", "8. Root Cause Analysis", rccls, rcbody, rccite))

    # 9. Evidence Summary ----------------------------------------------------
    ev = g.nodes(NodeType.EVIDENCE)
    ebody = ([f"- {len(ev)} evidence record(s), each a chain-of-custody hash computed "
              "on the ORIGINAL response before redaction."] +
             [f"  - `{e.id.split(':', 1)[1][:16]}…`" for e in ev[:6]]
             if ev else [f"{_NOT_DEMONSTRATED} No evidence records were captured."])
    if ev:
        ebody.append("- Secret-shaped content is redacted in stored artifacts by "
                     "default; hashes still prove integrity of the original.")
    sections.append(Section("evidence", "9. Evidence Summary",
                            EC.VERIFIED if ev else EC.HYPOTHESIZED, ebody,
                            [e.id for e in ev[:4]]))

    # 10. Prioritized Remediation -------------------------------------------
    rbody2, rcite2 = [], []
    actionable = [r for r in recs if r.get("status") != "in place" and r.get("impact_score", 0) > 0]
    for r in actionable[:5]:
        rbody2.append(f"- **{r['title']}** (graph impact {r['impact_score']})")
        rbody2.append(f"  - {r['rationale']}")
        rcite2 += r.get("cited_edges", [])[:2]
    inplace = [r for r in recs if r.get("status") == "in place"]
    if inplace:
        rbody2.append(f"- Already in place: "
                      f"{', '.join(r['mitigation'] for r in inplace)}")
    sections.append(Section("remediation", "10. Prioritized Remediation",
                            EC.ESTIMATED if actionable else EC.HYPOTHESIZED,
                            rbody2 or [_NOT_DEMONSTRATED], rcite2))

    # 11. Residual Risk ------------------------------------------------------
    total_paths = len(chains)
    covered = set()
    for r in actionable:
        covered.update(r.get("cited_edges", []))
    remaining = [c for c in chains if not (set(c.get("_edge_ids", [])) & covered)]
    resid = [f"- Attack paths in the graph: **{total_paths}**; paths NOT addressed by "
             f"the mitigations above: **{len(remaining)}**.",
             f"- Indicative Risk Index before remediation: "
             f"{posture.get('risk_index', '?')}/100 (uncalibrated heuristic).",
             "- Residual risk after remediation is **not computed as a number**: "
             "GLASSCAGE has no calibration data to support such a claim. Re-run the "
             "assessment after fixes to observe the change."]
    if na:
        resid.append(f"- {len(na)} check(s) were Not Assessable at this tier and remain "
                     "unknown — an unmeasured area, not a clean result.")
    sections.append(Section("residual", "11. Residual Risk", EC.ESTIMATED, resid))

    # 12. Verification Checklist --------------------------------------------
    vbody = ["Confirm each item manually before acting on it:"]
    for f in demo[:6]:
        vbody.append(f"- [ ] Reproduce `{f.id}` using its stored evidence and "
                     "reproduction steps (demonstrated — expect it to reproduce).")
    for f in hypo[:4]:
        vbody.append(f"- [ ] Manually test `{f.id}` (hypothesized — unproven).")
    for f in na[:3]:
        vbody.append(f"- [ ] Re-test `{f.id}` against an L2+ instrumented target "
                     "(not assessable at this tier).")
    for r in actionable[:3]:
        vbody.append(f"- [ ] After applying **{r['mitigation']}**, re-run and confirm "
                     f"{r['paths_affected']} path(s) no longer traverse "
                     f"{', '.join(r.get('cited_edges', [])[:1]) or 'the cited edges'}.")
    sections.append(Section("verification", "12. Verification Checklist", EC.VERIFIED,
                            vbody))

    # 13. Lessons Learned ----------------------------------------------------
    owasp_hit = sorted({(g.node(e.dst).label or e.dst)
                        for f in g.find(NodeType.FINDING)
                        for e in g.out_edges(f.id, EdgeType.MAPPED_TO)
                        if g.node(e.dst) and g.node(e.dst).ntype is NodeType.OWASP})
    lbody = []
    if owasp_hit:
        lbody.append(f"- Categories exercised on this target: {', '.join(owasp_hit)}.")
    if trust.get("excessive_privilege"):
        lbody.append("- A semi-trusted component can reach more than one trusted asset; "
                     "tool scope is the highest-leverage structural fix in this graph.")
    if na:
        lbody.append("- Agentic checks could not run at this tier. Instrumenting the "
                     "target to L2 would convert unknowns into measurements.")
    if not demo and hypo:
        lbody.append("- Signals were observed without confirmed impact: treat this run "
                     "as hypothesis generation, not proof.")
    lbody.append("- Findings here are hypotheses until confirmed; the Indicative Risk "
                 "Index is uncalibrated and is a relative prioritization signal only.")
    sections.append(Section("lessons", "13. Lessons Learned", EC.OBSERVED, lbody))

    return StoryModel(target=target_name, sections=sections)
