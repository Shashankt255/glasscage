# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Graph-native report engine (GLASSCAGE Stage E5-3).

Status: Implemented (markdown). Generates the markdown assessment report by querying
the AAKG for every section - attack paths, trust-boundary crossings, blast radius,
posture (with per-factor contributions), coverage, evidence, and demonstrated vs
hypothesized findings. Removes the duplicated section-building that previously lived
in report.to_markdown by sourcing everything from one graph.

The interactive HTML report remains results-driven (report.to_html); since those
results are now graph-derived, it presents the same graph truth - see the Stage E5
architecture notes on the one remaining presentation shim.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .types import EdgeType, NodeType
from . import paths as paths_mod, trust_graph, blast as blast_mod, remediation as rem_mod
from . import narrative as narr_mod
from ..evidence_confidence import EvidenceClass as EC, from_state, tag, legend


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


def to_markdown(g, results, target_name: str = "target") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    posture = results.get("posture") or {}
    coverage = results.get("coverage") or {}
    chains = results.get("chains") or paths_mod.build_paths(g)
    trust = results.get("trust") or trust_graph.analyze(g)
    br = results.get("blast") or blast_mod.summary(g)
    recs = results.get("remediation_priorities") or rem_mod.prioritize(g)
    demo, hypo, na = _findings_by_state(g)

    L = [f"# GLASSCAGE AI Security Assessment: {target_name}",
         f"_Generated {ts} · graph-native report (AAKG source of truth)_", "",
         "> Findings require human confirmation via the evidence and reproduction "
         "steps before action. Demonstrated = observed on-target; Hypothesized = "
         "architecturally reachable but unproven; Not Assessable = target tier too low.",
         "",
         legend([EC.VERIFIED, EC.MEASURED, EC.DEMONSTRATED, EC.OBSERVED,
                 EC.ESTIMATED, EC.HYPOTHESIZED, EC.PENDING_EXTERNAL_VALIDATION]),
         ""]

    # Executive summary — posture is an uncalibrated heuristic (Estimated)
    L += ["## Executive Summary",
          f"- **Indicative Risk Index {posture.get('risk_index','?')}/100** "
          f"(band {posture.get('band','?')}) — {tag('uncalibrated heuristic', EC.ESTIMATED)}; "
          "NOT a statistical or calibrated measure",
          f"- Findings: **{len(demo)} demonstrated**, {len(hypo)} hypothesized, "
          f"{len(na)} not assessable",
          f"- Attack paths to high-value assets: {len(chains)} "
          f"({sum(1 for c in chains if c['state']=='demonstrated')} demonstrated)",
          f"- Blast radius: {br.get('asset_count',0)} high-value asset(s) reachable "
          f"({br.get('basis','?')}), multiplier x{br.get('multiplier','?')} "
          f"[{from_state(br.get('basis','hypothesized')).value if br.get('basis') in ('demonstrated','hypothesized') else EC.ESTIMATED.value}]",
          f"- Trust-boundary violations: {len(trust.get('violations',[]))}"]
    # Narrative headline: one line pointing at the story below (not a repeat of it).
    _top = narr_mod.build_narrative(g, chains, "highest_impact")
    if _top.supported:
        L.append(f"- Most consequential scenario: **{_top.transitions[0].src_id.split(':',1)[-1]} "
                 f"→ {_top.terminal_label}** in {len(_top.transitions)} step(s) — "
                 f"{tag(_top.state, _top.evidence_class)}. Narrated in the Assessment "
                 f"Story below.")
    else:
        L.append("- Most consequential scenario: Not demonstrated "
                 "[Not Supported by Current Evidence].")
    L.append("")

    # Posture contributions (explain every point)
    if posture.get("contributions"):
        L.append(tag("## Indicative Risk Index — contribution breakdown", EC.ESTIMATED))
        for c in posture["contributions"]:
            ev = ", ".join(c["evidence"][:3]) if c.get("evidence") else "-"
            L.append(f"- {c['factor']}: value {c['value']}, "
                     f"{'weight '+str(c['weight']) if c['weight'] is not None else 'offset'}"
                     f" -> **{c['points']} pts** (evidence: {ev})")
        L.append("")

    # Assessment Story — the narrative account (reporting layer; no new analysis)
    story_obj = results.get("story")
    if story_obj is None:
        from . import story as story_mod
        story_obj = story_mod.build_story(g, results, target_name)
    L.append(story_obj.to_markdown())
    L.append("")

    # Attack Narratives — deduped renderings of EXISTING paths
    narratives = results.get("narratives")
    if narratives is None:
        narratives = narr_mod.build_all(g, chains)
    L.append("## Attack Narratives")
    L.append("_Different strategic readings of the SAME graph paths. No path is "
             "synthesized; strategies that match no existing path say so._")
    L.append("")
    for group in narr_mod.dedupe(narratives):
        L.append(narr_mod.group_to_markdown(group))
        L.append("")

    # Attack paths — condensed index (prose lives in the narratives above)
    if chains:
        L.append("## Attack Paths (graph traversal)  [state-tagged per path]")
        L.append("_Index of every path in the graph. Narrated prose is above; this is "
                 "the raw enumeration._")
        L.append("")
        L.append("| State | Path | Likelihood | Demonstrated hops |")
        L.append("|---|---|---|---|")
        for c in chains:
            L.append(f"| {from_state(c['state']).value} | {c['title']} | "
                     f"{c['likelihood']} | {c['evidenced_links']}/{c['total_links']} |")
        L.append("")

    # Trust boundary
    L.append(tag("## Trust Boundary", EC.DEMONSTRATED))
    L.append(f"- Reachable trusted assets: "
             f"{', '.join(trust.get('reachable_trusted_assets',[])) or 'none'}")
    L.append(f"- Privilege transitions: {len(trust.get('transitions',[]))}")
    for v in trust.get("violations", []):
        L.append(f"  - VIOLATION: {v}")
    for ex in trust.get("excessive_privilege", []):
        L.append(f"  - Excessive privilege: {ex['component']} reaches "
                 f"{', '.join(ex['reaches'])}")
    L.append("")

    # Blast radius
    L.append(tag("## Blast Radius", from_state(br.get("basis","hypothesized")) if br.get("basis") in ("demonstrated","hypothesized") else EC.ESTIMATED))
    L.append(f"- {br.get('reason','')}")
    if br.get("secrets"):
        L.append(f"- Secrets reachable: {', '.join(br['secrets'])}")
    L.append("")

    # Coverage. ADR 0027: the runtime-tested figure is the measured claim; the
    # graph-derived taxonomy counts mix provenance and are contextual only.
    tc = coverage.get("taxonomy_coverage")
    prov = coverage.get("coverage_provenance") or {}
    rt_ratio = coverage.get("runtime_coverage_ratio")
    if tc or prov:
        L.append("## Coverage")
        # 1. The measured claim: a payload was actually sent for these categories.
        if prov:
            universe = prov.get("universe") or 0
            runtime = len(prov.get("runtime_tested") or [])
            ratio = rt_ratio if rt_ratio is not None else (
                round(runtime / universe, 2) if universe else 0.0)
            L.append(tag(f"- **OWASP runtime-tested: {runtime}/{universe} "
                         f"({ratio})**", EC.MEASURED))
            L.append(f"  - runtime-tested: "
                     f"{', '.join(prov.get('runtime_tested') or []) or 'none'}")
            L.append(f"  - configuration-review only: "
                     f"{', '.join(prov.get('config_review_only') or []) or 'none'}")
            L.append(f"  - questionnaire only: "
                     f"{', '.join(prov.get('questionnaire_only') or []) or 'none'}")
            L.append(f"  - not tested: "
                     f"{', '.join(prov.get('not_tested') or []) or 'none'}")
            L.append("")
        # 2. Context, not a measurement: these counts include findings obtained without
        #    sending a payload, so the section is not tagged Measured.
        if tc:
            L.append(tag("### Coverage (graph-derived) — contextual, mixed provenance",
                         EC.OBSERVED))
            for fam, c in tc.items():
                L.append(f"- **{fam}**: {c['tested']}/{c['universe']} categories with a "
                         f"mapped finding (demonstrated {len(c['demonstrated'])}, "
                         f"hypothesized {len(c['hypothesized'])}, not-assessable "
                         f"{len(c['not_assessable'])})")
            caveat = coverage.get("coverage_ratio_caveat")
            if caveat:
                L.append(f"- *{caveat}*")
            L.append("")

    # Prioritized remediation
    L.append(tag("## (impact figures below are graph-derived estimates)", EC.ESTIMATED))
    L.append(rem_mod.to_markdown(recs))
    L.append("")

    # Evidence ledger
    ev_nodes = g.nodes(NodeType.EVIDENCE)
    if ev_nodes:
        L.append(tag("## Evidence Ledger (chain-of-custody hashes)", EC.VERIFIED))
        for e in ev_nodes[:12]:
            L.append(f"- {e.id.split(':',1)[1][:16]} ({e.label})")
    return "\n".join(L)
