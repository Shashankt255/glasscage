# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Audience views over the Narrative/Story models (GLASSCAGE reporting layer).

Status: Implemented (renderer only).

Five lenses on the SAME underlying models (`narrative.NarrativeModel`,
`story.StoryModel`). No view performs analysis or reaches past those models into new
computation; they select and phrase what is already there, and every view preserves the
evidence classification of what it shows.

Honest limitation: the Incident Response view's "Indicators" are GLASSCAGE's own probe
markers and evidence hashes. GLASSCAGE does not observe network/host telemetry, so it
cannot emit network IOCs; that is stated in the view rather than faked.
"""

from __future__ import annotations

from ..evidence_confidence import EvidenceClass as EC
from . import narrative as narr_mod
from .types import NodeType

AUDIENCES = ("executive", "security", "developer", "incident_response", "compliance")


def _sec(story, key):
    s = story.section(key)
    return s.body if s else []


def _cls(story, key, default=EC.HYPOTHESIZED):
    s = story.section(key)
    return s.evidence_class if s else default


# --------------------------------------------------------------------------- #
def executive(story, narratives) -> str:
    top = next((n for n in narratives if n.strategy == "highest_impact"), None)
    L = ["### Executive View", "",
         "_Business-language summary. Confidence labels are shown so you know what is "
         "proven versus suspected._", ""]
    L.append("**Risk summary**")
    L += [f"- {b}" if not b.startswith(("-", "*", "**")) else b
          for b in _sec(story, "findings")[:3]]
    L.append("- Overall rating: see the Indicative Risk Index — an **uncalibrated "
             "heuristic [Estimated]**, useful for prioritization, not an absolute "
             "measure of risk.")
    L.append("")
    L.append(f"**What an attacker could reach**  [{_cls(story,'business_impact').value}]")
    L += _sec(story, "business_impact")
    L.append("")
    if top is not None and top.supported:
        L.append(f"**The most consequential scenario**  [{top.evidence_class.value}]")
        L.append(f"- {len(top.transitions)} step(s) from an ordinary user to "
                 f"**{top.terminal_label}**.")
        L.append(f"- Status: **{top.state}** — "
                 + ("observed on the target." if top.state == "demonstrated"
                    else "structurally reachable but NOT proven on this target; treat "
                         "as a lead to confirm."))
    else:
        L.append("**The most consequential scenario**  [Not Supported by Current Evidence]")
        L.append("- Not demonstrated. No qualifying path exists in the evidence graph.")
    L.append("")
    L.append(f"**Recommended actions**  [{_cls(story,'remediation').value}]")
    L += _sec(story, "remediation")[:6] or ["- None identified from graph evidence."]
    return "\n".join(L)


def security(story, narratives) -> str:
    L = ["### Security Team View", "",
         "_Full attack chain with graph citations and framework mappings._", ""]
    for n in narratives:
        L.append(narr_mod.to_markdown(n))
        L.append("")
    L.append(f"**Trust boundary crossings**  [{_cls(story,'trust').value}]")
    L += _sec(story, "trust")
    L.append("")
    L.append(f"**Evidence**  [{_cls(story,'evidence').value}]")
    L += _sec(story, "evidence")
    return "\n".join(L)


def developer(story, narratives, g=None) -> str:
    L = ["### Developer View", "",
         "_Root cause, affected components, and how to verify a fix._", ""]
    L.append(f"**Root cause**  [{_cls(story,'root_cause').value}]")
    L += _sec(story, "root_cause")
    L.append("")
    # affected components: nodes on the highest-impact narrative (already selected)
    top = next((n for n in narratives if n.strategy == "highest_impact"), None)
    L.append("**Affected components**")
    if top is not None and top.supported:
        seen, comps = set(), []
        for t in top.transitions:
            for nid in (t.src_id, t.dst_id):
                if nid not in seen:
                    seen.add(nid)
                    comps.append(nid)
        for c in comps:
            L.append(f"- `{c}`")
        L.append("")
        L.append(f"**Why exploitation succeeded (per hop)**  "
                 f"[{top.evidence_class.value}]")
        for t in top.transitions:
            why = (t.provenance or "structural relationship recorded in the graph")
            L.append(f"- `{t.edge_id}` — {why} ({t.state})")
            if t.state != "demonstrated":
                L.append("  - NOTE: this hop is not demonstrated; do not treat it as a "
                         "confirmed defect without manual testing.")
    else:
        L.append("- Not demonstrated. No qualifying path in the graph.")
    L.append("")
    L.append("**Configuration guidance**  [Estimated]")
    L += _sec(story, "remediation")[:6] or ["- None derivable from graph evidence."]
    L.append("")
    L.append(f"**Verification steps**  [{_cls(story,'verification', EC.VERIFIED).value}]")
    L += _sec(story, "verification")
    return "\n".join(L)


def incident_response(story, narratives, g=None) -> str:
    L = ["### Incident Response View", "",
         "_Timeline, markers, reachability and containment order._", ""]
    # Timeline from evidence/finding timestamps already in the graph
    L.append("**Timeline**  [Verified]")
    rows = []
    if g is not None:
        for f in g.find(NodeType.FINDING):
            if f.timestamp:
                rows.append((f.timestamp, f.id,
                             (f.metadata or {}).get("status", "?")))
        rows.sort()
    if rows:
        for ts, fid, st in rows[:8]:
            L.append(f"- `{ts}` — `{fid}` ({st})")
    else:
        L.append("- Not demonstrated. No timestamped findings in the graph.")
    L.append("")
    L.append("**Indicators**  [Observed]")
    L.append("- GLASSCAGE observes only its own probe traffic; it has no host or network "
             "telemetry, so **no network IOCs are produced**. The markers below are what "
             "an operator can search for in their own logs:")
    L.append("- GLASSCAGE canary markers (e.g. `GLSSCG-INJECT-OK`) appearing in model "
             "output or downstream logs.")
    ev = g.nodes(NodeType.EVIDENCE) if g is not None else []
    for e in ev[:4]:
        L.append(f"- Evidence hash `{e.id.split(':', 1)[1][:16]}…` (chain of custody)")
    L.append("")
    L.append(f"**Blast radius**  [{_cls(story,'blast').value}]")
    L += _sec(story, "blast")
    L.append("")
    L.append("**Containment priorities**  [Estimated]")
    rem = _sec(story, "remediation")
    if rem:
        L.append("- Ordered by measured graph impact (paths broken, assets removed):")
        L += rem[:4]
    else:
        L.append("- None derivable from graph evidence.")
    return "\n".join(L)


def compliance(story, narratives, g=None) -> str:
    L = ["### Compliance View", "",
         "_Control failures and framework mappings, taken from graph mappings only._", ""]
    L.append(f"**Control failures observed**  [{_cls(story, 'trust').value}]")
    body = [b for b in _sec(story, "trust") if "VIOLATION" in b or "Excessive" in b]
    L += body or ["- Not demonstrated. No trust-boundary violation recorded in the graph."]
    L.append("")
    L.append("**Framework mappings**  [Demonstrated]")
    if g is not None:
        fam = {NodeType.OWASP: "OWASP LLM", NodeType.ATLAS: "MITRE ATLAS",
               NodeType.CWE: "CWE", NodeType.CAPEC: "CAPEC", NodeType.NIST: "NIST AI RMF"}
        for nt, label in fam.items():
            ids = sorted(n.label or n.id for n in g.nodes(nt))
            L.append(f"- {label}: {', '.join(ids) if ids else 'none mapped'}")
    L.append("")
    L.append("**Residual compliance gaps**  [Estimated]")
    L += _sec(story, "residual")
    na = [n for n in (g.find(NodeType.FINDING) if g is not None else [])
          if (n.metadata or {}).get("status") == "not_assessable"]
    if na:
        L.append(f"- {len(na)} control area(s) could not be assessed at this target's "
                 "capability tier. These are **unmeasured, not compliant** — do not "
                 "record them as passing.")
    return "\n".join(L)


_DISPATCH = {"executive": executive, "security": security}


def render(story, narratives, audience: str, g=None) -> str:
    """Render one audience view from the shared models."""
    if audience not in AUDIENCES:
        raise ValueError(f"unknown audience '{audience}'; expected one of {AUDIENCES}")
    if audience == "executive":
        return executive(story, narratives)
    if audience == "security":
        return security(story, narratives)
    if audience == "developer":
        return developer(story, narratives, g)
    if audience == "incident_response":
        return incident_response(story, narratives, g)
    return compliance(story, narratives, g)


def render_all(story, narratives, g=None) -> dict:
    return {a: render(story, narratives, a, g) for a in AUDIENCES}
