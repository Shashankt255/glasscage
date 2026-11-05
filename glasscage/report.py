# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Report generator: interactive HTML app + Markdown + JSON.

- Markdown: pentest-style deliverable (exec summary, recon, per-finding
  remediation, verification, reproduction steps, references, Mermaid graph).
- HTML: a self-contained interactive single-page app with a severity dashboard,
  live filtering/search, collapsible findings, per-finding tabs
  (Evidence / Remediation / Verify / Reproduce / References), and embedded
  screenshot-style evidence cards.
- JSON: machine-readable, with the inline evidence SVG stripped for size.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .models import Finding, ReconResult, Status

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (0 if f.status is Status.VULNERABLE else
                       1 if f.status is Status.INCONCLUSIVE else 2,
                       _SEV_ORDER[f.severity.value]),
    )


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def to_markdown(target_name: str, recon: ReconResult, findings: list[Finding],
                summary: dict, graph: dict | None = None,
                coverage: dict | None = None, architecture: dict | None = None,
                trust: dict | None = None, chains: list | None = None,
                posture: dict | None = None) -> str:
    from . import chain as chain_mod
    from . import coverage as coverage_mod
    from . import graph as graph_mod
    from . import trust as trust_mod
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L: list[str] = []
    L.append(f"# GLASSCAGE AI Security Assessment: {target_name}")
    L.append(f"_Generated {ts}_\n")
    L.append("> This is a force-multiplier for a skilled tester, not an assurance "
             "certificate. Findings require human confirmation via the reproduction "
             "steps before action.\n")

    L.append("## Executive Summary")
    L.append(f"- Assessment tier: **{summary.get('target_tier','L0')}** · trials/probe: "
             f"{summary.get('trials',1)} · NOT ASSESSABLE at this tier: "
             f"{summary.get('not_assessable_count',0)}")
    if posture:
        L.append(f"- **Indicative Risk Index: {posture['risk_index']}/100** "
                 f"(band {posture.get('band','?')}) — uncalibrated heuristic [Estimated], "
                 f"not a statistical measure")
    L.append(f"- Posture: **{summary.get('posture','n/a')}**  (indicative grade {summary['grade']})")
    L.append(f"- Impact-confirmed: **{summary.get('impact_confirmed_count',0)}** | "
             f"Steerability-only: **{summary.get('steerability_count',0)}** | "
             f"Needs review: {summary['inconclusive_count']}")
    L.append(f"- Blast radius x{summary['blast_radius_multiplier']} — {summary.get('blast_radius_reason','')}")
    L.append(f"\n_{summary.get('caveat','')}_\n")

    if posture:
        L.append("## Risk Model (dynamic, auditable)")
        for k, v in posture["factors"].items():
            L.append(f"- {k}: {v} (weight {posture['weights'][k]})")
        L.append("")

    if chains:
        L.append("## Exploit Chains")
        L.append("Multi-stage attack paths composed from this run's findings + trust model.\n")
        for c in chains:
            L.append(f"### [{c['severity'].upper()}] {c['title']}  (likelihood {c['likelihood']})")
            L.append(f"- ATLAS: {c['atlas']}")
            L.append(f"- Path: {c['narrative']}")
            L.append(f"- Evidenced links: {c['evidenced_links']}/{c['total_links']}")
            L.append("\n```mermaid")
            L.append(chain_mod.to_mermaid(c))
            L.append("```\n")

    if trust and trust.get("nodes"):
        L.append("## Trust Boundaries")
        L.append(trust_mod.summary_line(trust))
        if trust.get("violations"):
            L.append("\n**Boundary violations:**")
            for v in trust["violations"]:
                L.append(f"- {v}")
        L.append("\n```mermaid")
        L.append(trust_mod.to_mermaid(trust))
        L.append("```\n")

    if coverage:
        L.append("## Coverage")
        L.append(coverage_mod.statement(coverage) + "\n")

    if architecture:
        L.append("## Architecture (assessed, defense-in-depth)")
        L.append(f"- Controls present: {architecture['present']} | "
                 f"missing: {architecture['missing']} | "
                 f"unverified: {architecture['unverified']} of {architecture['controls_total']}\n")

    if graph and graph.get("nodes") and len(graph["nodes"]) > 1:
        L.append("## Attack-Surface Graph")
        L.append(graph_mod.summary_line(graph))
        L.append("\n```mermaid")
        L.append(graph_mod.to_mermaid(graph))
        L.append("```\n")

    L.append("## Recon")
    L.append(f"- Reachable: {recon.reachable}")
    L.append(f"- Model hints: {', '.join(recon.model_hints) or 'none'}")
    L.append(f"- Guardrail signals: {', '.join(recon.guardrail_signals) or 'none detected'}")
    L.append(f"- Tool surface: {', '.join(recon.tool_surface) or 'none self-reported'}\n")

    L.append("## Findings")
    for i, f in enumerate(_sorted_findings(findings), 1):
        atlas = f" | ATLAS: {f.atlas_id}" if f.atlas_id else ""
        L.append(f"### {i}. [{f.owasp_id}] {f.title}")
        L.append(f"- Status: **{f.status.value.upper()}** | Dimension: **{f.dimension}** "
                 f"| Severity: **{f.severity.value}** | Confidence: {f.confidence:.0%}"
                 f" | Category: {f.category}{atlas}")
        if f.cvss_vector:
            L.append(f"- Score: {f.cvss_score}/10 — `{f.cvss_vector}`")
        if f.evidence_hash:
            L.append(f"- Evidence integrity (sha256): `{f.evidence_hash[:32]}...` @ {f.timestamp}")
        if f.prompt:
            L.append(f"- Probe input: `{f.prompt[:200]}`")
        if f.response_excerpt:
            L.append(f"- Evidence: `{f.response_excerpt[:300]}`")
        if f.evidence_path:
            L.append(f"- Evidence card: `{f.evidence_path}`")
        if f.turns:
            L.append("- Multi-turn trail:")
            for t in f.turns:
                L.append(f"  - turn {t['turn']}: sent `{t['sent'][:80]}` -> `{t['got'][:80]}`")
        if f.status in (Status.VULNERABLE, Status.INCONCLUSIVE):
            L.append("- Remediation:")
            for s in f.remediation:
                L.append(f"  - {s}")
            if f.reproduction_steps:
                L.append("- Steps to reproduce (manual re-validation):")
                for n, s in enumerate(f.reproduction_steps, 1):
                    if "\n" in s:
                        L.append(f"  {n}. Request:\n\n```\n{s}\n```")
                    else:
                        L.append(f"  {n}. {s}")
            if f.verification_steps:
                L.append("- Verify / rule out false positive:")
                for s in f.verification_steps:
                    L.append(f"  - {s}")
        if f.reference_links:
            refs = "; ".join(f"[{r['label']}]({r['url']})" for r in f.reference_links)
            L.append(f"- References: {refs}")
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Interactive HTML
# --------------------------------------------------------------------------- #
def to_html(target_name: str, recon: ReconResult, findings: list[Finding],
            summary: dict, graph: dict | None = None,
            coverage: dict | None = None, architecture: dict | None = None,
            trust: dict | None = None, chains: list | None = None,
            posture: dict | None = None, narratives=None, story=None) -> str:
    """Render the interactive report. `narratives`/`story` are optional; when absent
    the output is exactly as before (backward compatible)."""
    from . import chain as chain_mod
    from . import coverage as coverage_mod
    from . import graph as graph_mod
    from . import trust as trust_mod

    mermaid = (graph_mod.to_mermaid(graph)
               if graph and graph.get("nodes") and len(graph["nodes"]) > 1 else "")
    graph_summary = graph_mod.summary_line(graph) if mermaid else ""

    # static fragments (so mermaid startOnLoad renders them)
    chains_html = ""
    if chains:
        blocks = []
        for c in chains:
            blocks.append(
                f'<details class="graph" open><summary>[{html.escape(c["severity"].upper())}] '
                f'{html.escape(c["title"])} — likelihood {c["likelihood"]}</summary>'
                f'<div class="meta">ATLAS: {html.escape(c["atlas"])} · '
                f'{c["evidenced_links"]}/{c["total_links"]} links evidenced</div>'
                f'<div class="meta">{html.escape(c["narrative"])}</div>'
                f'<pre class="mermaid">{html.escape(chain_mod.to_mermaid(c))}</pre></details>')
        chains_html = '<h2 style="font-size:18px;margin-top:20px">Exploit Chains</h2>' + "".join(blocks)

    trust_html = ""
    if trust and trust.get("nodes"):
        viol = ""
        if trust.get("violations"):
            viol = "<ul>" + "".join(f"<li style='color:#f87171'>{html.escape(v)}</li>"
                                    for v in trust["violations"]) + "</ul>"
        trust_html = (
            '<h2 style="font-size:18px;margin-top:20px">Trust Boundaries</h2>'
            f'<details class="graph" open><summary>{html.escape(trust_mod.summary_line(trust))}</summary>'
            f'{viol}<pre class="mermaid">{html.escape(trust_mod.to_mermaid(trust))}</pre></details>')

    data = {
        "target": target_name,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": summary,
        "posture": posture or {},
        "coverage": (coverage_mod.statement(coverage) if coverage else ""),
        "architecture": architecture or {},
        "recon": {
            "model_hints": recon.model_hints,
            "tool_surface": recon.tool_surface,
            "guardrail_signals": recon.guardrail_signals,
        },
        "graph_summary": graph_summary,
        "findings": [
            {
                "probe_name": f.probe_name, "title": f.title, "owasp_id": f.owasp_id,
                "atlas_id": f.atlas_id, "category": f.category, "status": f.status.value,
                "severity": f.severity.value, "confidence": f.confidence,
                "dimension": f.dimension, "impact_confirmed": f.impact_confirmed,
                "cvss_vector": f.cvss_vector, "cvss_score": f.cvss_score,
                "evidence_hash": f.evidence_hash, "timestamp": f.timestamp,
                "prompt": f.prompt, "response": f.response_excerpt,
                "remediation": f.remediation, "verification": f.verification_steps,
                "reproduction": f.reproduction_steps, "references": f.reference_links,
                "evidence_svg": f.evidence_svg, "turns": f.turns,
            }
            for f in _sorted_findings(findings)
        ],
    }
    # Reporting layer: narrative + story (all model-derived text is escaped).
    story_html, narr_html = "", ""
    if story is not None:
        parts = ['<section class="panel"><h2>Assessment Story</h2>']
        for s in story.sections:
            parts.append(f'<h3>{html.escape(s.title)} '
                         f'<span class="pill">{html.escape(s.evidence_class.value)}</span></h3>')
            parts.append("<ul>" + "".join(
                f"<li>{html.escape(line)}</li>" for line in s.body) + "</ul>")
        parts.append("</section>")
        story_html = "".join(parts)
        data["story"] = story.to_dict()
    if narratives is not None:
        from .aakg import narrative as _n
        parts = ['<section class="panel"><h2>Attack Narratives</h2>'
                 '<p class="meta">Strategic readings of the same graph paths; no path '
                 'is synthesized.</p>']
        for grp in _n.dedupe(narratives):
            m = grp["model"]
            parts.append(f'<h3>{html.escape(", ".join(grp["strategies"]))} '
                         f'<span class="pill">{html.escape(m.evidence_class.value)}</span></h3>')
            if not grp["supported"]:
                parts.append(f'<p>{html.escape(m.reason)}</p>')
                continue
            parts.append("<ol>" + "".join(
                f"<li>{html.escape(t.prose)}<br><span class='meta'>"
                f"{html.escape(t.citation())}</span></li>"
                for t in m.transitions) + "</ol>")
        parts.append("</section>")
        narr_html = "".join(parts)
        data["narratives"] = [_n.to_dict(m) for m in narratives]

    payload = json.dumps(data).replace("</", "<\\/")
    return (_HTML_TEMPLATE
            .replace("%%TITLE%%", html.escape(target_name))
            .replace("%%MERMAID%%", html.escape(mermaid))
            .replace("%%CHAINS%%", story_html + narr_html + chains_html)
            .replace("%%TRUST%%", trust_html)
            .replace("%%DATA%%", payload))


def write_json(path: str, target_name: str, recon: ReconResult,
               findings: list[Finding], summary: dict,
               narratives=None, story=None) -> None:
    """Write machine-readable results.

    `narratives`/`story` are optional (reporting layer). When supplied they are
    serialized alongside findings; omitting them preserves the previous payload
    exactly, so existing consumers keep working.
    """
    def clean(f: Finding) -> dict:
        d = f.to_dict()
        d.pop("evidence_svg", None)  # keep JSON lean; SVG lives in .svg files + HTML
        return d
    payload = {
        "target": target_name,
        "summary": summary,
        "recon": recon.to_dict(),
        "findings": [clean(f) for f in findings],
    }
    if narratives is not None:
        from .aakg import narrative as _n
        payload["narratives"] = [_n.to_dict(m) for m in narratives]
    if story is not None:
        payload["story"] = story.to_dict()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


_HTML_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GLASSCAGE report: %%TITLE%%</title>
<style>
 :root{--bg:#0b1220;--panel:#111a2e;--panel2:#0f1728;--line:#243149;--tx:#e2e8f0;--mut:#93a4c0;--accent:#38bdf8}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
 .wrap{max-width:1040px;margin:0 auto;padding:24px}
 h1{font-size:22px;margin:0 0 2px} .sub{color:var(--mut);margin-bottom:18px;font-size:13px}
 .dash{display:grid;grid-template-columns:auto 1fr;gap:18px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
 .grade{font-size:56px;font-weight:800;line-height:1;text-align:center}
 .grade small{display:block;font-size:12px;color:var(--mut);font-weight:600;margin-top:4px}
 .bars{display:flex;flex-direction:column;gap:6px;justify-content:center}
 .bar{display:grid;grid-template-columns:70px 1fr 30px;align-items:center;gap:8px;font-size:12px}
 .bar .track{height:10px;background:#1e293b;border-radius:6px;overflow:hidden}
 .bar .fill{height:100%}
 .meta{color:var(--mut);font-size:13px;margin-top:8px}
 .controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:14px 0}
 .controls input[type=text]{flex:1;min-width:180px;background:var(--panel2);border:1px solid var(--line);color:var(--tx);border-radius:9px;padding:9px 12px;font-size:14px}
 .chip{border:1px solid var(--line);background:var(--panel2);color:var(--tx);border-radius:999px;padding:6px 12px;font-size:12px;cursor:pointer;user-select:none}
 .chip.off{opacity:.4}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:10px 0;overflow:hidden}
 .chd{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:13px 15px;cursor:pointer}
 .chd:hover{background:#13203a}
 .pill{color:#0b1220;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:800;text-transform:uppercase}
 .oid{color:var(--accent);font-weight:700} .st{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
 .ttl{font-weight:600;flex:1;min-width:180px} .caret{color:var(--mut);transition:transform .15s}
 .card.open .caret{transform:rotate(90deg)}
 .body{display:none;border-top:1px solid var(--line);padding:14px 15px}
 .card.open .body{display:block}
 .tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
 .tab{border:1px solid var(--line);background:var(--panel2);color:var(--mut);border-radius:8px;padding:5px 11px;font-size:12px;cursor:pointer}
 .tab.active{color:var(--tx);border-color:var(--accent)}
 .pane{display:none} .pane.active{display:block}
 ul,ol{margin:6px 0;padding-left:20px} li{margin:4px 0}
 code,pre{background:#0a1120;border:1px solid var(--line);border-radius:8px;color:#cbd5e1}
 code{padding:1px 6px;word-break:break-word} pre{padding:11px;overflow:auto;font-size:12.5px;position:relative;white-space:pre-wrap}
 .copy{position:absolute;top:8px;right:8px;font-size:11px;background:#1e293b;border:1px solid var(--line);color:var(--tx);border-radius:6px;padding:3px 8px;cursor:pointer}
 .refs a{color:var(--accent);font-size:12px} .refs{color:var(--mut)}
 .ev svg{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px}
 .count{color:var(--mut);font-size:13px;margin:6px 2px}
 details.graph{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 15px;margin-bottom:14px}
 details.graph summary{cursor:pointer;font-weight:600}
 .empty{color:var(--mut);text-align:center;padding:26px}
</style></head><body><div class="wrap">
 <h1>GLASSCAGE AI Security Assessment</h1>
 <div class="sub" id="sub"></div>
 <div class="dash">
   <div><div class="grade" id="grade"></div></div>
   <div class="bars" id="bars"></div>
 </div>
 <div class="meta" id="reconmeta"></div>
 <div class="meta" id="posture" style="margin-top:6px"></div>
 <div class="meta" id="coverage" style="margin-top:6px"></div>
 <div class="meta" id="archmeta" style="margin-top:6px"></div>
 <div id="caveat" style="margin-top:10px;padding:10px 12px;border:1px solid #3a2d12;background:#1a1408;border-radius:10px;color:#eab308;font-size:12.5px"></div>
 <details class="graph" id="graphwrap" style="display:none"><summary>Attack-surface blast radius</summary>
   <div class="meta" id="graphsum"></div><pre class="mermaid">%%MERMAID%%</pre></details>
 %%CHAINS%%
 %%TRUST%%

 <div class="controls">
   <input type="text" id="search" placeholder="Search findings, OWASP id, ATLAS id...">
   <span class="chip" data-sev="critical">critical</span>
   <span class="chip" data-sev="high">high</span>
   <span class="chip" data-sev="medium">medium</span>
   <span class="chip" data-sev="low">low</span>
   <span class="chip" data-sev="info">info</span>
   <span class="chip" data-status="passed" id="togglePassed">show passed</span>
 </div>
 <div class="count" id="count"></div>
 <div id="list"></div>
</div>
<script type="module">
 import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
 mermaid.initialize({startOnLoad:true, theme:"dark"});
</script>
<script>
const DATA = %%DATA%%;
const SEVCOLOR={critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#84cc16",info:"#64748b"};
const state={sev:new Set(["critical","high","medium","low","info"]),showPassed:false,q:""};

function esc(s){return (s==null?"":""+s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

function header(){
  const s=DATA.summary;
  document.getElementById("sub").textContent=DATA.target+" \u00b7 "+DATA.generated;
  const pscore=(DATA.posture&&DATA.posture.posture_score!=null)?DATA.posture.posture_score:null;
  document.getElementById("grade").innerHTML=(pscore!=null?pscore:esc(s.grade))+"<small>"+(pscore!=null?"posture /100 \u00b7 grade "+esc(s.grade)+" \u00b7 risk "+DATA.posture.risk_index:"risk "+s.risk_score)+"</small>";
  const counts=s.counts_by_severity||{};
  const bars=["critical","high","medium","low"].map(function(k){
    const n=counts[k]||0; const w=Math.min(100,n*22+(n?12:0));
    return '<div class="bar"><span>'+k+'</span><div class="track"><div class="fill" style="width:'+w+'%;background:'+SEVCOLOR[k]+'"></div></div><span>'+n+'</span></div>';
  }).join("");
  document.getElementById("bars").innerHTML=bars +
    '<div class="meta">'+s.vulnerable_count+' confirmed \u00b7 '+s.inconclusive_count+' to review \u00b7 blast-radius x'+s.blast_radius_multiplier+'</div>';
  const r=DATA.recon;
  document.getElementById("reconmeta").innerHTML=
    "Model: <b>"+esc(r.model_hints.join(", ")||"unknown")+"</b> \u00b7 Tools: <b>"+esc(r.tool_surface.join(", ")||"none")+"</b> \u00b7 Guardrails: <b>"+esc(r.guardrail_signals.join(", ")||"none detected")+"</b>";
  if(DATA.graph_summary){document.getElementById("graphwrap").style.display="";document.getElementById("graphsum").textContent=DATA.graph_summary;}
  document.getElementById("posture").innerHTML="Posture: <b>"+esc(s.posture||"n/a")+"</b> \u00b7 worst finding "+(s.worst_finding_score||0)+"/10 \u00b7 impact-confirmed <b>"+(s.impact_confirmed_count||0)+"</b>, steerability-only "+(s.steerability_count||0);
  if(DATA.coverage) document.getElementById("coverage").textContent="Coverage: "+DATA.coverage;
  const a=DATA.architecture;
  if(a&&a.controls_total) document.getElementById("archmeta").innerHTML="Architecture (assessed): <b>"+a.present+"</b> present \u00b7 <b>"+a.missing+"</b> missing \u00b7 "+a.unverified+" unverified of "+a.controls_total;
  if(s.caveat) document.getElementById("caveat").textContent="\u26a0 "+s.caveat;
}

function tabs(f,idx){
  const panes=[];
  if(f.evidence_svg) panes.push(["Evidence",'<div class="ev">'+f.evidence_svg+'</div>']);
  if(f.remediation&&f.remediation.length) panes.push(["Remediation","<ul>"+f.remediation.map(function(x){return "<li>"+esc(x)+"</li>";}).join("")+"</ul>"]);
  if(f.reproduction&&f.reproduction.length){
    const items=f.reproduction.map(function(x){return x.indexOf("\n")>=0
        ? '<li><pre><button class="copy">copy</button>'+esc(x)+'</pre></li>'
        : "<li>"+esc(x)+"</li>";}).join("");
    panes.push(["Reproduce","<ol>"+items+"</ol>"]);
  }
  if(f.verification&&f.verification.length) panes.push(["Verify (false-positive check)","<ul>"+f.verification.map(function(x){return "<li>"+esc(x)+"</li>";}).join("")+"</ul>"]);
  if(f.references&&f.references.length) panes.push(["References",'<div class="refs">'+f.references.map(function(r){return '<a href="'+esc(r.url)+'" target="_blank" rel="noopener">'+esc(r.label)+"</a>";}).join(" \u00b7 ")+"</div>"]);
  const btns=panes.map(function(p,i){return '<div class="tab '+(i===0?"active":"")+'" data-t="'+idx+"-"+i+'">'+esc(p[0])+"</div>";}).join("");
  const bodies=panes.map(function(p,i){return '<div class="pane '+(i===0?"active":"")+'" id="pane-'+idx+"-"+i+'">'+p[1]+"</div>";}).join("");
  return '<div class="tabs">'+btns+"</div>"+bodies;
}

function render(){
  const list=document.getElementById("list"); list.innerHTML="";
  let shown=0;
  DATA.findings.forEach(function(f,idx){
    if(f.status==="passed" && !state.showPassed) return;
    if(f.status!=="passed" && !state.sev.has(f.severity)) return;
    if(state.q){
      const hay=(f.title+" "+f.owasp_id+" "+f.atlas_id+" "+f.category+" "+f.probe_name).toLowerCase();
      if(hay.indexOf(state.q)<0) return;
    }
    shown++;
    const c=SEVCOLOR[f.severity];
    const card=document.createElement("div"); card.className="card";
    card.innerHTML=
      '<div class="chd">'+
        '<span class="pill" style="background:'+c+'">'+esc(f.severity)+"</span>"+
        '<span class="oid">'+esc(f.owasp_id)+"</span>"+
        (f.dimension&&f.dimension!=="informational"?'<span class="st" style="color:'+(f.dimension==="impact"?"#f87171":"#fbbf24")+'">'+esc(f.dimension)+"</span>":"")+
        (f.cvss_score?'<span class="st">'+f.cvss_score+"/10</span>":"")+
        (f.atlas_id?'<span class="st">'+esc(f.atlas_id)+"</span>":"")+
        '<span class="st">'+esc(f.status)+"</span>"+
        '<span class="ttl">'+esc(f.title)+"</span>"+
        '<span class="caret">\u25b8</span>'+
      "</div>"+
      '<div class="body">'+tabs(f,idx)+"</div>";
    card.querySelector(".chd").addEventListener("click",function(){card.classList.toggle("open");});
    list.appendChild(card);
  });
  document.getElementById("count").textContent=shown+" finding(s) shown";
  if(!shown) list.innerHTML='<div class="empty">No findings match the current filters.</div>';
  list.querySelectorAll(".tab").forEach(function(t){t.addEventListener("click",function(e){
    e.stopPropagation();
    const card=t.closest(".card");
    card.querySelectorAll(".tab").forEach(function(x){x.classList.remove("active");});
    card.querySelectorAll(".pane").forEach(function(x){x.classList.remove("active");});
    t.classList.add("active");
    card.querySelector("#pane-"+t.dataset.t).classList.add("active");
  });});
  list.querySelectorAll(".copy").forEach(function(b){b.addEventListener("click",function(e){
    e.stopPropagation();
    const pre=b.parentElement; const txt=pre.textContent.replace(/^copy/,"");
    if(navigator.clipboard) navigator.clipboard.writeText(txt.trim());
    b.textContent="copied"; setTimeout(function(){b.textContent="copy";},1200);
  });});
}

document.querySelectorAll(".chip[data-sev]").forEach(function(ch){ch.addEventListener("click",function(){
  const s=ch.dataset.sev;
  if(state.sev.has(s)){state.sev.delete(s);ch.classList.add("off");}
  else{state.sev.add(s);ch.classList.remove("off");}
  render();
});});
const tp=document.getElementById("togglePassed"); tp.classList.add("off");
tp.addEventListener("click",function(){state.showPassed=!state.showPassed;tp.classList.toggle("off",!state.showPassed);tp.textContent=state.showPassed?"hide passed":"show passed";render();});
document.getElementById("search").addEventListener("input",function(e){state.q=e.target.value.toLowerCase();render();});

header(); render();
</script></body></html>"""
