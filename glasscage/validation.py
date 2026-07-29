# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Cross-framework validation harness (GLASSCAGE Stage D4).

Status: Implemented (mechanism) / honest availability gating.

Runs multiple framework adapters against the SAME target and compares them:
detection overlap, unique findings, pairwise agreement (Jaccard on OWASP-category
sets), runtime, and native reproducibility. Tools neither installed nor supplied
an output file are reported **Not Tested** - never fabricated.
"""

from __future__ import annotations

from itertools import combinations

from .adapters import REGISTRY


def _run_tool(key, target, from_file=None):
    cls = REGISTRY.get(key)
    if cls is None:
        return {"tool": key, "mode": "unknown", "available": False,
                "detections": 0, "categories": [], "error": "unknown adapter",
                "_category_set": set()}
    adapter = cls()
    opts = {"from_file": from_file} if from_file else None
    res = adapter.run(target, opts)
    cats = sorted({getattr(f, "owasp_id", "?") for f in res.findings})
    mode = ("from_file" if from_file else ("live" if res.available and not res.error
                                           else "not_tested"))
    return {"tool": key, "mode": mode, "status": getattr(adapter, "status", "?"),
            "available": res.available, "version": res.version,
            "detections": len(res.findings), "categories": cats,
            "elapsed_ms": res.elapsed_ms, "error": res.error,
            "_category_set": set(cats)}


def validate(target, tools, adapter_files=None, native_reproducibility=True) -> dict:
    adapter_files = adapter_files or {}
    runs = [_run_tool(t, target, adapter_files.get(t)) for t in tools]
    ran = [r for r in runs if r["detections"] > 0]

    overlap = sorted(set.intersection(*[r["_category_set"] for r in ran])) if len(ran) >= 2 else []
    union = sorted(set.union(*[r["_category_set"] for r in ran])) if ran else []
    for r in ran:
        others = set.union(*[o["_category_set"] for o in ran if o is not r]) if len(ran) > 1 else set()
        r["unique_categories"] = sorted(r["_category_set"] - others)

    agreement = []
    for a, b in combinations(ran, 2):
        inter = a["_category_set"] & b["_category_set"]
        uni = a["_category_set"] | b["_category_set"]
        agreement.append({"pair": f"{a['tool']}~{b['tool']}",
                          "jaccard": round(len(inter) / len(uni), 3) if uni else 0.0,
                          "shared": sorted(inter)})

    repro = None
    if native_reproducibility and "native" in tools:
        r1 = _run_tool("native", target)
        r2 = _run_tool("native", target)
        s1, s2 = r1["_category_set"], r2["_category_set"]
        repro = {"category_agreement": round(len(s1 & s2) / len(s1 | s2), 3) if (s1 | s2) else 1.0,
                 "run1_detections": r1["detections"], "run2_detections": r2["detections"],
                 "note": "two identical native runs; 1.0 == fully reproducible"}

    for r in runs:
        r.pop("_category_set", None)
    not_tested = [r["tool"] for r in runs if r["mode"] == "not_tested"]
    return {
        "target": getattr(target, "name", "target"),
        "tools_requested": tools, "runs": runs,
        "detection_overlap": overlap, "union_categories": union,
        "pairwise_agreement": agreement, "native_reproducibility": repro,
        "not_tested": not_tested,
        "disclaimer": ("from_file tools use provided native output (real or "
                       "representative fixture); not_tested tools were neither installed "
                       "nor supplied output and produced NO synthetic data."),
    }


def to_markdown(v: dict) -> str:
    L = ["# GLASSCAGE Cross-Framework Validation", f"Target: {v['target']}", "",
         "| Tool | Mode | Status | Detections | Categories | Time(ms) |",
         "|---|---|---|---|---|---|"]
    for r in v["runs"]:
        L.append(f"| {r['tool']} | {r['mode']} | {r.get('status','?')} | "
                 f"{r['detections']} | {','.join(r['categories']) or '-'} | {r.get('elapsed_ms','-')} |")
    L += ["", f"**Detection overlap (all tools):** {', '.join(v['detection_overlap']) or 'n/a'}",
          f"**Union of categories:** {', '.join(v['union_categories']) or 'n/a'}",
          f"**Not tested (honest):** {', '.join(v['not_tested']) or 'none'}", ""]
    if v["pairwise_agreement"]:
        L.append("## Pairwise agreement (Jaccard)")
        for a in v["pairwise_agreement"]:
            L.append(f"- {a['pair']}: {a['jaccard']} (shared: {', '.join(a['shared']) or 'none'})")
    if v["native_reproducibility"]:
        rp = v["native_reproducibility"]
        L.append(f"\n## Native reproducibility\n- category agreement across 2 runs: "
                 f"{rp['category_agreement']} ({rp['note']})")
    L.append(f"\n_{v['disclaimer']}_")
    return "\n".join(L)


def paper_report(bench: dict, val: dict, corpus_meta: dict | None = None) -> str:
    """D5: paper-quality validation report combining benchmark + cross-tool validation."""
    o = bench["overall"]
    L = ["# GLASSCAGE Validation Report", "",
         "_Auto-generated. Reproducible: rerun `python cli.py --validate --harness "
         "--out <base>`. Every number below comes from an actual run in this "
         "environment; unavailable external tools are marked Not Tested, never faked._",
         "",
         "## 1. Methodology",
         "GLASSCAGE detectors are measured against a hand-labeled corpus whose ground "
         "truth the detectors never saw (detector-level FP/FN). Separately, framework "
         "adapters are run against one shared target and compared for detection overlap, "
         "unique findings, and agreement. Statistics use the Wilson score interval "
         "(95%) for proportions, appropriate at small N and extreme rates.",
         "",
         "## 2. Assumptions & limitations",
         "- Corpus is small and Experimental; metrics are indicative, not population-level.",
         "- The exact-match canary oracle is intentionally imperfect; the corpus includes "
         "cases it is expected to miss (documented FNs) as honest evidence of its limits.",
         "- Trace/tier-gated categories (planner, memory, MCP, retrieval, etc.) are NOT "
         "text-measurable and are excluded from detector metrics.",
         "- External-tool findings shown here are parsed from provided native output "
         "(real or representative fixture). Live execution of garak/PyRIT/etc. requires "
         "them installed; where absent they are Not Tested.",
         "",
         "## 3. Benchmark corpus",
         f"- Name: {bench['corpus']}",
         f"- Total cases: {bench['total_cases']} · text-measurable: {bench['text_measurable']} "
         f"· tier-gated excluded: {bench['tier_gated_excluded']} · categories: {bench['attack_categories']}",
         f"- Status: {bench['status']}",
         "",
         "## 4. Detector results (95% Wilson CIs)  [Measured — Experimental corpus]",
         f"- **Precision** {o['precision']} CI{o['precision_ci']}",
         f"- **Recall** {o['recall']} CI{o['recall_ci']}",
         f"- **F1** {o['f1']} · **Accuracy** {o['accuracy']} CI{o['accuracy_ci']}",
         f"- Confusion: TP {o['tp']} · FP {o['fp']} · FN {o['fn']} · TN {o['tn']}",
         f"- Reproducibility: {bench['reproducibility']} (deterministic detectors) · "
         f"time {bench['elapsed_ms']} ms",
         ""]
    L.append("### Documented misclassifications")
    for e in bench["errors"]:
        L.append(f"- [{e['type'].upper()}] {e['id']} ({e['detector']})"
                 + (f" — {e['note']}" if e.get("note") else ""))
    L += ["", "## 5. Cross-framework validation  [external tools: Pending External Validation unless run]"]
    L.append(to_markdown(val).split("\n", 1)[1])  # drop duplicate H1
    L += ["", "## 6. Statistical methods",
          "Wilson score interval for binomial proportions (precision/recall/accuracy); "
          "Jaccard index for cross-tool category agreement; modal-outcome agreement for "
          "reproducibility. All inputs are logged in the accompanying JSON for replay.",
          "",
          "## 7. Maturity labels",
          "- **Implemented:** TAL tiers L0–L2, statistics engine, detector benchmark, "
          "taxonomy crosswalk, native+fake adapters, garak/promptfoo parsers, orchestration, "
          "validation harness.",
          "- **Partial:** live execution of garak/promptfoo (parser tested, live run needs tool).",
          "- **Experimental:** PyRIT/DeepTeam/FuzzyAI parsers (representative fixtures; live "
          "compatibility unverified); corpus size.",
          "- **Roadmap:** L3 tier, live external orchestration at scale, AI Attack Knowledge Graph."]
    return "\n".join(L)
