# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Benchmark & validation harness (GLASSCAGE Stage C/D3).

Status: Implemented (native detectors) / Experimental (corpus).

Measures GLASSCAGE detectors against a hand-labeled corpus with ground-truth the
detectors never saw. Reports precision/recall/F1/accuracy WITH Wilson confidence
intervals, false-positive/negative lists, per-category breakdown, coverage, and
timing. Trace/tier-gated cases (planner, memory, MCP, etc.) are NOT text-measurable
and are excluded from metrics and reported separately - never scored as pass/fail.

The corpus deliberately includes hard cases the exact-match oracle is expected to
MISS (canary-stripped injections, obfuscated secrets); resulting sub-1.0 recall is
honest evidence of detector limits, not a defect to hide.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from .models import Status
from .probes import CANARY_INJECT, canary_verdict, detect_secret, is_refusal

INDIRECT = "GLSSCG-INDIRECT-OK"
TEXT_DETECTORS = ("injection", "disclosure", "refusal", "indirect")


def _predict(detector: str, text: str) -> bool:
    if detector == "injection":
        return canary_verdict(CANARY_INJECT, text)[0] is Status.VULNERABLE
    if detector == "indirect":
        return canary_verdict(INDIRECT, text)[0] is Status.VULNERABLE
    if detector == "disclosure":
        return detect_secret(text)
    if detector == "refusal":
        return is_refusal(text)
    raise ValueError(f"unknown text detector {detector}")


def _metrics(tp, fp, fn, tn):
    from .stats import wilson
    n_p = tp + fp
    n_r = tp + fn
    n_a = tp + fp + fn + tn
    p, plo, phi = wilson(tp, n_p) if n_p else (0.0, 0.0, 0.0)
    r, rlo, rhi = wilson(tp, n_r) if n_r else (0.0, 0.0, 0.0)
    a, alo, ahi = wilson(tp + tn, n_a) if n_a else (0.0, 0.0, 0.0)
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": p, "precision_ci": [plo, phi],
            "recall": r, "recall_ci": [rlo, rhi],
            "accuracy": a, "accuracy_ci": [alo, ahi],
            "f1": round(f1, 3)}


def run_corpus(corpus_path: str) -> dict:
    with open(corpus_path, encoding="utf-8") as fh:
        corpus = json.load(fh)
    per = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    cat_counts = defaultdict(int)
    errors = []
    tier_gated = 0
    start = time.perf_counter()
    for case in corpus["cases"]:
        det = case["detector"]
        cat_counts[case.get("category", "?")] += 1
        if det not in TEXT_DETECTORS:
            tier_gated += 1
            continue
        pred = _predict(det, case["text"])
        label = bool(case["label"])
        cell = ("tp" if pred and label else "fp" if pred and not label
                else "fn" if (not pred) and label else "tn")
        per[det][cell] += 1
        if cell in ("fp", "fn"):
            errors.append({"id": case["id"], "detector": det, "type": cell,
                           "text": case["text"][:80],
                           "note": case.get("note", "")})
    elapsed = round((time.perf_counter() - start) * 1000, 2)

    by_detector = {d: _metrics(**c) for d, c in per.items()}
    agg = _metrics(
        sum(c["tp"] for c in per.values()), sum(c["fp"] for c in per.values()),
        sum(c["fn"] for c in per.values()), sum(c["tn"] for c in per.values()))
    return {
        "corpus": corpus["meta"].get("name", "corpus"),
        "status": corpus["meta"].get("status", ""),
        "total_cases": len(corpus["cases"]),
        "text_measurable": sum(v["tp"] + v["fp"] + v["fn"] + v["tn"] for v in per.values()),
        "tier_gated_excluded": tier_gated,
        "attack_categories": len(cat_counts),
        "elapsed_ms": elapsed,
        "reproducibility": 1.0,  # deterministic detectors on fixed text
        "overall": agg,
        "by_detector": by_detector,
        "errors": errors,
    }


def to_markdown(report: dict) -> str:
    o = report["overall"]
    L = ["# GLASSCAGE Detector Benchmark", f"_{report['corpus']}_",
         f"> {report['status']}", "",
         f"Total cases: {report['total_cases']} · text-measurable: "
         f"{report['text_measurable']} · tier-gated excluded: {report['tier_gated_excluded']} "
         f"· categories: {report['attack_categories']} · time: {report['elapsed_ms']} ms "
         f"· reproducibility: {report['reproducibility']}", "",
         "## Overall (95% Wilson CIs)  [Measured — on an Experimental corpus]",
         f"- Precision {o['precision']} CI{o['precision_ci']}",
         f"- Recall {o['recall']} CI{o['recall_ci']}",
         f"- F1 {o['f1']} · Accuracy {o['accuracy']} CI{o['accuracy_ci']}",
         f"- TP {o['tp']} · FP {o['fp']} · FN {o['fn']} · TN {o['tn']}",
         "", "## By detector"]
    for d, m in report["by_detector"].items():
        L.append(f"- **{d}**: P {m['precision']} CI{m['precision_ci']} · "
                 f"R {m['recall']} CI{m['recall_ci']} · F1 {m['f1']} "
                 f"(TP{m['tp']} FP{m['fp']} FN{m['fn']} TN{m['tn']})")
    if report["errors"]:
        L.append("\n## Misclassifications (documented)")
        for e in report["errors"]:
            L.append(f"- [{e['type'].upper()}] {e['id']} ({e['detector']}): `{e['text']}`"
                     + (f" — {e['note']}" if e['note'] else ""))
    return "\n".join(L)


def write_report(report: dict, base: str) -> None:
    with open(f"{base}.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(f"{base}.md", "w", encoding="utf-8") as fh:
        fh.write(to_markdown(report))
