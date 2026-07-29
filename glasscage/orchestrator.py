# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Multi-tool orchestrator (GLASSCAGE Stage C).

Status: Implemented (orchestration) / Roadmap (external result normalization).

Runs a set of framework adapters against one target and produces a cross-tool
comparison: availability, detection counts, timing, per-OWASP breakdown. This is
how GLASSCAGE positions itself as an orchestration + analysis platform rather than
another standalone scanner. Unavailable tools are reported honestly, never faked.
"""

from __future__ import annotations

from collections import Counter

from .adapters import REGISTRY


def orchestrate(target, tools=None, options=None) -> dict:
    tools = tools or ["native"]
    options = options or {}
    results = []
    for key in tools:
        cls = REGISTRY.get(key)
        if cls is None:
            results.append({"tool": key, "available": False,
                            "error": "unknown adapter"})
            continue
        adapter = cls()
        res = adapter.run(target, options.get(key))
        by_owasp = Counter(getattr(f, "owasp_id", "?") for f in res.findings)
        results.append({
            "tool": key, "adapter_name": res.tool,
            "status": getattr(adapter, "status", "?"),
            "available": res.available, "version": res.version,
            "detections": len(res.findings), "elapsed_ms": res.elapsed_ms,
            "by_owasp": dict(by_owasp), "error": res.error,
        })
    return {"target": getattr(target, "name", "target"), "tools": results}


def to_markdown(report: dict) -> str:
    L = ["# GLASSCAGE Multi-Tool Orchestration", f"Target: {report['target']}", "",
         "| Tool | Status | Available | Detections | Time(ms) | Note |",
         "|---|---|---|---|---|---|"]
    for r in report["tools"]:
        L.append(f"| {r['tool']} | {r.get('status','?')} | {r['available']} | "
                 f"{r.get('detections','-')} | {r.get('elapsed_ms','-')} | "
                 f"{(r.get('error') or 'ok')[:50]} |")
    return "\n".join(L)
