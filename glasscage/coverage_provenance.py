# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Coverage provenance (release-quality reporting fix, additive).

Classifies each canonical OWASP-LLM category by HOW its evidence was obtained, so the
report can state an honest *runtime* coverage figure alongside the legacy
`coverage_ratio` (which counts any mapped finding as "tested" regardless of provenance).

This is a reporting helper only. It introduces no new node/edge types and does not
change the graph or any analysis. Provenance is derived from the probe registry:

  runtime        - at least one probe for the category sends a payload to the target
  config_review  - evidence comes only from static manifest/config parsing (e.g. MCP)
  questionnaire  - evidence comes only from a static questionnaire (no target contact)
  not_tested     - no probe exists for the category
"""
from __future__ import annotations

import inspect

from .coverage import CANONICAL
from .probes import REGISTRY

_RUNTIME = "runtime"
_CONFIG = "config_review"
_QUEST = "questionnaire"
_NONE = "not_tested"


def _probe_provenance(probe) -> str:
    """Best-effort provenance for a single probe, from its run() source."""
    try:
        src = inspect.getsource(probe.run)
    except (OSError, TypeError):
        src = ""
    if "target.send" in src:
        return _RUNTIME
    name = probe.__class__.__name__.lower()
    if "manifest" in src.lower() or "mcp" in name:
        return _CONFIG
    return _QUEST


def category_provenance() -> dict[str, str]:
    """Map each canonical category to its strongest provenance.

    Strength order: runtime > config_review > questionnaire > not_tested.
    """
    order = {_RUNTIME: 3, _CONFIG: 2, _QUEST: 1, _NONE: 0}
    out: dict[str, str] = {}
    for cat in sorted(CANONICAL):
        probes = [p for p in REGISTRY if getattr(p, "owasp_id", None) == cat]
        if not probes:
            out[cat] = _NONE
            continue
        best = max((_probe_provenance(p) for p in probes), key=lambda p: order[p])
        out[cat] = best
    return out


def summarize() -> dict:
    """Provenance breakdown + the honest runtime coverage ratio."""
    prov = category_provenance()
    buckets: dict[str, list[str]] = {_RUNTIME: [], _CONFIG: [], _QUEST: [], _NONE: []}
    for cat, p in prov.items():
        buckets[p].append(cat)
    universe = len(prov)
    runtime = len(buckets[_RUNTIME])
    return {
        "universe": universe,
        "runtime_tested": sorted(buckets[_RUNTIME]),
        "config_review_only": sorted(buckets[_CONFIG]),
        "questionnaire_only": sorted(buckets[_QUEST]),
        "not_tested": sorted(buckets[_NONE]),
        "runtime_coverage_ratio": round(runtime / universe, 2) if universe else 0.0,
    }
