# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Coverage provenance (release-quality reporting fix, additive).

Classifies each canonical OWASP-LLM category by HOW its evidence was obtained, so the
report can state an honest *runtime* coverage figure alongside the legacy
`coverage_ratio` (which counts any mapped finding as "tested" regardless of provenance).

This is a reporting helper only. It introduces no new node/edge types and does not
change the graph or any analysis. Provenance is derived from two sources - the probe
registry, and a declaration of assessors that are not registered probes:

  runtime        - at least one probe for the category sends a payload to the target
  config_review  - evidence comes only from static manifest/config parsing (e.g. MCP)
  questionnaire  - evidence comes only from a static questionnaire (no target contact)
  not_tested     - nothing assesses the category

ADR 0016: the registry alone was not enough. `mcp.analyze_manifest` produces findings for
MCP03 and MCP07 without being a registered `Probe` - the engine calls it directly - so
every category it alone covers reported `not_tested`, and the `config_review` bucket this
module documents could never fill. A module whose purpose is an honest coverage figure was
reporting configuration-reviewed categories as untested.
"""
from __future__ import annotations

import inspect

from .coverage import CANONICAL
from .probes import REGISTRY

_RUNTIME = "runtime"
_CONFIG = "config_review"
_QUEST = "questionnaire"
_NONE = "not_tested"


# ADR 0016: categories assessed by something that is not a registered probe. Declared
# here rather than exported from the assessing module, so the reporting layer states its
# own inputs and `mcp.py` stays free of reporting concerns. Drift is caught by test, which
# checks this set both against what `mcp.analyze_manifest` emits and against the category
# literals in `mcp.py` itself - the same trade PR #14 made when `diff.py` composed its own
# subject digest rather than importing `aakg.build`.
#
# `architecture.assess` is likewise not a registered probe, and is deliberately absent:
# every category it covers is already runtime-tested or already questionnaire-covered, so
# declaring it changes no bucket. See ADR 0016 for why that gap is recorded, not filled.
_NON_PROBE_ASSESSORS: dict[str, frozenset[str]] = {
    _CONFIG: frozenset({"MCP03", "MCP07"}),   # mcp.analyze_manifest
}


def _probe_provenance(probe) -> str:
    """Best-effort provenance for a single registered probe, from its run() source.

    The `config_review` branch below stays reachable despite no built-in probe hitting it:
    `plugins.load` appends third-party probes to the same registry, so a plugin whose class
    name or source mentions a manifest is classified without this module knowing about it.
    """
    try:
        src = inspect.getsource(probe.run)
    except (OSError, TypeError):
        src = ""
    # ADR 0012: a non-chat probe drives its surface with an Action instead of sending a
    # prompt. Both are runtime evidence; only the transport differs.
    if "target.send" in src or "target.drive" in src:
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
        found = [_probe_provenance(p) for p in REGISTRY
                 if getattr(p, "owasp_id", None) == cat]
        found += [prov for prov, cats in _NON_PROBE_ASSESSORS.items() if cat in cats]
        # Strongest wins, so a category a probe drives at runtime is never demoted by a
        # declaration here, and a category only a manifest review covers is no longer
        # reported as untested.
        out[cat] = max(found, key=lambda p: order[p]) if found else _NONE
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
