# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Graph-native coverage engine (GLASSCAGE Stage E5-2).

Status: Implemented. Replaces the finding-list coverage computation with one that
reads OWASP/ATLAS/CAPEC/CWE/NIST coverage directly from graph relationships.

For every taxonomy family, coverage is the set of taxonomy nodes reachable via
FINDING -[mapped_to]-> node edges, and each tested category is classified by the
strongest evidence state among the findings that map to it:
  Demonstrated > Hypothesized > Not Assessable ; Untested if no finding maps to it.

Emits the legacy coverage dict keys (so report/HTML shims keep working) plus a new
`taxonomy_coverage` breakdown.
"""

from __future__ import annotations

from .. import taxonomy
from ..coverage import CANONICAL, KNOWN_GAPS
from .types import EdgeType, NodeType

_FAMILIES = {
    NodeType.OWASP: sorted(CANONICAL.keys()),
    NodeType.ATLAS: sorted({v["atlas"] for v in taxonomy.CROSSWALK.values() if v["atlas"]}),
    NodeType.CWE: sorted({v["cwe"] for v in taxonomy.CROSSWALK.values() if v["cwe"]}),
    NodeType.CAPEC: sorted({v["capec"] for v in taxonomy.CROSSWALK.values() if v["capec"]}),
    NodeType.NIST: sorted({v["nist"] for v in taxonomy.CROSSWALK.values() if v["nist"]}),
}
_RANK = {"demonstrated": 3, "hypothesized": 2, "not_assessable": 1}


def _finding_state(g, fnode) -> str:
    md = fnode.metadata or {}
    if md.get("impact_confirmed"):
        return "demonstrated"
    st = md.get("status", "")
    if st == "not_assessable":
        return "not_assessable"
    if st in ("vulnerable", "inconclusive"):
        return "hypothesized"
    return "hypothesized"


def _category_status(g, tax_node) -> str:
    """Strongest evidence among findings that map to this taxonomy node."""
    best = 0
    for e in g.in_edges(tax_node.id, EdgeType.MAPPED_TO):
        f = g.node(e.src)
        if f is None or f.ntype is not NodeType.FINDING:
            continue
        best = max(best, _RANK[_finding_state(g, f)])
    return {3: "demonstrated", 2: "hypothesized", 1: "not_assessable", 0: "untested"}[best]


def compute(g) -> dict:
    tax_cov = {}
    for ntype, universe in _FAMILIES.items():
        _present = {n.label or n.id.split(":", 1)[1] for n in g.nodes(ntype)}
        buckets = {"demonstrated": [], "hypothesized": [], "not_assessable": [],
                   "untested": []}
        for cat in universe:
            node = g.node(f"{ntype.value}:{cat}")
            status = _category_status(g, node) if node else "untested"
            buckets[status].append(cat)
        tested = [c for c in universe if c not in buckets["untested"]]
        tax_cov[ntype.value] = {
            "universe": len(universe), "tested": len(tested),
            "coverage_ratio": round(len(tested) / len(universe), 2) if universe else 0.0,
            "demonstrated": buckets["demonstrated"], "hypothesized": buckets["hypothesized"],
            "not_assessable": buckets["not_assessable"], "untested": buckets["untested"],
        }

    # legacy-compatible OWASP view (keeps report/HTML statement() working)
    owasp = tax_cov[NodeType.OWASP.value]
    tested_ids = sorted(set(owasp["demonstrated"] + owasp["hypothesized"]))
    not_assessable_ids = sorted(owasp["not_assessable"])
    not_tested = sorted(c for c in CANONICAL if c in owasp["untested"])
    return {
        "techniques_run": len(g.nodes(NodeType.FINDING)),
        "categories_tested": tested_ids,
        "categories_not_tested": not_tested,
        "categories_not_assessable": not_assessable_ids,
        "known_gaps": {k: KNOWN_GAPS[k] for k in KNOWN_GAPS
                       if k in not_tested or k in tested_ids},
        "coverage_ratio": owasp["coverage_ratio"],
        "taxonomy_coverage": tax_cov,
        "source": "aakg",
        # Release-quality honesty fix (additive; legacy coverage_ratio unchanged).
        # `coverage_ratio` counts any mapped finding as "tested" regardless of how it
        # was obtained. `runtime_coverage_ratio` counts only categories where a payload
        # was actually sent to the target. Quote the runtime figure externally.
        "coverage_provenance": _provenance_summary(),
        "runtime_coverage_ratio": _provenance_summary()["runtime_coverage_ratio"],
        "coverage_ratio_caveat": (
            "coverage_ratio counts questionnaire and configuration-review findings as "
            "tested; use runtime_coverage_ratio for runtime-tested categories only."
        ),
    }


def _provenance_summary() -> dict:
    """Provenance-aware coverage (see glasscage.coverage_provenance)."""
    from ..coverage_provenance import summarize
    return summarize()
