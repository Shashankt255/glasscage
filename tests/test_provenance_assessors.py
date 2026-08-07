# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Non-probe assessor provenance tests (ADR 0016, PR #17).

`coverage_provenance` derived provenance from `probes.REGISTRY` alone. `mcp.analyze_manifest`
is not a registered probe - the engine calls it directly - so MCP03 and MCP07 reported
`not_tested` while being assessed, and the `config_review` bucket the module documents
could never fill.

The load-bearing assertions are the frozen ones. This is a reporting-layer fix, so the
battery must stay at 22, `runtime_coverage_ratio` must stay 0.54, and no run may gain a
gated finding. The anti-drift tests matter almost as much: the declaration is a hardcoded
set, so it is checked in both directions against `mcp.py`.

Run: python -m unittest tests.test_provenance_assessors -v
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import coverage_provenance as cp
from glasscage import mcp
from glasscage.coverage import CANONICAL
from glasscage.engine import Engine
from glasscage.probes import all_probes
from glasscage.refagent import ReferenceAgent

_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "samples",
                              "mcp_manifest.json")
_MCP_SRC = os.path.join(os.path.dirname(__file__), "..", "glasscage", "mcp.py")

# Captured from d6ec11c (v0.4.0-cli-surface). A reporting-layer fix may not move these.
_FROZEN_RUNTIME = ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"]
_FROZEN_RATIO = 0.54
_FROZEN_BATTERY = 22


def _manifest():
    import json
    with open(_MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------- the classification this PR corrects ----------------
class TestMcpIsConfigReviewed(unittest.TestCase):
    def test_mcp_categories_are_config_review(self):
        self.assertEqual(cp.summarize()["config_review_only"], ["MCP03", "MCP07"])

    def test_mcp_categories_are_no_longer_not_tested(self):
        self.assertEqual(cp.summarize()["not_tested"], ["LLM04", "MULTIMODAL"])

    def test_the_config_review_bucket_is_no_longer_empty(self):
        """It was structurally unreachable: no registered probe carries an MCP owasp_id
        or an MCP-bearing class name, so `_probe_provenance` could never return it."""
        self.assertTrue(cp.summarize()["config_review_only"])

    def test_mcp_is_still_not_a_registered_probe(self):
        """The fix is reporting-layer only — registering MCP was explicitly rejected."""
        names = {p.name for p in all_probes()}
        self.assertNotIn("mcp-analyzer", names)
        self.assertEqual({p.owasp_id for p in all_probes()} & {"MCP03", "MCP07"}, set())


# ---------------- frozen invariants ----------------
class TestFrozenInvariants(unittest.TestCase):
    def test_runtime_coverage_ratio_is_unchanged(self):
        self.assertEqual(cp.summarize()["runtime_coverage_ratio"], _FROZEN_RATIO)

    def test_runtime_tested_set_is_unchanged(self):
        self.assertEqual(cp.summarize()["runtime_tested"], _FROZEN_RUNTIME)

    def test_universe_is_unchanged(self):
        self.assertEqual(cp.summarize()["universe"], 13)
        self.assertEqual(cp.summarize()["universe"], len(CANONICAL))

    def test_battery_composition_is_unchanged(self):
        self.assertEqual(len(all_probes()), _FROZEN_BATTERY)

    def test_no_gated_findings_were_introduced(self):
        """A reporting change must not perturb what the engine assesses."""
        res = Engine(ReferenceAgent(), capture_evidence=False, use_aakg=False).run()
        gated = [f for f in res["findings"] if f.status.value == "not_assessable"]
        self.assertEqual(len(gated), 1)          # the REST probe on a chat run, as before

    def test_buckets_still_partition_the_universe(self):
        s = cp.summarize()
        total = (len(s["runtime_tested"]) + len(s["config_review_only"])
                 + len(s["questionnaire_only"]) + len(s["not_tested"]))
        self.assertEqual(total, s["universe"])


# ---------------- anti-drift (EIA risk R-1) ----------------
class TestDeclarationDoesNotDrift(unittest.TestCase):
    def _declared(self):
        return set(cp._NON_PROBE_ASSESSORS[cp._CONFIG])

    def test_declaration_matches_what_the_analyzer_emits(self):
        emitted = {f.owasp_id for f in mcp.analyze_manifest(_manifest())}
        self.assertEqual(self._declared(), emitted & set(CANONICAL))

    def test_declaration_matches_the_category_literals_in_mcp_source(self):
        """Catches a category added to `mcp.py` that the shipped sample never triggers."""
        with open(_MCP_SRC, encoding="utf-8") as fh:
            literals = set(re.findall(r'"(MCP\d\d)"', fh.read()))
        self.assertEqual(self._declared(), literals & set(CANONICAL))

    def test_every_declared_category_is_canonical(self):
        for prov, cats in cp._NON_PROBE_ASSESSORS.items():
            with self.subTest(provenance=prov):
                self.assertTrue(set(cats) <= set(CANONICAL))

    def test_non_canonical_mcp00_is_ignored(self):
        """`mcp.py` can emit MCP00 (its clean-manifest verdict, which the shipped sample
        does not trigger). It is not a canonical category and must reach no bucket."""
        with open(_MCP_SRC, encoding="utf-8") as fh:
            self.assertIn("MCP00", set(re.findall(r'"(MCP\d\d)"', fh.read())))
        self.assertNotIn("MCP00", CANONICAL)
        s = cp.summarize()
        for bucket in ("runtime_tested", "config_review_only", "questionnaire_only",
                       "not_tested"):
            self.assertNotIn("MCP00", s[bucket])


# ---------------- precedence ----------------
class TestPrecedence(unittest.TestCase):
    def test_a_runtime_category_is_never_demoted_by_a_declaration(self):
        original = dict(cp._NON_PROBE_ASSESSORS)
        try:
            cp._NON_PROBE_ASSESSORS[cp._CONFIG] = frozenset({"MCP03", "MCP07", "LLM01"})
            self.assertIn("LLM01", cp.summarize()["runtime_tested"])
            self.assertNotIn("LLM01", cp.summarize()["config_review_only"])
        finally:
            cp._NON_PROBE_ASSESSORS.clear()
            cp._NON_PROBE_ASSESSORS.update(original)

    def test_config_review_outranks_questionnaire(self):
        order_config = cp._CONFIG
        original = dict(cp._NON_PROBE_ASSESSORS)
        try:
            cp._NON_PROBE_ASSESSORS[order_config] = frozenset({"MCP03", "MCP07", "LLM03"})
            self.assertIn("LLM03", cp.summarize()["config_review_only"])
        finally:
            cp._NON_PROBE_ASSESSORS.clear()
            cp._NON_PROBE_ASSESSORS.update(original)

    def test_a_category_with_no_assessor_is_not_tested(self):
        self.assertIn("LLM04", cp.summarize()["not_tested"])


if __name__ == "__main__":
    unittest.main()
