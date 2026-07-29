"""Stage E5 tests: native graph posture / coverage / remediation / reporting.
Run: python -m unittest tests.test_stage_e5 -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage import schema
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage.aakg import build as B
from glasscage.aakg import posture as GP, coverage as GC, remediation as GR, report as GRPT

_TOOLS = schema.ingest({"functions": [
    {"name": "get_secret", "description": "vault secret", "parameters": {}},
    {"name": "run_sql", "description": "database", "parameters": {}}]})


def _graph():
    res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
    return B.build_graph(res["recon"], res["findings"], None, None, "L2", "fixed"), res


# ---------------- E5-1: posture ----------------
class TestGraphPosture(unittest.TestCase):
    def test_posture_is_graph_sourced_and_explained(self):
        g, _ = _graph()
        p = GP.compute(g, GC.compute(g))
        self.assertEqual(p["source"], "aakg")
        self.assertTrue(0 <= p["posture_score"] <= 100)
        self.assertEqual(round(p["posture_score"] + p["risk_index"], 1), 100.0)
        # every contribution explains its points
        self.assertTrue(p["contributions"])
        pts = sum(c["points"] for c in p["contributions"])
        self.assertAlmostEqual(pts, p["risk_index"], delta=0.5)

    def test_evidence_counts_present(self):
        g, _ = _graph()
        p = GP.compute(g)
        ec = p["evidence_counts"]
        self.assertIn("demonstrated", ec)
        self.assertGreater(ec["demonstrated"], 0)

    def test_mitigations_reduce_risk(self):
        res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
        g_no = B.build_graph(res["recon"], res["findings"], None, None, "L2", "fixed")
        g_mit = B.build_graph(res["recon"], res["findings"], None,
                              {"tool_least_privilege": "yes", "secrets_out_of_context": "yes"},
                              "L2", "fixed")
        self.assertLess(GP.compute(g_mit)["risk_index"], GP.compute(g_no)["risk_index"])


# ---------------- E5-2: coverage ----------------
class TestGraphCoverage(unittest.TestCase):
    def test_taxonomy_families_present(self):
        g, _ = _graph()
        c = GC.compute(g)
        self.assertEqual(c["source"], "aakg")
        for fam in ("OWASP", "ATLAS", "CWE", "CAPEC", "NIST"):
            self.assertIn(fam, c["taxonomy_coverage"])

    def test_states_distinguished(self):
        g, _ = _graph()
        owasp = GC.compute(g)["taxonomy_coverage"]["OWASP"]
        for k in ("demonstrated", "hypothesized", "not_assessable", "untested"):
            self.assertIn(k, owasp)

    def test_legacy_keys_preserved(self):
        g, _ = _graph()
        c = GC.compute(g)
        for k in ("categories_tested", "categories_not_tested", "coverage_ratio",
                  "techniques_run"):
            self.assertIn(k, c)
        from glasscage import coverage as legacy
        # legacy statement() must still work on graph coverage
        self.assertIsInstance(legacy.statement(c), str)


# ---------------- E5-4: remediation ----------------
class TestGraphRemediation(unittest.TestCase):
    def test_ranked_and_cited(self):
        g, _ = _graph()
        recs = GR.prioritize(g)
        self.assertTrue(recs)
        top = recs[0]
        self.assertGreater(top["impact_score"], 0)
        self.assertTrue(top["cited_edges"])   # every rec cites graph edges
        self.assertIn("paths_affected", top)

    def test_least_privilege_breaks_paths(self):
        g, _ = _graph()
        recs = {r["mitigation"]: r for r in GR.prioritize(g)}
        self.assertGreater(recs["tool_least_privilege"]["paths_affected"], 0)
        self.assertTrue(recs["tool_least_privilege"]["blast_reduction_assets"])

    def test_present_mitigation_scores_zero(self):
        res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
        g = B.build_graph(res["recon"], res["findings"], None,
                          {"tool_least_privilege": "yes"}, "L2", "fixed")
        recs = {r["mitigation"]: r for r in GR.prioritize(g)}
        self.assertEqual(recs["tool_least_privilege"]["status"], "in place")
        self.assertEqual(recs["tool_least_privilege"]["impact_score"], 0)


# ---------------- E5-3: reporting ----------------
class TestGraphReport(unittest.TestCase):
    def test_all_sections_graph_sourced(self):
        g, res = _graph()
        md = GRPT.to_markdown(g, res, "demo")
        for section in ("Executive Summary", "contribution breakdown", "Attack Paths",
                        "Trust Boundary", "Blast Radius", "Coverage (graph-derived)",
                        "Prioritized Remediation", "Evidence Ledger"):
            self.assertIn(section, md)

    def test_engine_routes_markdown_through_graph(self):
        eng = Engine(ReferenceAgent(), schema_tools=_TOOLS)
        md = eng.report_markdown(eng.run())
        self.assertIn("graph-native report", md)


# ---------------- Backward compatibility / fallback ----------------
class TestE5Fallback(unittest.TestCase):
    def test_legacy_path_intact(self):
        eng = Engine(_MockTarget(), use_aakg=False)
        res = eng.run()
        self.assertNotEqual(res["posture"].get("source"), "aakg")
        self.assertIsNone(res["remediation_priorities"])
        md = eng.report_markdown(res)
        self.assertIn("Executive Summary", md)   # legacy report still works

    def test_engine_results_expose_graph_native(self):
        res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
        self.assertEqual(res["posture"]["source"], "aakg")
        self.assertEqual(res["coverage"]["source"], "aakg")
        self.assertTrue(res["remediation_priorities"])


if __name__ == "__main__":
    unittest.main()
