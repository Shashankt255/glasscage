"""Stage E tests: AAKG engine (E1), attack paths (E2), trust (E3), blast (E4).
Run: python -m unittest tests.test_stage_e -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage import schema
from glasscage.aakg import EdgeState, EdgeType, NodeType, PropertyGraph
from glasscage.aakg import blast as BL
from glasscage.aakg import build as B
from glasscage.aakg import paths as P
from glasscage.aakg import trust_graph as T
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent

_TOOLS = schema.ingest({"functions": [
    {"name": "get_secret", "description": "vault secret", "parameters": {}},
    {"name": "run_sql", "description": "database", "parameters": {}}]})


# ---------------- E1: graph engine ----------------
class TestGraphEngine(unittest.TestCase):
    def test_add_and_dedupe_nodes(self):
        g = PropertyGraph()
        a = g.ensure(NodeType.LLM, "m")
        b = g.ensure(NodeType.LLM, "m")   # same id -> merged, not duplicated
        self.assertIs(a, b)
        self.assertEqual(len(g.nodes()), 1)

    def test_edge_state_monotonic_upgrade(self):
        g = PropertyGraph()
        g.ensure(NodeType.USER, "u"); g.ensure(NodeType.LLM, "m")
        uid, mid = "User:u", "LLM:m"
        g.add_edge(uid, EdgeType.CROSSES, mid, EdgeState.HYPOTHESIZED)
        g.add_edge(uid, EdgeType.CROSSES, mid, EdgeState.DEMONSTRATED)  # upgrade
        e = g.out_edges(uid)[0]
        self.assertIs(e.state, EdgeState.DEMONSTRATED)
        g.add_edge(uid, EdgeType.CROSSES, mid, EdgeState.HYPOTHESIZED)  # no downgrade
        self.assertIs(g.out_edges(uid)[0].state, EdgeState.DEMONSTRATED)

    def test_deterministic_serialization(self):
        run = _mk_run()                      # identical inputs for both builds
        g1 = B.build_graph(*run)
        g2 = B.build_graph(*run)
        self.assertEqual(g1.to_json(), g2.to_json())

    def test_roundtrip(self):
        g = B.build_graph(*_mk_run())
        self.assertEqual(PropertyGraph.from_dict(g.to_dict()).to_json(), g.to_json())

    def test_simple_paths_cycle_free(self):
        g = PropertyGraph()
        for k in "abc":
            g.ensure(NodeType.COMPONENT, k)
        g.add_edge("Component:a", EdgeType.INVOKES, "Component:b", EdgeState.DEMONSTRATED)
        g.add_edge("Component:b", EdgeType.INVOKES, "Component:c", EdgeState.DEMONSTRATED)
        g.add_edge("Component:b", EdgeType.INVOKES, "Component:a", EdgeState.DEMONSTRATED)  # cycle
        paths = g.simple_paths("Component:a", ["Component:c"])
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0]), 2)


def _mk_run():
    res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
    return (res["recon"], res["findings"], None, None, "L2", "fixed")


# ---------------- E2: attack paths ----------------
class TestAttackPaths(unittest.TestCase):
    def test_paths_reach_high_value_assets(self):
        g = B.build_graph(*_mk_run())
        paths = P.build_paths(g)
        self.assertTrue(paths)
        # every path terminates at a high-value asset and carries a state
        for p in paths:
            self.assertIn(p["state"], ("demonstrated", "hypothesized", "not_assessable"))
            self.assertTrue(p["links"])
            self.assertIn("evidence_refs", p)

    def test_path_state_is_weakest_link(self):
        g = B.build_graph(*_mk_run())
        for p in P.build_paths(g):
            states = [l["state"] for l in p["links"]]
            rank = {"demonstrated": 2, "hypothesized": 1, "not_assessable": 0}
            self.assertEqual(rank[p["state"]], min(rank[s] for s in states))

    def test_l0_paths_marked_not_assessable(self):
        res = Engine(_MockTarget(), schema_tools=_TOOLS).run()
        g = B.build_graph(res["recon"], res["findings"], None, None, "L0", "fixed")
        states = {e.state for e in g.edges()}
        self.assertIn(EdgeState.NOT_ASSESSABLE, states)


# ---------------- E3: trust boundary ----------------
class TestTrustGraph(unittest.TestCase):
    def test_reachable_assets_and_transitions(self):
        g = B.build_graph(*_mk_run())
        t = T.analyze(g)
        self.assertEqual(t["source"], "aakg")
        self.assertTrue(t["reachable_trusted_assets"])
        self.assertTrue(t["transitions"])

    def test_excessive_privilege_detected(self):
        g = B.build_graph(*_mk_run())
        t = T.analyze(g)
        # model/planner reach both secrets and database -> excessive
        self.assertTrue(t["excessive_privilege"])

    def test_mitigation_suppresses_violation(self):
        recon, findings, _, _, tier, ts = _mk_run()
        g = B.build_graph(recon, findings, None,
                          {"tenant_isolation": "yes", "secrets_out_of_context": "yes",
                           "tool_least_privilege": "yes", "hitl_high_impact": "yes"},
                          tier, ts)
        t = T.analyze(g)
        self.assertEqual(t["violations"], [])


# ---------------- E4: blast radius ----------------
class TestBlast(unittest.TestCase):
    def test_blast_from_finding(self):
        g = B.build_graph(*_mk_run())
        findings = g.find(NodeType.FINDING)
        self.assertTrue(findings)
        br = BL.blast_radius(g, findings[0].id)
        self.assertIn("reachable_assets", br)

    def test_blast_summary_uses_observed_relationships(self):
        g = B.build_graph(*_mk_run())
        s = BL.summary(g)
        self.assertIn(s["basis"], ("demonstrated", "hypothesized", "unconfirmed"))
        self.assertGreaterEqual(s["multiplier"], 1.0)


# ---------------- Integration + backward compat ----------------
class TestAAKGIntegration(unittest.TestCase):
    def test_engine_exposes_aakg_and_blast(self):
        res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
        self.assertIsNotNone(res["aakg"])
        self.assertIn("by_edge_state", res["aakg"])
        self.assertIsNotNone(res["blast"])

    def test_trust_and_chains_now_graph_sourced(self):
        res = Engine(ReferenceAgent(), schema_tools=_TOOLS).run()
        self.assertEqual(res["trust"]["source"], "aakg")
        self.assertTrue(res["chains"])

    def test_legacy_fallback_still_works(self):
        res = Engine(_MockTarget(), use_aakg=False).run()
        self.assertIn("trust", res)
        self.assertIsNone(res["aakg"])   # aakg disabled -> None
        self.assertNotEqual(res["trust"].get("source"), "aakg")

    def test_report_still_renders_with_graph_trust(self):
        eng = Engine(ReferenceAgent(), schema_tools=_TOOLS)
        res = eng.run()
        md = eng.report_markdown(res)
        html = eng.report_html(res)
        # graph-native markdown report sections
        self.assertIn("graph-native report", md)
        self.assertIn("Trust Boundary", md)
        self.assertIn("Attack Paths", md)
        self.assertIn("contribution breakdown", md)
        self.assertIn("Prioritized Remediation", md)
        self.assertTrue(len(html) > 1000)


if __name__ == "__main__":
    unittest.main()
