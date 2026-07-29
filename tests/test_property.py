"""Property-based tests (stdlib randomized, seeded) for core invariants.
No third-party 'hypothesis' dependency (keeps the zero-dep philosophy).
Run: python -m unittest tests.test_property -q
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.stats import wilson
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage.aakg import build as B, paths as P


class TestWilsonProperties(unittest.TestCase):
    def test_bounds(self):
        rng = random.Random(1)
        for _ in range(2000):
            n = rng.randint(1, 500)
            k = rng.randint(0, n)
            p, lo, hi = wilson(k, n)
            eps = 1e-3   # wilson() rounds to 4 dp
            self.assertTrue(0.0 <= lo <= p + eps and p - eps <= hi <= 1.0,
                            f"{k}/{n} -> {p,lo,hi}")
            self.assertAlmostEqual(p, k / n, places=3)


class TestGraphProperties(unittest.TestCase):
    def _run(self, cfg, tier="L2"):
        res = Engine(ReferenceAgent(**cfg)).run()
        return B.build_graph(res["recon"], res["findings"], None, None, tier, "fixed"), res

    def test_determinism_across_configs(self):
        rng = random.Random(5)
        for _ in range(20):
            cfg = {k: rng.choice([True, False]) for k in
                   ("vuln_injection", "vuln_memory_persist", "vuln_tool_routing", "leak_secret")}
            res = Engine(ReferenceAgent(**cfg)).run()
            g1 = B.build_graph(res["recon"], res["findings"], None, None, "L2", "z")
            g2 = B.build_graph(res["recon"], res["findings"], None, None, "L2", "z")
            self.assertEqual(g1.to_json(), g2.to_json())

    def test_path_state_is_weakest_link_invariant(self):
        rng = random.Random(11)
        rank = {"demonstrated": 2, "hypothesized": 1, "not_assessable": 0}
        for _ in range(15):
            cfg = {k: rng.choice([True, False]) for k in
                   ("vuln_injection", "vuln_tool_routing")}
            g, _ = self._run(cfg)
            for path in P.build_paths(g):
                states = [l["state"] for l in path["links"]]
                self.assertEqual(rank[path["state"]], min(rank[s] for s in states))

    def test_posture_and_coverage_ranges(self):
        rng = random.Random(3)
        for _ in range(15):
            cfg = {k: rng.choice([True, False]) for k in
                   ("vuln_injection", "vuln_memory_persist", "leak_secret")}
            res = Engine(ReferenceAgent(**cfg)).run()
            p = res["posture"]
            self.assertTrue(0 <= p["posture_score"] <= 100)
            self.assertEqual(round(p["posture_score"] + p["risk_index"], 1), 100.0)
            self.assertTrue(0.0 <= res["coverage"]["coverage_ratio"] <= 1.0)


if __name__ == "__main__":
    unittest.main()
