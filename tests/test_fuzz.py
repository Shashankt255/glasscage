"""Fuzz tests (stdlib, seeded): malformed inputs must never crash uncaught.
Run: python -m unittest tests.test_fuzz -q
"""
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage.adapters import REGISTRY
from glasscage.adapters.base import AdapterResult
from glasscage.config import validate_target_config
from glasscage.errors import ConfigError
from glasscage.aakg import PropertyGraph, NodeType, EdgeType, EdgeState


def _rand_json(rng):
    kinds = [
        lambda: "{not json",
        lambda: json.dumps({"results": rng.choice([None, [], {}, 42, "x"])}),
        lambda: json.dumps([{"score": {"score_value": rng.choice(["true", "false", 0.5, None])}}]),
        lambda: json.dumps({"vulnerabilities": [{"test_cases": [{"passed": rng.choice([True, False])}]}]}),
        lambda: "\n".join(json.dumps({"entry_type": "attempt",
                                      "status": rng.randint(0, 3),
                                      "detector_results": {"d": [rng.random()]}}) for _ in range(3)),
        lambda: "",
        lambda: "\x00\x01\x02 garbage",
    ]
    return rng.choice(kinds)()


class TestAdapterFuzz(unittest.TestCase):
    def test_adapters_never_crash_on_garbage(self):
        rng = random.Random(2026)
        for i in range(200):
            payload = _rand_json(rng)
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write(payload); path = fh.name
            try:
                for name in ("garak", "promptfoo", "pyrit", "deepteam", "fuzzyai"):
                    res = REGISTRY[name]().run(_MockTarget(), {"from_file": path})
                    self.assertIsInstance(res, AdapterResult)  # graceful, never raises
            finally:
                os.unlink(path)


class TestGraphFuzz(unittest.TestCase):
    def test_random_graphs_serialize_and_roundtrip(self):
        rng = random.Random(7)
        ntypes = list(NodeType); etypes = list(EdgeType); states = list(EdgeState)
        for _ in range(50):
            g = PropertyGraph()
            ids = []
            for _ in range(rng.randint(1, 12)):
                nt = rng.choice(ntypes)
                n = g.ensure(nt, f"k{rng.randint(0, 6)}")
                ids.append(n.id)
            for _ in range(rng.randint(0, 20)):
                a, b = rng.choice(ids), rng.choice(ids)
                g.add_edge(a, rng.choice(etypes), b, rng.choice(states))
            js = g.to_json()
            self.assertEqual(PropertyGraph.from_dict(g.to_dict()).to_json(), js)
            # traversal must not crash
            g.simple_paths(ids[0], ids, max_depth=4)
            g.reachable(ids[0])


class TestConfigFuzz(unittest.TestCase):
    def test_config_validation_is_total(self):
        rng = random.Random(99)
        keys = ["url", "method", "headers", "timeout", "stateful", "response_path", "bogus"]
        vals = ["http://x", "harness://y", 5, -1, {}, [], None, "POST", True, "z"]
        for _ in range(300):
            cfg = {rng.choice(keys): rng.choice(vals) for _ in range(rng.randint(0, 4))}
            try:
                validate_target_config(cfg)
            except ConfigError:
                pass  # expected class of failure
            except Exception as e:  # noqa: BLE001
                self.fail(f"unexpected error type {type(e).__name__} for {cfg}: {e}")


if __name__ == "__main__":
    unittest.main()
