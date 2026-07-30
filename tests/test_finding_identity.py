# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Finding-node identity tests (ADR 0010).

Covers: one graph node per graph-eligible finding, elimination of the documented MCP and
Architecture collisions, absence of `surface_id` from the identity, direct/surface graph
equivalence, determinism across repeats/seeds/configurations, and the guarantee that no
unredacted content enters a node id.

The existing suite pins no Finding node id, so a wrong key would pass all 350 tests. These
tests exist to close that gap: they pin exact ids for fixed fixtures.
Run: python -m unittest tests.test_finding_identity -v
"""

import hashlib
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import architecture
from glasscage.aakg.build import _finding_key, _subject_digest
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage.targets import ChatSurface

_SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")
_ELIGIBLE = ("vulnerable", "inconclusive", "not_assessable")


def _stable(text):
    return _TS.sub("<TS>", text)


def _manifest():
    with open(os.path.join(_SAMPLES, "mcp_manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _run(surface=False, maximal=False, **kw):
    agent = ReferenceAgent()
    if maximal:
        kw.update(mcp_manifest=_manifest(), architecture_answers=architecture.template(),
                  adaptive=True, genetic=True, genetic_budget=8)
    eng = Engine(agent, capture_evidence=False,
                 surface=ChatSurface(agent) if surface else None, **kw)
    return eng, eng.run()


def _eligible(results):
    return [f for f in results["findings"] if f.status.value in _ELIGIBLE]


def _finding_nodes(engine):
    return [n for n in engine._graph_obj.to_dict()["nodes"] if n["ntype"] == "Finding"]


# ---------------- one node per eligible finding ----------------
class TestOneNodePerFinding(unittest.TestCase):
    def _assert_lossless(self, **kw):
        eng, res = _run(**kw)
        self.assertEqual(len(_finding_nodes(eng)), len(_eligible(res)))

    def test_maximal_run_is_lossless(self):
        self._assert_lossless(maximal=True)

    def test_harness_run_is_lossless(self):
        self._assert_lossless()

    def test_mcp_run_is_lossless(self):
        eng, res = _run(mcp_manifest=_manifest())
        self.assertEqual(len(_finding_nodes(eng)), len(_eligible(res)))

    def test_surface_driven_run_is_lossless(self):
        self._assert_lossless(surface=True, maximal=True)


# ---------------- documented collisions eliminated ----------------
class TestDocumentedCollisions(unittest.TestCase):
    def test_mcp_collision_eliminated(self):
        eng, _ = _run(maximal=True)
        ids = {n["id"]: n for n in _finding_nodes(eng)}
        self.assertIn("Finding:MCP07:mcp-analyzer:ca58bd41c936", ids)
        self.assertIn("Finding:MCP07:mcp-analyzer:f74b6ac34d23", ids)
        self.assertNotIn("Finding:MCP07:mcp-analyzer", ids)

    def test_mcp_nodes_report_their_own_status(self):
        eng, _ = _run(maximal=True)
        ids = {n["id"]: n for n in _finding_nodes(eng)}
        fetch = ids["Finding:MCP07:mcp-analyzer:ca58bd41c936"]
        meta = ids["Finding:MCP07:mcp-analyzer:f74b6ac34d23"]
        self.assertIn("fetch_url", fetch["label"])
        self.assertEqual(fetch["metadata"]["status"], "inconclusive")
        self.assertIn("metadata_probe", meta["label"])
        self.assertEqual(meta["metadata"]["status"], "vulnerable")

    def test_architecture_collision_eliminated(self):
        eng, _ = _run(maximal=True)
        arch = [n for n in _finding_nodes(eng) if "LLM06:architecture-review" in n["id"]]
        self.assertEqual(len(arch), 3)
        self.assertEqual(len(arch), len({n["id"] for n in arch}))

    def test_no_node_mixes_label_and_status_from_different_findings(self):
        eng, res = _run(maximal=True)
        by_key = {_finding_key(f): f for f in _eligible(res)}
        for n in _finding_nodes(eng):
            src = by_key[n["id"].split(":", 1)[1]]
            self.assertEqual(n["metadata"]["status"], src.status.value)
            self.assertTrue(n["label"] and src.title.startswith(n["label"][:20]))


# ---------------- surface_id is not part of the identity ----------------
class TestSurfaceIdExcluded(unittest.TestCase):
    def test_key_ignores_surface_id(self):
        eng, res = _run()
        f = _eligible(res)[0]
        before = _finding_key(f)
        f.surface_id = "some-surface"
        self.assertEqual(_finding_key(f), before)

    def test_key_has_exactly_three_components(self):
        eng, res = _run(maximal=True)
        for f in _eligible(res):
            self.assertEqual(len(_finding_key(f).split(":")), 3)

    def test_direct_and_surface_driven_graphs_are_byte_identical(self):
        e1, _ = _run(maximal=True)
        e2, _ = _run(surface=True, maximal=True)
        a = json.dumps(e1._graph_obj.to_dict(), sort_keys=True)
        b = json.dumps(e2._graph_obj.to_dict(), sort_keys=True)
        self.assertEqual(_stable(a), _stable(b))


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def _ids(self, **kw):
        eng, _ = _run(**kw)
        return sorted(n["id"] for n in _finding_nodes(eng))

    def test_identical_across_repeated_runs(self):
        self.assertEqual(self._ids(maximal=True), self._ids(maximal=True))

    def test_identical_across_seeds(self):
        self.assertEqual(self._ids(maximal=True, seed=1),
                         self._ids(maximal=True, seed=999))

    def test_identical_across_run_configurations(self):
        minimal = set(self._ids())
        maximal = set(self._ids(maximal=True))
        self.assertTrue(minimal, "expected findings in the minimal run")
        self.assertTrue(minimal <= maximal,
                        "a probe's node id changed when other probes were added")

    def test_key_is_not_order_derived(self):
        eng, res = _run(maximal=True)
        fs = _eligible(res)
        self.assertEqual([_finding_key(f) for f in fs],
                         [_finding_key(f) for f in reversed(fs)][::-1])


# ---------------- no unredacted content in ids ----------------
class TestNoSensitiveContentInIds(unittest.TestCase):
    def test_digest_is_opaque_hex(self):
        d = _subject_digest("api_key=sk-ABCDEF0123456789 GLSSCG-INJECT-OK")
        self.assertRegex(d, r"^[0-9a-f]{12}$")
        for leak in ("sk-", "api_key", "GLSSCG"):
            self.assertNotIn(leak, d)

    def test_node_ids_carry_no_canary_or_secret_shapes(self):
        eng, _ = _run(maximal=True)
        for n in _finding_nodes(eng):
            for leak in ("GLSSCG-", "sk-", "password=", "hunter2"):
                self.assertNotIn(leak, n["id"])

    def test_whitespace_normalisation(self):
        self.assertEqual(_subject_digest("  tool:   fetch_url  "),
                         _subject_digest("tool: fetch_url"))
        self.assertEqual(_subject_digest("tool: fetch_url"),
                         hashlib.sha256(b"tool: fetch_url").hexdigest()[:12])


if __name__ == "__main__":
    unittest.main()
