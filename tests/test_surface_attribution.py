# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Runtime surface attribution tests (ADR 0004).

Covers: runtime findings carry the driven surface id; configuration-review and
questionnaire findings never do; the default path is unchanged; serialization gains
exactly one key; and the graph, SARIF and reproduction output are unperturbed.
Run: python -m unittest tests.test_surface_attribution -v
"""

import dataclasses
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage import architecture, report, sarif
from glasscage.engine import Engine
from glasscage.models import Finding, Severity, Status
from glasscage.refagent import ReferenceAgent
from glasscage.targets import ChatSurface

_SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")


def _stable(text):
    return _TS.sub("<TS>", text)


def _manifest():
    with open(os.path.join(_SAMPLES, "mcp_manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _driven(target=None, **kw):
    """Run with a bound CHAT surface over the target. Returns (engine, results)."""
    t = target if target is not None else ReferenceAgent()
    eng = Engine(t, capture_evidence=False, surface=ChatSurface(t), **kw)
    return eng, eng.run()


def _direct(target=None, **kw):
    t = target if target is not None else ReferenceAgent()
    eng = Engine(t, capture_evidence=False, **kw)
    return eng, eng.run()


def _runtime(results):
    """Findings produced by target interaction (not MCP / architecture review)."""
    return [f for f in results["findings"]
            if not f.owasp_id.startswith("MCP") and f.probe_name != "architecture-review"]


def _shape(results):
    return [(f.probe_name, f.status.value, f.severity.value, f.title, f.response_excerpt)
            for f in results["findings"]]


# ---------------- tagging ----------------
class TestRuntimeTagging(unittest.TestCase):
    def test_probe_findings_carry_the_surface_id(self):
        _, res = _driven()
        runtime = _runtime(res)
        self.assertTrue(runtime)
        for f in runtime:
            self.assertEqual(f.surface_id, "chat")

    def test_tier_gated_findings_carry_the_surface_id(self):
        _, res = _driven(_MockTarget())          # L0 target -> agentic probes gated
        gated = [f for f in res["findings"] if f.status is Status.NOT_ASSESSABLE]
        self.assertTrue(gated, "expected tier-gated findings on an L0 target")
        for f in gated:
            self.assertEqual(f.surface_id, "chat")

    def test_adaptive_findings_carry_the_surface_id(self):
        _, res = _driven(adaptive=True)
        adaptive = [f for f in res["findings"] if f.probe_name == "adaptive-attacker"]
        self.assertTrue(adaptive)
        for f in adaptive:
            self.assertEqual(f.surface_id, "chat")

    def test_genetic_findings_carry_the_surface_id(self):
        _, res = _driven(genetic=True, genetic_budget=8)
        genetic = [f for f in res["findings"] if f.probe_name == "genetic-attacker"]
        self.assertTrue(genetic)
        for f in genetic:
            self.assertEqual(f.surface_id, "chat")


# ---------------- honesty: non-runtime evidence is never attributed ----------------
class TestNonRuntimeEvidenceUnattributed(unittest.TestCase):
    def test_mcp_findings_are_not_attributed(self):
        _, res = _driven(mcp_manifest=_manifest())
        mcp = [f for f in res["findings"] if f.owasp_id.startswith("MCP")]
        self.assertTrue(mcp, "expected MCP configuration-review findings")
        for f in mcp:
            self.assertEqual(f.surface_id, "")

    def test_architecture_findings_are_not_attributed(self):
        _, res = _driven(architecture_answers=architecture.template())
        arch = [f for f in res["findings"] if f.probe_name == "architecture-review"]
        self.assertTrue(arch, "expected architecture questionnaire findings")
        for f in arch:
            self.assertEqual(f.surface_id, "")


# ---------------- legacy invariance ----------------
class TestLegacyInvariance(unittest.TestCase):
    def test_default_run_leaves_surface_id_empty(self):
        _, res = _direct(mcp_manifest=_manifest())
        self.assertTrue(res["findings"])
        for f in res["findings"]:
            self.assertEqual(f.surface_id, "")

    def test_findings_are_otherwise_identical(self):
        _, direct = _direct()
        _, driven = _driven()
        self.assertEqual(_shape(direct), _shape(driven))
        self.assertEqual(direct["summary"], driven["summary"])


# ---------------- serialization ----------------
class TestSerialization(unittest.TestCase):
    def test_to_dict_carries_surface_id_and_no_other_change(self):
        d = Finding(probe_name="p", title="t", owasp_id="LLM01", category="c",
                    status=Status.PASSED, severity=Severity.INFO).to_dict()
        self.assertIn("surface_id", d)
        self.assertEqual(d["surface_id"], "")
        self.assertEqual(set(d), {f.name for f in dataclasses.fields(Finding)})
        for key in ("probe_name", "owasp_id", "status", "severity", "assessed_tier",
                    "source_framework", "evidence_hash", "turns"):
            self.assertIn(key, d)

    def test_json_report_round_trips(self):
        eng, res = _driven()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            report.write_json(path, "t", res["recon"], res["findings"], res["summary"])
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        ids = {f["surface_id"] for f in data["findings"]}
        self.assertEqual(ids, {"chat"})


# ---------------- non-perturbation ----------------
class TestNonPerturbation(unittest.TestCase):
    def test_aakg_serialization_identical_between_paths(self):
        e1, _ = _direct()
        e2, _ = _driven()
        a = json.dumps(e1._graph_obj.to_dict(), sort_keys=True)
        b = json.dumps(e2._graph_obj.to_dict(), sort_keys=True)
        self.assertEqual(_stable(a), _stable(b))

    def test_repro_and_sarif_unchanged_for_a_driven_run(self):
        _, direct = _direct()
        _, driven = _driven()
        self.assertEqual([f.reproduction_steps for f in direct["findings"]],
                         [f.reproduction_steps for f in driven["findings"]])
        with tempfile.TemporaryDirectory() as tmp:
            p1, p2 = os.path.join(tmp, "a.sarif"), os.path.join(tmp, "b.sarif")
            sarif.write_sarif(p1, "t", direct["findings"], direct["summary"])
            sarif.write_sarif(p2, "t", driven["findings"], driven["summary"])
            with open(p1, encoding="utf-8") as fh:
                a = _stable(fh.read())
            with open(p2, encoding="utf-8") as fh:
                b = _stable(fh.read())
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
