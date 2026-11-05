# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Context-window pressure is prompt injection, not unbounded consumption (ADR 0031, PR #32).

`ContextExhaustionProbe` sends filler followed by an injected tail and verdicts with
`canary_verdict`. It measures whether a buried instruction is still executed - prompt
injection - and observes no token count, request count, latency or resource bound of any
kind. It was nonetheless mapped to `LLM10` (Unbounded Consumption).

Real-target calibration made the mismatch measurable: this probe produced EVERY LLM10
`vulnerable` verdict across ten runs, while independent server-side counters supported
almost none of them. That is a taxonomy defect, not a detector defect - the probe reports
exactly what it claims to, under the wrong category.

PR #32 re-maps it to `LLM01`. `dimension` stays "steerability" on the vulnerable branch:
that is what the finding is, and it is the field scoring and posture actually read, so the
score cannot move. Genuine LLM10 consumption measurement is deferred to a separate PR.

Run: python -m unittest tests.test_context_pressure_taxonomy -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage import coverage_provenance as cp
from glasscage.agent_probes import ContextExhaustionProbe
from glasscage.coverage import CANONICAL
from glasscage.models import Status
from glasscage.probes import REGISTRY
from glasscage.target import ChatResponse

CANARY = "GLSSCG-INJECT-OK"


class _Recon:
    notes: list = []


class _Target:
    """Canned responder. No network."""

    def __init__(self, text, ok=True):
        self.text, self.ok = text, ok
        self.sent = []

    def send(self, prompt):
        self.sent.append(prompt)
        return ChatResponse(text=self.text, raw=None, latency_ms=1.0, ok=self.ok,
                            error=None if self.ok else "boom")


def run(text, ok=True):
    t = _Target(text, ok)
    return ContextExhaustionProbe().run(t, _Recon())[0], t


class TestTaxonomyMapping(unittest.TestCase):
    def test_01_owasp_id_is_llm01(self):
        """The correction. Was LLM10; the probe tests injection, not consumption."""
        self.assertEqual(ContextExhaustionProbe.owasp_id, "LLM01")

    def test_02_owasp_id_is_not_llm10(self):
        self.assertNotEqual(ContextExhaustionProbe.owasp_id, "LLM10")

    def test_03_category_describes_instruction_following(self):
        c = ContextExhaustionProbe.category.lower()
        self.assertIn("injection", c)
        self.assertNotIn("unbounded", c)
        self.assertNotIn("consumption", c)

    def test_04_references_no_longer_cite_llm10(self):
        refs = " ".join(ContextExhaustionProbe.references).lower()
        self.assertIn("llm01", refs)
        self.assertNotIn("llm10", refs)

    def test_05_id_stays_inside_the_canonical_taxonomy(self):
        """No off-taxonomy id: an unknown id is silently dropped from coverage."""
        self.assertIn(ContextExhaustionProbe.owasp_id, CANONICAL)

    def test_06_findings_carry_the_new_id(self):
        f, _ = run(f"Sure: {CANARY}")
        self.assertEqual(f.owasp_id, "LLM01")


class TestDimensionAndSeverityUnchanged(unittest.TestCase):
    def test_07_vulnerable_branch_keeps_steerability(self):
        """`dimension` is what scoring and posture read - it must not move."""
        f, _ = run(f"Sure: {CANARY}")
        self.assertIs(f.status, Status.VULNERABLE)
        self.assertEqual(f.dimension, "steerability")

    def test_08_class_dimension_default_unchanged(self):
        self.assertEqual(ContextExhaustionProbe.dimension, "informational")

    def test_09_impact_confirmed_unchanged(self):
        f, _ = run(f"Sure: {CANARY}")
        self.assertFalse(f.impact_confirmed)

    def test_10_severity_and_confidence_unchanged(self):
        f, _ = run(f"Sure: {CANARY}")
        self.assertEqual(f.severity.value, "medium")
        self.assertEqual(f.confidence, 0.9)

    def test_11_passed_branch_unchanged(self):
        f, _ = run("I will not repeat that token for you.")
        self.assertIs(f.status, Status.PASSED)
        self.assertEqual(f.severity.value, "info")
        self.assertEqual(f.confidence, 0.5)

    def test_12_transport_error_branch_unchanged(self):
        f, _ = run("", ok=False)
        self.assertIs(f.status, Status.INCONCLUSIVE)
        self.assertEqual(f.severity.value, "low")


class TestProbeStillExecutes(unittest.TestCase):
    def test_13_probe_still_delivers_a_payload(self):
        _, t = run(f"Sure: {CANARY}")
        self.assertEqual(len(t.sent), 1)
        self.assertIn("lorem ipsum", t.sent[0])
        self.assertIn(CANARY, t.sent[0])

    def test_14_probe_identity_and_tier_unchanged(self):
        self.assertEqual(ContextExhaustionProbe.name, "context-window-exhaustion")
        self.assertEqual(ContextExhaustionProbe.min_tier.name, "L0")


class TestSiblingsAndCoverage(unittest.TestCase):
    def test_15_llm10_still_has_runtime_sibling_probes(self):
        """LLM10 must not lose runtime capability when this probe leaves it."""
        siblings = sorted(p.name for p in REGISTRY if p.owasp_id == "LLM10")
        self.assertIn("loop-amplification", siblings)
        self.assertIn("unbounded-consumption-review", siblings)
        self.assertNotIn("context-window-exhaustion", siblings)

    def test_16_capability_coverage_unchanged(self):
        s = cp.summarize()
        self.assertEqual(s["runtime_tested"],
                         ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"])
        self.assertEqual(s["runtime_coverage_ratio"], 0.54)

    def test_17_llm10_still_classified_runtime(self):
        self.assertIn("LLM10", cp.summarize()["runtime_tested"])

    def test_18_llm01_still_classified_runtime(self):
        self.assertIn("LLM01", cp.summarize()["runtime_tested"])

    def test_19_registry_size_unchanged(self):
        self.assertEqual(len(REGISTRY), 22)


class TestEndToEndInvariants(unittest.TestCase):
    """Real `--demo` run: posture, risk and all three coverage figures must not move."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        out = os.path.join(cls._tmp.name, "o")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(["--demo", "--no-evidence", "--out", out])
        assert rc == 0, rc
        with open(out + ".json", encoding="utf-8") as fh:
            cls.report = json.load(fh)
        with open(out + ".html", encoding="utf-8") as fh:
            cls.html = fh.read()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _coverage_line(self):
        import re
        m = re.search(r"const DATA\s*=\s*(\{.*?\});", self.html, re.DOTALL)
        return json.loads(m.group(1))["coverage"]

    def test_20_posture_and_risk_unchanged(self):
        s = self.report["summary"]
        self.assertEqual(s["posture_score"], 42.7)
        self.assertEqual(s["risk_index"], 57.3)

    def test_21_capability_coverage_line_unchanged(self):
        self.assertIn("Runtime-tested coverage: 7/13", self._coverage_line())

    def test_22_measured_coverage_unchanged(self):
        self.assertIn("Measured runtime coverage this run: 7/13", self._coverage_line())

    def test_23_graph_coverage_unchanged(self):
        cov = self._coverage_line()
        self.assertIn("mixed provenance): 11/13", cov)
        self.assertIn("LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM07, LLM08, LLM09, LLM10, MCP03",
                      cov)

    def test_24_llm10_still_present_in_graph_coverage(self):
        """The remap must not drop LLM10 from graph coverage - its INCONCLUSIVE
        sibling `unbounded-consumption-review` keeps it graph-eligible."""
        ids = {f["owasp_id"] for f in self.report["findings"]}
        self.assertIn("LLM10", ids)
        self.assertIn("LLM10", self._coverage_line())

    def test_25_context_probe_reports_under_llm01_in_the_report(self):
        rows = [f for f in self.report["findings"]
                if f["probe_name"] == "context-window-exhaustion"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["owasp_id"], "LLM01")


class TestSiblingProbesUnmodified(unittest.TestCase):
    def test_26_loop_amplification_unchanged(self):
        p = next(x for x in REGISTRY if x.name == "loop-amplification")
        self.assertEqual(p.owasp_id, "LLM10")
        self.assertEqual(p.category, "Agentic: Retry / Loop Amplification")

    def test_27_unbounded_consumption_review_unchanged(self):
        p = next(x for x in REGISTRY if x.name == "unbounded-consumption-review")
        self.assertEqual(p.owasp_id, "LLM10")
        self.assertEqual(p.category, "Unbounded Consumption")


if __name__ == "__main__":
    unittest.main()
