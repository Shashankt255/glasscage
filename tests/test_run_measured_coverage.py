# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Run-derived measured coverage (ADR 0029, PR #30).

`coverage_provenance.summarize()` takes no run argument. It classifies the probe REGISTRY
by source inspection, so its 7/13 answers "seven categories have a probe that would send a
payload" - a CAPABILITY. It reads 7/13 whether the target answered every request or
refused all of them.

This module pins the separate, run-derived measurement: which categories actually
delivered a payload to THIS target on THIS run. The expected category set in every
scenario below is fixed by construction - the fake probes declare which categories they
drive and the fake target declares which prompts it will accept - so no expectation is
taken from the code under test.

Run: python -m unittest tests.test_run_measured_coverage -v
"""

import contextlib
import io as _io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage import coverage as cov_mod
from glasscage import coverage_provenance as cp
from glasscage.engine import Engine
from glasscage.models import Finding, Severity, Status
from glasscage.target import ChatResponse
from glasscage.tal import TargetCapabilities

REFUSE = "REFUSE-THIS-PAYLOAD"


class _FakeTarget:
    """Records exchanges exactly as the real transports do (ts/url/status/...).

    `status` is 0 when the payload never reached the target and 200 when it did - the
    same contract `HTTPChatTarget._record`, `targets/rest.py` and `refagent` all write.
    """

    name = "fake-target"

    def __init__(self, refuse_all=False, raise_on=None):
        self.url = "mock://fake"
        self.exchanges = []
        self.audit = None
        self.scope = None
        self.rate = None
        self.capabilities = TargetCapabilities(stateful=True)
        self.refuse_all = refuse_all
        self.raise_on = raise_on      # a scope refusal: raises, records nothing

    def send(self, prompt):
        if self.raise_on and self.raise_on in prompt:
            raise RuntimeError("out of scope: refused before transport")
        delivered = not (self.refuse_all or REFUSE in prompt)
        resp = ChatResponse(text="ok" if delivered else "", raw=None, latency_ms=1.0,
                            ok=delivered,
                            error=None if delivered else "connection refused")
        # status 0 == never reached the target, exactly as the real transports record it
        self.exchanges.append({"ts": "t", "url": self.url, "method": "POST",
                               "request_body": prompt, "status": 200 if delivered else 0,
                               "response_body": resp.text, "ms": 1.0})
        return resp


class _Probe:
    """Drives the target with a declared prompt. Emits no finding by default, so
    delivery and finding-production stay independent."""

    def __init__(self, name, owasp_id, prompt="hello", emit=False, crash_before=False):
        self.name = name
        self.owasp_id = owasp_id
        self.category = owasp_id
        self.prompt = prompt
        self.emit = emit
        self.crash_before = crash_before

    def run(self, target, recon):
        if self.crash_before:
            raise RuntimeError("probe crashed before transport")
        target.send(self.prompt)
        if not self.emit:
            return []
        return [Finding(probe_name=self.name, title="t", owasp_id=self.owasp_id,
                        category=self.category, status=Status.PASSED,
                        severity=Severity.INFO, confidence=0.5,
                        dimension="informational", prompt=self.prompt,
                        response_excerpt="ok")]


def _run(probes, target=None):
    """Run the engine; return (run-derived block, target)."""
    t = target if target is not None else _FakeTarget()
    res = Engine(t, selected_probes=probes, capture_evidence=False,
                 use_aakg=False, build_chains=False).run()
    return res["coverage"]["run_measured_coverage"], t


# ---------------- the delivery predicate ----------------
class TestDeliveryPredicate(unittest.TestCase):
    def test_a_recorded_response_is_delivered(self):
        self.assertTrue(cov_mod.is_delivered({"status": 200}))

    def test_status_zero_is_not_delivered(self):
        """Every transport writes 0 when the payload never reached the target."""
        self.assertFalse(cov_mod.is_delivered({"status": 0}))

    def test_an_error_status_still_counts_as_delivered(self):
        """4xx/5xx means the target received the payload and rejected it."""
        self.assertTrue(cov_mod.is_delivered({"status": 500}))
        self.assertTrue(cov_mod.is_delivered({"status": 403}))

    def test_a_malformed_record_is_not_delivered(self):
        for rec in ({}, {"status": None}, {"status": "nope"}, None):
            self.assertFalse(cov_mod.is_delivered(rec), rec)


# ---------------- the assembled block ----------------
class TestRunMeasuredBlock(unittest.TestCase):
    def test_a_category_counts_once_however_many_probes(self):
        b = cov_mod.run_measured(["LLM01", "LLM01", "LLM01", "LLM02"])
        self.assertEqual(b["measured_categories"], ["LLM01", "LLM02"])
        self.assertEqual(b["measured_count"], 2)

    def test_off_taxonomy_ids_cannot_inflate_the_count(self):
        b = cov_mod.run_measured(["LLM01", "PLUGIN-X", ""])
        self.assertEqual(b["measured_categories"], ["LLM01"])

    def test_the_denominator_is_the_canonical_taxonomy(self):
        self.assertEqual(cov_mod.run_measured([])["universe"], len(cov_mod.CANONICAL))
        self.assertEqual(cov_mod.run_measured([])["universe"], 13)

    def test_the_ratio_is_measured_over_universe(self):
        self.assertEqual(cov_mod.run_measured(["LLM01"])["run_coverage_ratio"], 0.08)
        self.assertEqual(cov_mod.run_measured([])["run_coverage_ratio"], 0.0)

    def test_custody_flag_is_carried(self):
        self.assertTrue(cov_mod.run_measured([], custody_complete=True)["custody_complete"])
        self.assertFalse(cov_mod.run_measured([], custody_complete=False)["custody_complete"])


# ---------------- the run-level scenarios ----------------
class TestMeasuredFromRealRuns(unittest.TestCase):
    def test_all_probes_deliver(self):
        """Scenario 1. Expected set fixed by construction: both probes send, target accepts."""
        block, _ = _run([_Probe("a", "LLM01"), _Probe("b", "LLM07")])
        self.assertEqual(block["measured_categories"], ["LLM01", "LLM07"])
        self.assertEqual(block["measured_count"], 2)

    def test_a_category_whose_probes_never_deliver_is_not_counted(self):
        """Scenario 2. LLM07's probe sends a payload the target refuses."""
        block, _ = _run([_Probe("a", "LLM01"), _Probe("b", "LLM07", prompt=REFUSE)])
        self.assertEqual(block["measured_categories"], ["LLM01"])

    def test_delivery_without_a_finding_still_counts(self):
        """Scenario 3. The probe emits nothing; delivery is what is measured."""
        block, _ = _run([_Probe("a", "LLM01", emit=False)])
        self.assertEqual(block["measured_categories"], ["LLM01"])

    def test_a_probe_that_crashes_before_transport_is_not_counted(self):
        """Scenario 4."""
        block, t = _run([_Probe("a", "LLM01", crash_before=True)])
        self.assertEqual(block["measured_categories"], [])
        self.assertEqual([x for x in t.exchanges if x["request_body"] == "hello"], [])

    def test_a_scope_refusal_is_not_counted(self):
        """Scenario 5. `scope.check` raises inside send before anything is recorded."""
        block, t = _run([_Probe("a", "LLM01", prompt="BLOCKED")],
                        target=_FakeTarget(raise_on="BLOCKED"))
        self.assertEqual(block["measured_categories"], [])
        self.assertEqual([x for x in t.exchanges if x["request_body"] == "BLOCKED"], [])

    def test_a_transport_refusal_is_not_counted(self):
        """Scenario 6. An exchange IS recorded, with status 0."""
        block, t = _run([_Probe("a", "LLM01")], target=_FakeTarget(refuse_all=True))
        self.assertEqual(block["measured_categories"], [])
        self.assertTrue(any(x["status"] == 0 for x in t.exchanges))

    def test_one_category_many_probes_counts_once(self):
        """Scenario 8."""
        block, _ = _run([_Probe("a", "LLM01"), _Probe("b", "LLM01"),
                         _Probe("c", "LLM01")])
        self.assertEqual(block["measured_categories"], ["LLM01"])
        self.assertEqual(block["measured_count"], 1)

    def test_a_partially_delivering_category_counts(self):
        """One probe of the category is refused, another delivers - the category was
        exercised."""
        block, _ = _run([_Probe("a", "LLM01", prompt=REFUSE), _Probe("b", "LLM01")])
        self.assertEqual(block["measured_categories"], ["LLM01"])

    def test_no_runtime_exchanges_measures_zero(self):
        """Scenario 9."""
        block, _ = _run([])
        self.assertEqual(block["measured_count"], 0)
        self.assertEqual(block["run_coverage_ratio"], 0.0)
        self.assertEqual(block["measured_categories"], [])

    def test_a_probe_that_delivers_then_crashes_still_counts(self):
        """The payload was delivered; the crash is after the fact."""
        class _Late(_Probe):
            def run(self, target, recon):
                target.send(self.prompt)
                raise RuntimeError("crashed after delivering")
        block, _ = _run([_Late("a", "LLM01")])
        self.assertEqual(block["measured_categories"], ["LLM01"])

    def test_measured_can_be_lower_than_capability(self):
        """Scenario 12 - the whole point of the metric."""
        block, _ = _run([_Probe("a", "LLM01"), _Probe("b", "LLM07", prompt=REFUSE)])
        capability = len(cp.summarize()["runtime_tested"])
        self.assertLess(block["measured_count"], capability)


# ---------------- custody (scenario 7) ----------------
class _Audit:
    def __init__(self):
        self.entries = []


class TestCustodyInteraction(unittest.TestCase):
    def test_incomplete_custody_is_flagged_not_silently_counted(self):
        t = _FakeTarget()
        t.audit = _Audit()                 # nothing ever vouched for
        res = Engine(t, selected_probes=[_Probe("a", "LLM01")], capture_evidence=False,
                     use_aakg=False, build_chains=False).run()
        block = res["coverage"]["run_measured_coverage"]
        self.assertFalse(block["custody_complete"])
        self.assertIn("LLM01", block["measured_categories"])
        self.assertIn("NOT VOUCHED", cov_mod.statement(res["coverage"]))

    def test_complete_custody_is_not_flagged(self):
        t = _FakeTarget()
        t.audit = _Audit()
        original_send = t.send

        def _send(prompt):                 # record custody for every exchange
            r = original_send(prompt)
            t.audit.entries.append({"e": prompt})
            return r
        t.send = _send
        res = Engine(t, selected_probes=[_Probe("a", "LLM01")], capture_evidence=False,
                     use_aakg=False, build_chains=False).run()
        block = res["coverage"]["run_measured_coverage"]
        self.assertTrue(block["custody_complete"])
        self.assertNotIn("NOT VOUCHED", cov_mod.statement(res["coverage"]))


# ---------------- nothing else moves ----------------
class TestNothingElseChanges(unittest.TestCase):
    def test_capability_coverage_is_unchanged(self):
        """Scenario 11. The registry-derived figure keeps its exact meaning and value."""
        s = cp.summarize()
        self.assertEqual(s["runtime_tested"],
                         ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"])
        self.assertEqual(s["runtime_coverage_ratio"], 0.54)

    def test_non_runtime_categories_are_never_measured(self):
        """Scenario 10. A questionnaire probe contacts no target, so it records nothing."""
        class _Quiet(_Probe):
            def run(self, target, recon):
                return []
        block, _ = _run([_Quiet("q", "LLM03"), _Quiet("v", "LLM08")])
        self.assertEqual(block["measured_categories"], [])

    def test_the_statement_reports_both_figures_distinctly(self):
        c = {"techniques_run": 3, "categories_tested": ["LLM01"],
             "categories_not_tested": ["LLM04"],
             "run_measured_coverage": {"universe": 13, "measured_categories": ["LLM01"],
                                       "measured_count": 1, "run_coverage_ratio": 0.08,
                                       "custody_complete": True}}
        s = cov_mod.statement(c)
        self.assertIn("Measured runtime coverage this run: 1/13 (0.08)", s)
        self.assertIn("capability", s)

    def test_the_measured_sentence_reads_the_block_not_the_graph_count(self):
        """The two figures must not be interchangeable. Here the graph-derived count is
        three and the measured count is one, so a statement that rendered the wrong one
        is visible."""
        c = {"techniques_run": 9,
             "categories_tested": ["LLM01", "LLM02", "LLM05"],
             "categories_not_tested": ["LLM04"],
             "run_measured_coverage": {"universe": 13, "measured_categories": ["LLM01"],
                                       "measured_count": 1, "run_coverage_ratio": 0.08,
                                       "custody_complete": True}}
        s = cov_mod.statement(c)
        self.assertIn("Measured runtime coverage this run: 1/13", s)
        self.assertNotIn("Measured runtime coverage this run: 3/13", s)

    def test_a_dict_without_the_block_omits_the_measured_sentence(self):
        c = {"techniques_run": 3, "categories_tested": ["LLM01"],
             "categories_not_tested": ["LLM04"]}
        self.assertNotIn("Measured runtime coverage", cov_mod.statement(c))

    def test_posture_and_risk_are_unchanged_on_the_demo_path(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o")
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = cli.main(["--demo", "--no-evidence", "--out", out])
            self.assertEqual(rc, 0)
            with open(out + ".json", encoding="utf-8") as fh:
                s = json.load(fh)["summary"]
        self.assertEqual(s["posture_score"], 42.7)
        self.assertEqual(s["risk_index"], 57.3)

    def test_json_and_sarif_do_not_gain_the_run_block(self):
        """No new machine-readable contract was approved for this PR."""
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o")
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = cli.main(["--demo", "--no-evidence", "--sarif", "--out", out])
            self.assertEqual(rc, 0)
            for suffix in (".json", ".sarif"):
                with open(out + suffix, encoding="utf-8") as fh:
                    txt = fh.read()
                self.assertNotIn("run_measured_coverage", txt, suffix)
                self.assertNotIn("run_coverage_ratio", txt, suffix)


if __name__ == "__main__":
    unittest.main()
