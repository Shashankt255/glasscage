# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Recorded correctness defects (PR #18).

Four defects, each named by an ADR or found during ADR-driven review:

  D1  `rest.py` told operators REST has no CLI path and never crosses `--authorized`.
      PR #16 gave it both; ADR 0015 records the wording as owed.
  D2  `schema.from_openapi` raised AttributeError on a path whose value is not an object,
      while `discovery.discover_openapi` skipped it (ADR 0003's "Note for the next PR").
  D3  `redact_finding` wrote its count to `f.metadata`, a field `Finding` does not declare,
      so `dataclasses.asdict` never saw it and the value reached no artifact.
  D4  The adaptive and genetic attackers ran regardless of the driven surface kind. On a
      REST surface that produced an unhandled AttributeError out of reproduction.

The D4 tests are the load-bearing ones: they must fail against the baseline with that
exact exception, or they are not reproducing the defect.

Run: python -m unittest tests.test_correctness_defects -v
"""

import dataclasses
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import redaction, schema
from glasscage.audit import Scope
from glasscage.engine import Engine
from glasscage.errors import TargetError
from glasscage.models import Finding, Severity, Status
from glasscage.refagent import ReferenceAgent
from glasscage.targets import (ApplicationTarget, ChatSurface, RestTarget, SurfaceTarget,
                               bind_candidate, discover_openapi, rest_surface_from_target)

_REST_SRC = os.path.join(os.path.dirname(__file__), "..", "glasscage", "targets", "rest.py")
_SPEC = {"paths": {"/u": {"get": {}}}}


class _Resp:
    status = 200

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _rest_app(scope_hosts=("api.example",)):
    t = RestTarget("https://api.example/v1")
    if scope_hosts is not None:
        t.scope = Scope(list(scope_hosts))
    app = ApplicationTarget(base_url=t.url)
    for c in discover_openapi(_SPEC):
        app.add_surface(bind_candidate(c, t))
    return t, app


def _finding(**kw):
    base = dict(probe_name="p", title="t", owasp_id="LLM02", category="c",
                status=Status.VULNERABLE, severity=Severity.HIGH)
    base.update(kw)
    return Finding(**base)


# ---------------- D1 ----------------
class TestRestWordingIsCorrect(unittest.TestCase):
    _FALSE_CLAIMS = ("has no CLI path", "which REST never crosses",
                     "REST has no --authorized gate", "gate that does not exist for REST")

    def test_source_asserts_no_false_claim(self):
        with open(_REST_SRC, encoding="utf-8") as fh:
            src = fh.read()
        for claim in self._FALSE_CLAIMS:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, src)

    def test_refusal_message_carries_no_false_claim(self):
        t = RestTarget("https://api.example/v1")
        surface = rest_surface_from_target(t, "GET", "/u")
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(surface, origin=t)
        for claim in self._FALSE_CLAIMS:
            self.assertNotIn(claim, str(ctx.exception))

    def test_absent_scope_is_still_refused(self):
        """D1 is wording only — R1's behaviour must be untouched."""
        t = RestTarget("https://api.example/v1")
        surface = rest_surface_from_target(t, "GET", "/u")
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("no request may be issued")):
            with self.assertRaises(TargetError) as ctx:
                SurfaceTarget(surface, origin=t)
        self.assertIn("holds no scope", str(ctx.exception))

    def test_empty_scope_is_still_refused(self):
        t = RestTarget("https://api.example/v1")
        t.scope = Scope([])
        surface = rest_surface_from_target(t, "GET", "/u")
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(surface, origin=t)
        self.assertIn("empty scope", str(ctx.exception))

    def test_non_empty_scope_is_still_accepted(self):
        t = RestTarget("https://api.example/v1")
        t.scope = Scope(["api.example"])
        self.assertIsNotNone(
            SurfaceTarget(rest_surface_from_target(t, "GET", "/u"), origin=t))


# ---------------- D2 ----------------
class TestSchemaSkipsMalformedPaths(unittest.TestCase):
    def test_adr_0003_case_returns_empty(self):
        self.assertEqual(schema.from_openapi({"paths": {"/x": "oops"}}), [])

    def test_malformed_entry_does_not_suppress_valid_siblings(self):
        tools = schema.from_openapi(
            {"paths": {"/bad": "oops", "/good": {"get": {"operationId": "getGood"}}}})
        self.assertEqual([t["name"] for t in tools], ["getGood"])

    def test_other_malformed_shapes_are_skipped(self):
        for bad in ("oops", 3, [], None, True):
            with self.subTest(value=bad):
                self.assertEqual(schema.from_openapi({"paths": {"/x": bad}}), [])

    def test_well_formed_output_is_unchanged(self):
        tools = schema.from_openapi(
            {"paths": {"/u": {"get": {"operationId": "listUsers"},
                              "post": {"operationId": "createUser"}}}})
        self.assertEqual(sorted(t["name"] for t in tools), ["createUser", "listUsers"])

    def test_matches_discovery_on_the_same_document(self):
        """ADR 0003 drew the contrast: discovery skipped, schema raised. Both now skip."""
        doc = {"paths": {"/x": "oops"}}
        self.assertEqual(schema.from_openapi(doc), [])
        self.assertEqual(discover_openapi(doc), [])


# ---------------- D3 ----------------
class TestRedactionLeavesNoDeadState(unittest.TestCase):
    def test_no_undeclared_attribute_is_set(self):
        f = _finding(response_excerpt="key sk-ABCDEFGHIJKLMNOP0123")
        redaction.redact_finding(f)
        declared = {x.name for x in dataclasses.fields(Finding)}
        self.assertEqual(set(vars(f)) - declared, set())

    def test_redaction_behaviour_is_unchanged(self):
        f = _finding(response_excerpt="key sk-ABCDEFGHIJKLMNOP0123")
        n = redaction.redact_finding(f)
        self.assertEqual(n, 1)
        self.assertNotIn("sk-ABCDEFGHIJKLMNOP0123", f.response_excerpt)
        self.assertIn("[REDACTED:", f.response_excerpt)

    def test_the_count_is_still_returned(self):
        f = _finding(response_excerpt="sk-ABCDEFGHIJKLMNOP0123",
                     raw_response="sk-ABCDEFGHIJKLMNOP0123")
        self.assertEqual(redaction.redact_finding(f), 2)

    def test_finding_field_count_is_unchanged(self):
        self.assertEqual(len(dataclasses.fields(Finding)), 41)

    def test_clean_finding_is_untouched(self):
        f = _finding(response_excerpt="nothing secret here")
        self.assertEqual(redaction.redact_finding(f), 0)
        self.assertEqual(f.response_excerpt, "nothing secret here")


# ---------------- D4 ----------------
class TestAttackersAreSurfaceGated(unittest.TestCase):
    def _rest_run(self, **kw):
        t, app = _rest_app()
        with mock.patch("urllib.request.urlopen", return_value=_Resp()):
            return Engine(t, surface=app, capture_evidence=False, use_aakg=False,
                          **kw).run()

    def _attackers(self, res):
        return [f for f in res["findings"] if f.probe_name.endswith("-attacker")]

    def test_adaptive_on_a_rest_surface_does_not_crash(self):
        """Reproduces the defect: this raised AttributeError from repro.build_all."""
        res = self._rest_run(adaptive=True, adaptive_budget=2)
        self.assertTrue(res["findings"])

    def test_genetic_on_a_rest_surface_does_not_crash(self):
        res = self._rest_run(genetic=True, genetic_budget=4)
        self.assertTrue(res["findings"])

    def test_adaptive_is_reported_not_assessable(self):
        atk = self._attackers(self._rest_run(adaptive=True, adaptive_budget=2))
        self.assertEqual([f.probe_name for f in atk], ["adaptive-attacker"])
        self.assertIs(atk[0].status, Status.NOT_ASSESSABLE)
        self.assertEqual(atk[0].prompt, "(surface-gated)")

    def test_genetic_is_reported_not_assessable(self):
        atk = self._attackers(self._rest_run(genetic=True, genetic_budget=4))
        self.assertEqual([f.probe_name for f in atk], ["genetic-attacker"])
        self.assertIs(atk[0].status, Status.NOT_ASSESSABLE)

    def test_gated_attacker_names_the_driven_kind(self):
        atk = self._attackers(self._rest_run(adaptive=True, adaptive_budget=2))
        self.assertIn("rest surface", atk[0].title)
        self.assertIn("NOT ASSESSABLE", atk[0].title)

    def test_gating_is_reported_not_silent(self):
        """ADR 0006's discipline: an operator who asked for the attacker must be able to
        see that it did not run."""
        without = self._rest_run()
        with_ = self._rest_run(adaptive=True, adaptive_budget=2)
        self.assertEqual(len(with_["findings"]), len(without["findings"]) + 1)

    def test_rest_run_without_attackers_is_unchanged(self):
        self.assertEqual(len(self._rest_run()["findings"]), 22)

    def test_chat_attackers_still_run(self):
        agent = ReferenceAgent()
        res = Engine(agent, surface=ChatSurface(agent), capture_evidence=False,
                     use_aakg=False, adaptive=True, adaptive_budget=2).run()
        atk = self._attackers(res)
        self.assertEqual([f.probe_name for f in atk], ["adaptive-attacker"])
        self.assertIsNot(atk[0].status, Status.NOT_ASSESSABLE)

    def test_chat_genetic_still_runs(self):
        agent = ReferenceAgent()
        res = Engine(agent, surface=ChatSurface(agent), capture_evidence=False,
                     use_aakg=False, genetic=True, genetic_budget=4).run()
        atk = self._attackers(res)
        self.assertEqual([f.probe_name for f in atk], ["genetic-attacker"])
        self.assertIsNot(atk[0].status, Status.NOT_ASSESSABLE)

    def test_direct_run_attackers_are_unaffected(self):
        """No bound surface resolves to CHAT (ADR 0006), so the legacy path is untouched."""
        res = Engine(ReferenceAgent(), capture_evidence=False, use_aakg=False,
                     adaptive=True, adaptive_budget=2).run()
        atk = self._attackers(res)
        self.assertEqual([f.probe_name for f in atk], ["adaptive-attacker"])
        self.assertIsNot(atk[0].status, Status.NOT_ASSESSABLE)


# ---------------- cross-cutting invariants ----------------
class TestFrozenInvariants(unittest.TestCase):
    def test_runtime_coverage_ratio_and_buckets_unchanged(self):
        from glasscage import coverage_provenance as cp
        s = cp.summarize()
        self.assertEqual(s["runtime_coverage_ratio"], 0.54)
        self.assertEqual(s["config_review_only"], ["MCP03", "MCP07"])
        self.assertEqual(s["not_tested"], ["LLM04", "MULTIMODAL"])

    def test_battery_size_unchanged(self):
        from glasscage.probes import all_probes
        self.assertEqual(len(all_probes()), 22)


if __name__ == "__main__":
    unittest.main()
