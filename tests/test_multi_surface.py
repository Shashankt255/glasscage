# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Multi-surface execution tests (ADR 0011).

Covers: iteration over every resolved CHAT surface in `chat_surfaces_of()` order,
per-surface attribution, graph distinctness, per-surface recon isolation, per-surface
reproduction, validate-all-before-traffic, ApplicationTarget.scope verification, failure
semantics including total failure, determinism, backward compatibility, the run-level
`scope_confirmed` and `techniques_run` invariants, and PER_SURFACE budget reporting.
Run: python -m unittest tests.test_multi_surface -v
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import coverage as legacy_coverage
from glasscage.audit import Scope
from glasscage.engine import Engine
from glasscage.errors import TargetError
from glasscage.refagent import ReferenceAgent
from glasscage.targets import (
    ApplicationTarget,
    ChatDriver,
    Observation,
    Surface,
    SurfaceKind,
)

_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")
_ELIGIBLE = ("vulnerable", "inconclusive", "not_assessable")


def _stable(text):
    return _TS.sub("<TS>", text)


class _CountingAgent(ReferenceAgent):
    """ReferenceAgent that counts prompts and can carry a distinct tool surface."""

    def __init__(self, url="https://a.example", tools=None):
        super().__init__()
        self.url = url
        self.sends = 0
        if tools is not None:
            self.mcp_tools = list(tools)

    def send(self, prompt):
        self.sends += 1
        return super().send(prompt)


class _DeadDriver:
    kind = SurfaceKind.CHAT

    def __init__(self, target=None):
        self.target = target
        self.drives = 0

    def drive(self, surface, action):
        self.drives += 1
        return Observation.failure("surface unreachable")


class _CountingDriver:
    kind = SurfaceKind.CHAT

    def __init__(self, target):
        self._inner = ChatDriver(target)
        self.drives = 0

    @property
    def target(self):
        return self._inner.target

    def drive(self, surface, action):
        self.drives += 1
        return self._inner.drive(surface, action)


def _surface(target, sid):
    return Surface(id=sid, kind=SurfaceKind.CHAT, locator=getattr(target, "url", None),
                   driver=_CountingDriver(target))


def _app(*pairs, base_url="https://app.example", scope=None):
    """pairs: (target, surface_id). Returns (app, [surfaces])."""
    app = ApplicationTarget(base_url=base_url, scope=scope)
    surfaces = [app.add_surface(_surface(t, sid)) for t, sid in pairs]
    return app, surfaces


def _run_app(*pairs, origin=None, **kw):
    app, surfaces = _app(*pairs)
    target = origin if origin is not None else pairs[0][0]
    eng = Engine(target, capture_evidence=False, surface=app, **kw)
    return eng, eng.run(), app, surfaces


def _eligible(res):
    return [f for f in res["findings"] if f.status.value in _ELIGIBLE]


def _nodes(eng):
    return [n for n in eng._graph_obj.to_dict()["nodes"] if n["ntype"] == "Finding"]


# ---------------- iteration ----------------
class TestIteration(unittest.TestCase):
    def test_two_surfaces_are_both_driven(self):
        a = _CountingAgent()
        _, _, _, surfaces = _run_app((a, "chat-a"), (a, "chat-b"))
        for s in surfaces:
            self.assertGreater(s.driver.drives, 0)

    def test_five_surfaces_are_all_driven(self):
        a = _CountingAgent()
        pairs = [(a, f"s{i}") for i in range(5)]
        _, res, _, surfaces = _run_app(*pairs)
        self.assertEqual(len({s.driver.drives > 0 for s in surfaces}), 1)
        self.assertEqual(res["tier"]["surfaces_driven"], 5)

    def test_registration_order_is_preserved(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "zulu"), (a, "alpha"))
        order = [f.surface_id for f in res["findings"] if f.surface_id]
        self.assertEqual(order[0], "zulu")
        self.assertEqual(sorted(set(order)), ["alpha", "zulu"])

    def test_surfaces_driven_is_reported(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "x"), (a, "y"), (a, "z"))
        self.assertEqual(res["tier"]["surfaces_driven"], 3)


# ---------------- attribution ----------------
class TestAttribution(unittest.TestCase):
    def test_each_finding_carries_its_producing_surface(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "chat-a"), (a, "chat-b"))
        ids = {f.surface_id for f in res["findings"] if f.surface_id}
        self.assertEqual(ids, {"chat-a", "chat-b"})

    def test_each_surface_produces_the_same_probe_set(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "chat-a"), (a, "chat-b"))
        by = {}
        for f in res["findings"]:
            by.setdefault(f.surface_id, set()).add(f.probe_name)
        self.assertEqual(by["chat-a"], by["chat-b"])

    def test_config_review_findings_are_unattributed(self):
        a = _CountingAgent()
        m = json.load(open(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                        "samples", "mcp_manifest.json"), encoding="utf-8"))
        _, res, _, _ = _run_app((a, "chat-a"), (a, "chat-b"), mcp_manifest=m)
        mcp = [f for f in res["findings"] if f.owasp_id.startswith("MCP")]
        self.assertTrue(mcp)
        for f in mcp:
            self.assertEqual(f.surface_id, "")


# ---------------- graph distinctness ----------------
class TestGraphDistinctness(unittest.TestCase):
    def test_same_probe_on_two_surfaces_yields_two_nodes(self):
        a = _CountingAgent()
        eng, _, _, _ = _run_app((a, "chat-a"), (a, "chat-b"))
        ids = [n["id"] for n in _nodes(eng)]
        self.assertIn("Finding:LLM01:direct-injection-canary:chat-a:3cb153335f4a", ids)
        self.assertIn("Finding:LLM01:direct-injection-canary:chat-b:3cb153335f4a", ids)

    def test_node_count_equals_eligible_finding_count(self):
        a = _CountingAgent()
        eng, res, _, _ = _run_app((a, "chat-a"), (a, "chat-b"))
        self.assertEqual(len(_nodes(eng)), len(_eligible(res)))

    def test_no_evidence_is_merged_across_surfaces(self):
        a = _CountingAgent()
        eng, _, _, _ = _run_app((a, "chat-a"), (a, "chat-b"))
        ids = [n["id"] for n in _nodes(eng)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_three_independent_surfaces_triple_the_nodes(self):
        # Distinct targets per surface: ReferenceAgent is stateful, so sharing one
        # target across surfaces legitimately lets earlier surfaces affect later ones.
        e1, _, _, _ = _run_app((_CountingAgent(), "one"))
        agents = [_CountingAgent(url=f"https://s{i}.example") for i in range(3)]
        e3, _, _, _ = _run_app(*[(t, sid) for t, sid in zip(agents, "abc")],
                               origin=agents[0])
        self.assertEqual(len(_nodes(e3)), 3 * len(_nodes(e1)))


# ---------------- recon isolation ----------------
class TestReconIsolation(unittest.TestCase):
    def test_each_surface_gets_its_own_recon(self):
        with_tools = _CountingAgent(url="https://with.example")
        without = _CountingAgent(url="https://without.example", tools=[])
        _, res, _, _ = _run_app((with_tools, "has"), (without, "none"),
                                origin=with_tools)
        by = {(f.surface_id, f.probe_name): f.status.value
              for f in res["findings"] if f.probe_name == "excessive-agency-review"}
        self.assertEqual(by[("has", "excessive-agency-review")], "inconclusive")
        self.assertEqual(by[("none", "excessive-agency-review")], "passed")

    def test_merged_tool_surface_is_a_union(self):
        a = _CountingAgent(tools=["filesystem"])
        b = _CountingAgent(url="https://b.example", tools=["email"])
        _, res, _, _ = _run_app((a, "a"), (b, "b"), origin=a)
        merged = " ".join(res["recon"].tool_surface).lower()
        self.assertIn("filesystem", merged)
        self.assertIn("email", merged)

    def test_single_surface_recon_object_is_passed_through(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "only"))
        self.assertTrue(res["recon"].reachable)
        self.assertTrue(res["recon"].tool_surface)


# ---------------- reproduction ----------------
class TestReproduction(unittest.TestCase):
    def test_each_surface_cites_its_own_target(self):
        a = _CountingAgent(url="https://alpha.example")
        b = _CountingAgent(url="https://beta.example")
        _, res, _, _ = _run_app((a, "a"), (b, "b"), origin=a)
        for f in res["findings"]:
            if not f.surface_id or not f.reproduction_steps:
                continue
            joined = " ".join(f.reproduction_steps)
            other = "beta.example" if f.surface_id == "a" else "alpha.example"
            self.assertNotIn(other, joined)

    def test_config_review_steps_are_unaffected(self):
        a = _CountingAgent()
        m = json.load(open(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                        "samples", "mcp_manifest.json"), encoding="utf-8"))
        _, res, _, _ = _run_app((a, "a"), (a, "b"), mcp_manifest=m)
        mcp = [f for f in res["findings"] if f.probe_name == "mcp-analyzer"]
        self.assertTrue(all(f.reproduction_steps for f in mcp))


# ---------------- ownership and scope ----------------
class TestOwnershipAndScope(unittest.TestCase):
    def test_all_surfaces_validated_before_any_traffic(self):
        a, b = _CountingAgent(), _CountingAgent(url="https://b.example")
        a.scope = Scope(["harness"])          # b is ungoverned -> refusal on surface 2
        app, surfaces = _app((a, "ok"), (b, "bad"))
        with self.assertRaises(TargetError):
            Engine(a, capture_evidence=False, surface=app).run()
        for s in surfaces:
            self.assertEqual(s.driver.drives, 0)
        self.assertEqual((a.sends, b.sends), (0, 0))

    def test_application_scope_mismatch_is_refused(self):
        a = _CountingAgent()
        app, surfaces = _app((a, "only"), scope=Scope(["harness"]))
        with self.assertRaises(TargetError):
            Engine(a, capture_evidence=False, surface=app).run()
        self.assertEqual(surfaces[0].driver.drives, 0)

    def test_application_scope_match_is_accepted(self):
        scope = Scope(["harness"])
        a = _CountingAgent()
        a.scope = scope
        app, _ = _app((a, "only"), scope=scope)
        res = Engine(a, capture_evidence=False, surface=app).run()
        self.assertTrue(res["findings"])

    def test_undeclared_driver_is_refused(self):
        a = _CountingAgent()
        app = ApplicationTarget(base_url="https://x.example")
        app.add_surface(Surface(id="opaque", kind=SurfaceKind.CHAT, locator=None,
                                driver=_DeadDriver()))
        with self.assertRaises(TargetError):
            Engine(a, capture_evidence=False, surface=app).run()


# ---------------- failure semantics ----------------
class TestFailureSemantics(unittest.TestCase):
    def test_dead_surface_does_not_suppress_a_live_one(self):
        a = _CountingAgent()
        app = ApplicationTarget(base_url="https://x.example")
        app.add_surface(Surface(id="dead", kind=SurfaceKind.CHAT, locator=None,
                                driver=_DeadDriver(a)))
        live = app.add_surface(_surface(a, "live"))
        res = Engine(a, capture_evidence=False, surface=app).run()
        self.assertGreater(live.driver.drives, 0)
        self.assertTrue([f for f in res["findings"] if f.surface_id == "live"])
        self.assertFalse([f for f in res["findings"] if f.surface_id == "dead"])

    def test_unreachable_surface_is_named_in_notes(self):
        a = _CountingAgent()
        app = ApplicationTarget(base_url="https://x.example")
        app.add_surface(Surface(id="dead", kind=SurfaceKind.CHAT, locator=None,
                                driver=_DeadDriver(a)))
        app.add_surface(_surface(a, "live"))
        res = Engine(a, capture_evidence=False, surface=app).run()
        self.assertTrue([n for n in res["recon"].notes if "dead" in n])


# ---------------- total failure (INV-4) ----------------
class TestTotalFailure(unittest.TestCase):
    def _all_dead(self):
        a = _CountingAgent()
        app = ApplicationTarget(base_url="https://x.example")
        for sid in ("d1", "d2"):
            app.add_surface(Surface(id=sid, kind=SurfaceKind.CHAT, locator=None,
                                    driver=_DeadDriver(a)))
        return Engine(a, capture_evidence=False, surface=app).run()

    def test_run_completes_with_reachable_false(self):
        res = self._all_dead()
        self.assertFalse(res["recon"].reachable)

    def test_every_unreachable_surface_is_named(self):
        res = self._all_dead()
        notes = " ".join(res["recon"].notes)
        self.assertIn("d1", notes)
        self.assertIn("d2", notes)


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_identical_runs_produce_identical_graphs(self):
        def once():
            a = _CountingAgent()
            eng, _, _, _ = _run_app((a, "a"), (a, "b"))
            return _stable(json.dumps(eng._graph_obj.to_dict(), sort_keys=True))
        self.assertEqual(once(), once())

    def test_node_ids_do_not_depend_on_surface_count(self):
        # Fresh targets per run: a shared ReferenceAgent would carry poisoned memory
        # from the first run into the second.
        e1, _, _, _ = _run_app((_CountingAgent(), "shared"))
        a, b = _CountingAgent(), _CountingAgent(url="https://b.example")
        e2, _, _, _ = _run_app((a, "shared"), (b, "extra"), origin=a)
        one = {n["id"] for n in _nodes(e1)}
        many = {n["id"] for n in _nodes(e2)}
        self.assertTrue(one <= many)


# ---------------- backward compatibility ----------------
class TestBackwardCompatibility(unittest.TestCase):
    def test_no_surface_run_is_unattributed(self):
        res = Engine(_CountingAgent(), capture_evidence=False).run()
        self.assertTrue(res["findings"])
        for f in res["findings"]:
            self.assertEqual(f.surface_id, "")

    def test_single_surface_is_behaviourally_identical_to_direct(self):
        direct = Engine(_CountingAgent(), capture_evidence=False).run()
        a = _CountingAgent()
        _, driven, _, _ = _run_app((a, "chat"))
        shape = lambda r: [(f.probe_name, f.status.value, f.severity.value)
                           for f in r["findings"]]
        self.assertEqual(shape(direct), shape(driven))


# ---------------- report identity ----------------
class TestReportIdentity(unittest.TestCase):
    def test_application_run_names_the_application(self):
        a = _CountingAgent()
        eng, _, _, _ = _run_app((a, "a"), (a, "b"))
        self.assertEqual(eng._report_identity(), "https://app.example")

    def test_direct_run_names_the_target(self):
        a = _CountingAgent()
        eng = Engine(a, capture_evidence=False)
        self.assertEqual(eng._report_identity(), a.name)


# ---------------- INV-2: scope_confirmed is run-level ----------------
class TestScopeConfirmedIsRunLevel(unittest.TestCase):
    _SCHEMA = [{"name": "run_sql", "capability": "write", "side_effect": True,
                "provenance": "schema-confirmed"}]

    def _severities(self, n_surfaces):
        a = _CountingAgent()
        pairs = [(a, f"s{i}") for i in range(n_surfaces)]
        _, res, _, _ = _run_app(*pairs, schema_tools=self._SCHEMA)
        return {f.probe_name: f.severity.value
                for f in res["findings"] if f.surface_id == "s0"}

    def test_severities_are_identical_regardless_of_surface_count(self):
        self.assertEqual(self._severities(1), self._severities(3))

    def test_severities_match_a_direct_run(self):
        direct = Engine(_CountingAgent(), capture_evidence=False,
                        schema_tools=self._SCHEMA).run()
        expected = {f.probe_name: f.severity.value for f in direct["findings"]}
        got = self._severities(3)
        for probe, sev in got.items():
            self.assertEqual(sev, expected[probe])


# ---------------- techniques_run ----------------
class TestTechniquesRun(unittest.TestCase):
    def test_surface_count_independent(self):
        a = _CountingAgent()
        _, one, _, _ = _run_app((a, "a"))
        _, three, _, _ = _run_app((a, "a"), (a, "b"), (a, "c"))
        self.assertEqual(one["coverage"]["techniques_run"],
                         three["coverage"]["techniques_run"])

    def test_agrees_with_the_legacy_coverage_figure(self):
        a = _CountingAgent()
        eng, res, _, _ = _run_app((a, "a"), (a, "b"))
        legacy = legacy_coverage.build(res["findings"], eng.probes)["techniques_run"]
        self.assertEqual(res["coverage"]["techniques_run"], legacy)

    def test_counts_distinct_probes_not_findings(self):
        a = _CountingAgent()
        eng, res, _, _ = _run_app((a, "a"), (a, "b"))
        self.assertLess(res["coverage"]["techniques_run"], len(_eligible(res)))


# ---------------- PER_SURFACE budget (INV-3) ----------------
class TestPerSurfaceBudget(unittest.TestCase):
    def test_contract_is_named(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "a"))
        self.assertEqual(res["tier"]["attacker_budget_contract"], "PER_SURFACE")

    def test_effective_budget_scales_with_surfaces(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "a"), (a, "b"), adaptive=True, adaptive_budget=8,
                                genetic=True, genetic_budget=6)
        self.assertEqual(res["tier"]["effective_adaptive_budget"], 16)
        self.assertEqual(res["tier"]["effective_genetic_budget"], 12)

    def test_effective_budget_is_zero_when_attackers_are_off(self):
        a = _CountingAgent()
        _, res, _, _ = _run_app((a, "a"), (a, "b"))
        self.assertEqual(res["tier"]["effective_adaptive_budget"], 0)
        self.assertEqual(res["tier"]["effective_genetic_budget"], 0)


if __name__ == "__main__":
    unittest.main()
