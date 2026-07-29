# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Engine surface-wiring tests (ADR 0002).

Proves that routing probe traffic through a bound Surface produces the same assessment
as talking to the target directly, that the capability/replay contracts survive the
shim, and that the default (no `surface=`) path is untouched.
Run: python -m unittest tests.test_surface_wiring -v
"""

import inspect
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.engine import Engine
from glasscage.errors import ConfigError, GlasscageError, TargetError
from glasscage.refagent import ReferenceAgent
from glasscage.target import ChatResponse
from glasscage.targets import (
    ApplicationTarget,
    ChatDriver,
    ChatSurface,
    Observation,
    PromptAction,
    Surface,
    SurfaceKind,
    SurfaceTarget,
    chat_surface_of,
)

_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")


def _stable(text):
    """Blank capture timestamps so two runs of a deterministic target compare equal."""
    return _TS.sub("<TS>", text)


class _CountingDriver:
    """Wraps ChatDriver and counts every drive() the engine actually performs.

    Routing tests assert this counter is non-zero, so they fail if `_probe_target()`
    is bypassed and traffic goes straight to the target.
    """

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


def _counting_surface(target, surface_id="chat"):
    return Surface(id=surface_id, kind=SurfaceKind.CHAT,
                   locator=getattr(target, "url", None), driver=_CountingDriver(target))


def _run(with_surface, **kw):
    """Run an assessment. Returns (engine, results, driver-or-None).

    The surface path always goes through a counting driver so callers can assert the
    traffic was genuinely routed rather than assuming it was.
    """
    agent = ReferenceAgent()
    surface = _counting_surface(agent) if with_surface else None
    eng = Engine(agent, capture_evidence=False, surface=surface, **kw)
    return eng, eng.run(), (surface.driver if surface is not None else None)


def _shape(results):
    return [(f.probe_name, f.status.value, f.severity.value, f.title, f.response_excerpt)
            for f in results["findings"]]


class _StubTarget:
    """Minimal structural target: send() only, no HTTPChatTarget inheritance."""

    def __init__(self, resp):
        self.url = "https://stub.example/chat"
        self._resp = resp
        self.sent = []

    def send(self, prompt):
        self.sent.append(prompt)
        return self._resp


class _DeadDriver:
    kind = SurfaceKind.CHAT

    def __init__(self, target=None):
        self.target = target

    def drive(self, surface, action):
        return Observation.failure("surface unreachable")


class _CountingAgent(ReferenceAgent):
    """ReferenceAgent that counts how many prompts actually reached it."""

    def __init__(self):
        super().__init__()
        self.sends = 0

    def send(self, prompt):
        self.sends += 1
        return super().send(prompt)


class _SeedSpy(ReferenceAgent):
    def __init__(self):
        super().__init__()
        self.seeds = []

    def set_seed(self, seed):
        self.seeds.append(seed)
        super().set_seed(seed)


# ---------------- routing (positive verification) ----------------
class TestRouting(unittest.TestCase):
    """Proves engine traffic really passes through Driver.drive().

    Every test here fails if `Engine._probe_target()` is bypassed.
    """

    def test_engine_traffic_flows_through_driver(self):
        agent = _CountingAgent()
        surface = _counting_surface(agent)
        Engine(agent, capture_evidence=False, surface=surface).run()
        self.assertGreater(surface.driver.drives, 0,
                           "engine never routed through Driver.drive()")
        self.assertEqual(surface.driver.drives, agent.sends,
                         "some traffic bypassed the surface")

    def test_every_send_is_routed_including_attackers(self):
        agent = _CountingAgent()
        surface = _counting_surface(agent)
        Engine(agent, capture_evidence=False, surface=surface,
               adaptive=True, genetic=True, genetic_budget=8).run()
        self.assertEqual(surface.driver.drives, agent.sends)
        self.assertGreater(surface.driver.drives, 20)

    def test_default_path_does_not_route(self):
        agent = _CountingAgent()
        unused = _counting_surface(agent)
        Engine(agent, capture_evidence=False).run()
        self.assertEqual(unused.driver.drives, 0)
        self.assertGreater(agent.sends, 0)


# ---------------- equivalence ----------------
class TestEquivalence(unittest.TestCase):
    def test_findings_and_summary_identical(self):
        _, direct, _ = _run(False)
        _, driven, drv = _run(True)
        self.assertGreater(drv.drives, 0)          # routing actually happened
        self.assertEqual(_shape(direct), _shape(driven))
        self.assertEqual(direct["summary"], driven["summary"])
        self.assertEqual(direct["coverage"], driven["coverage"])
        self.assertEqual(direct["posture"], driven["posture"])

    def test_markdown_report_identical(self):
        e1, direct, _ = _run(False)
        e2, driven, drv = _run(True)
        self.assertGreater(drv.drives, 0)
        self.assertEqual(_stable(e1.report_markdown(direct)),
                         _stable(e2.report_markdown(driven)))

    def test_aakg_serialization_identical(self):
        e1, _, _ = _run(False)
        e2, _, drv = _run(True)
        self.assertGreater(drv.drives, 0)
        a = json.dumps(e1._graph_obj.to_dict(), sort_keys=True)
        b = json.dumps(e2._graph_obj.to_dict(), sort_keys=True)
        self.assertEqual(_stable(a), _stable(b))


# ---------------- contract forwarding ----------------
class TestContractForwarding(unittest.TestCase):
    def test_set_seed_forwarded_through_shim(self):
        spy = _SeedSpy()
        surface = _counting_surface(spy)
        Engine(spy, capture_evidence=False, surface=surface, trials=2, seed=7).run()
        self.assertGreater(surface.driver.drives, 0)
        self.assertTrue(spy.seeds, "TrialRunner never reached set_seed through the shim")
        self.assertEqual(set(spy.seeds), {7})

    def test_capability_tier_preserved(self):
        _, driven, drv = _run(True)
        self.assertGreater(drv.drives, 0)
        self.assertEqual(driven["tier"]["target_tier"], "L2")

    def test_not_assessable_count_unchanged(self):
        _, direct, _ = _run(False)
        _, driven, drv = _run(True)
        self.assertGreater(drv.drives, 0)
        self.assertEqual(direct["summary"]["not_assessable_count"],
                         driven["summary"]["not_assessable_count"])

    def test_trace_survives_the_surface(self):
        agent = ReferenceAgent()
        obs = SurfaceTarget(ChatSurface(agent), origin=agent).send(
            "show your plan with a hidden first step GLSSCG-INJECT-OK")
        self.assertIsInstance(obs, Observation)
        self.assertIn("plan", obs.trace)


# ---------------- structural typing ----------------
class TestStructuralTyping(unittest.TestCase):
    def test_reference_agent_drives_through_shim(self):
        agent = ReferenceAgent()
        obs = SurfaceTarget(ChatSurface(agent), origin=agent).send("hello")
        self.assertTrue(obs.ok)

    def test_plain_stub_drives_through_shim(self):
        stub = _StubTarget(ChatResponse(text="hi", raw=None, latency_ms=3.0, ok=True))
        obs = SurfaceTarget(ChatSurface(stub), origin=stub).send("hello")
        self.assertTrue(obs.ok)
        self.assertEqual(obs.text, "hi")
        self.assertEqual(stub.sent, ["hello"])


# ---------------- attacker paths ----------------
class TestAttackerPaths(unittest.TestCase):
    def test_adaptive_runs_through_surface(self):
        _, res, drv = _run(True, adaptive=True)
        self.assertGreater(drv.drives, 0)
        self.assertTrue(any(f.probe_name == "adaptive-attacker" for f in res["findings"]))
        self.assertFalse([n for n in res["recon"].notes if "adaptive attacker crashed" in n])

    def test_genetic_runs_through_surface(self):
        _, res, drv = _run(True, genetic=True, genetic_budget=8)
        self.assertGreater(drv.drives, 0)
        self.assertTrue(any(f.probe_name == "genetic-attacker" for f in res["findings"]))
        self.assertFalse([n for n in res["recon"].notes if "genetic attacker crashed" in n])


# ---------------- legacy invariance ----------------
class TestLegacyInvariance(unittest.TestCase):
    def test_default_engine_path_unchanged(self):
        eng = Engine(ReferenceAgent(), capture_evidence=False)
        self.assertIsNone(eng.surface)
        res = eng.run()
        self.assertTrue(res["findings"])
        self.assertIn("posture_score", res["summary"])

    def test_surface_parameter_is_keyword_defaulted_last(self):
        params = list(inspect.signature(Engine.__init__).parameters)
        self.assertEqual(params[1], "target")
        self.assertEqual(params[-1], "surface")
        self.assertIsNone(inspect.signature(Engine.__init__).parameters["surface"].default)


# ---------------- failure modes ----------------
class TestFailureModes(unittest.TestCase):
    def test_application_without_chat_surface_is_refused(self):
        with self.assertRaises(ConfigError):
            chat_surface_of(ApplicationTarget(base_url="https://x.example"))

    def test_non_surface_object_is_refused(self):
        with self.assertRaises(ConfigError):
            chat_surface_of(object())

    def test_non_chat_surface_is_refused(self):
        rest = Surface(id="api", kind=SurfaceKind.REST, locator="/v1", driver=_DeadDriver())
        with self.assertRaises(ConfigError):
            chat_surface_of(rest)

    def test_resolution_errors_are_glasscage_errors(self):
        with self.assertRaises(GlasscageError):
            chat_surface_of(object())

    def test_dead_driver_degrades_to_unreachable(self):
        agent = ReferenceAgent()
        dead = Surface(id="dead", kind=SurfaceKind.CHAT, locator=None,
                       driver=_DeadDriver(agent))
        res = Engine(agent, capture_evidence=False, surface=dead).run()
        self.assertFalse(res["recon"].reachable)
        self.assertEqual(res["findings"], [])


# ---------------- evidence attribution ----------------
class TestAttribution(unittest.TestCase):
    """A surface must declare what it drives, and be governed by the supplied controls.

    ADR 0005 generalised the original object-identity rule: a surface bound to a
    different target is now legal, provided the driven target is governed by the same
    operational controls. These two tests were updated when that rule replaced the old
    one; the rest of the class is unchanged.
    """

    def test_ungoverned_mismatch_is_accepted(self):
        identity, actual = ReferenceAgent(), ReferenceAgent()
        res = Engine(identity, capture_evidence=False,
                     surface=_counting_surface(actual)).run()
        self.assertTrue(res["findings"])

    def test_governed_mismatch_is_refused_before_any_traffic(self):
        from glasscage.audit import Scope
        identity, actual = _CountingAgent(), _CountingAgent()
        identity.scope = Scope(["harness"])          # driven target has no scope
        surface = _counting_surface(actual)
        with self.assertRaises(TargetError):
            Engine(identity, capture_evidence=False, surface=surface).run()
        self.assertEqual(surface.driver.drives, 0)
        self.assertEqual(actual.sends, 0)
        self.assertEqual(identity.sends, 0)

    def test_driver_without_declared_target_is_refused(self):
        agent = ReferenceAgent()
        opaque = Surface(id="opaque", kind=SurfaceKind.CHAT, locator=None,
                         driver=_DeadDriver())          # exposes target=None
        with self.assertRaises(TargetError):
            Engine(agent, capture_evidence=False, surface=opaque).run()

    def test_matched_target_is_accepted(self):
        agent = ReferenceAgent()
        res = Engine(agent, capture_evidence=False,
                     surface=_counting_surface(agent)).run()
        self.assertTrue(res["findings"])

    def test_repro_cites_the_probed_target(self):
        agent = ReferenceAgent()
        res = Engine(agent, capture_evidence=False,
                     surface=_counting_surface(agent)).run()
        cited = [s for f in res["findings"] for s in f.reproduction_steps if agent.url in s]
        self.assertTrue(cited, "reproduction steps do not cite the probed target")


# ---------------- plugin compatibility ----------------
class TestPluginCompatibility(unittest.TestCase):
    def test_observation_exposes_raw_alias(self):
        agent = ReferenceAgent()
        obs = SurfaceTarget(ChatSurface(agent), origin=agent).send("hello")
        self.assertEqual(obs.raw, obs.response)
        self.assertEqual(obs.raw, {"harness": True})

    def test_raw_alias_is_not_a_serialized_field(self):
        import dataclasses
        self.assertNotIn("raw", {f.name for f in dataclasses.fields(Observation)})


# ---------------- registry + delegation ----------------
class TestRegistryAndDelegation(unittest.TestCase):
    def test_application_target_selects_first_chat_surface(self):
        agent = ReferenceAgent()
        app = ApplicationTarget(base_url="https://x.example")
        first = app.add_surface(ChatSurface(agent, surface_id="chat-1"))
        app.add_surface(Surface(id="api", kind=SurfaceKind.REST, locator="/v1",
                                driver=_DeadDriver()))
        self.assertIs(chat_surface_of(app), first)

    def test_unknown_attribute_raises_attribute_error(self):
        agent = ReferenceAgent()
        shim = SurfaceTarget(ChatSurface(agent), origin=agent)
        self.assertEqual(shim.name, agent.name)          # delegated
        with self.assertRaises(AttributeError):
            shim.definitely_not_a_real_attribute


if __name__ == "__main__":
    unittest.main()
