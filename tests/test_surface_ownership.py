# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Declared and governed ownership tests (ADR 0005).

Covers: a driver must declare what it drives; a driven target other than the supplied one
is legal when governance matches and refused when it does not; attribution (identity,
capability tier, reproduction) follows the driven target; every refusal is a typed error
raised before any traffic.
Run: python -m unittest tests.test_surface_ownership -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import AuditLog, RateLimiter, Scope
from glasscage.engine import Engine
from glasscage.errors import GlasscageError, TargetError
from glasscage.refagent import ReferenceAgent
from glasscage.targets import ChatDriver, ChatSurface, Surface, SurfaceKind, SurfaceTarget


class _CountingDriver:
    """Wraps ChatDriver and counts drives, so 'refused before any traffic' is provable."""

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


class _UndeclaredDriver:
    """A driver that cannot answer 'what do you drive?'."""

    kind = SurfaceKind.CHAT

    def drive(self, surface, action):
        raise AssertionError("must never be driven")


class _CountingAgent(ReferenceAgent):
    def __init__(self):
        super().__init__()
        self.sends = 0

    def send(self, prompt):
        self.sends += 1
        return super().send(prompt)


def _surface(target, sid="chat"):
    return Surface(id=sid, kind=SurfaceKind.CHAT, locator=getattr(target, "url", None),
                   driver=_CountingDriver(target))


# ---------------- declared ownership ----------------
class TestDeclaredOwnership(unittest.TestCase):
    def test_undeclared_driver_is_refused(self):
        agent = ReferenceAgent()
        opaque = Surface(id="opaque", kind=SurfaceKind.CHAT, locator=None,
                         driver=_UndeclaredDriver())
        with self.assertRaises(TargetError):
            SurfaceTarget(opaque, origin=agent)

    def test_declared_and_equal_is_accepted(self):
        agent = ReferenceAgent()
        self.assertIsNotNone(SurfaceTarget(_surface(agent), origin=agent))

    def test_declared_and_different_is_accepted_when_ungoverned(self):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        shim = SurfaceTarget(_surface(driven), origin=supplied)
        self.assertIs(shim.driven, driven)


# ---------------- governed ownership ----------------
class TestGovernedOwnership(unittest.TestCase):
    def _mismatch(self, control, value):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        setattr(supplied, control, value)
        surface = _surface(driven)
        with self.assertRaises(TargetError):
            SurfaceTarget(surface, origin=supplied)
        self.assertEqual(surface.driver.drives, 0)

    def test_scope_mismatch_is_refused(self):
        self._mismatch("scope", Scope(["harness"]))

    def test_rate_mismatch_is_refused(self):
        self._mismatch("rate", RateLimiter(100.0))

    def test_audit_mismatch_is_refused(self):
        self._mismatch("audit", AuditLog(None))

    def test_matching_controls_are_accepted(self):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        scope, rate, audit = Scope(["harness"]), RateLimiter(100.0), AuditLog(None)
        for obj in (supplied, driven):
            obj.scope, obj.rate, obj.audit = scope, rate, audit
        shim = SurfaceTarget(_surface(driven), origin=supplied)
        self.assertIs(shim.driven, driven)


# ---------------- attribution follows the driven target ----------------
class TestAttributionFollowsDrivenTarget(unittest.TestCase):
    def _pair(self):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        supplied.url = "https://supplied.example"
        driven.url = "https://driven.example"
        return supplied, driven

    def test_url_and_name_resolve_to_the_driven_target(self):
        supplied, driven = self._pair()
        shim = SurfaceTarget(_surface(driven), origin=supplied)
        self.assertEqual(shim.url, "https://driven.example")
        self.assertIs(shim.capabilities, driven.capabilities)

    def test_set_seed_reaches_the_driven_target(self):
        supplied, driven = self._pair()
        seen = []
        driven.set_seed = seen.append
        SurfaceTarget(_surface(driven), origin=supplied).set_seed(11)
        self.assertEqual(seen, [11])

    def test_reproduction_cites_the_driven_target(self):
        supplied, driven = self._pair()
        res = Engine(supplied, capture_evidence=False, surface=_surface(driven)).run()
        cited = [s for f in res["findings"] for s in f.reproduction_steps
                 if "driven.example" in s]
        self.assertTrue(cited, "reproduction steps do not cite the driven target")
        self.assertFalse([s for f in res["findings"] for s in f.reproduction_steps
                          if "supplied.example" in s])

    def test_capability_tier_comes_from_the_driven_target(self):
        from cli import _MockTarget
        supplied = _MockTarget()                      # L0
        driven = ReferenceAgent()                     # L2
        res = Engine(supplied, capture_evidence=False, surface=_surface(driven)).run()
        self.assertEqual(res["tier"]["target_tier"], "L2")


# ---------------- refusal timing and typing ----------------
class TestRefusalDiscipline(unittest.TestCase):
    def test_refusal_precedes_any_send(self):
        supplied, driven = _CountingAgent(), _CountingAgent()
        supplied.scope = Scope(["harness"])
        surface = _surface(driven)
        with self.assertRaises(TargetError):
            Engine(supplied, capture_evidence=False, surface=surface).run()
        self.assertEqual((surface.driver.drives, driven.sends, supplied.sends), (0, 0, 0))

    def test_undeclared_refusal_precedes_any_drive(self):
        agent = ReferenceAgent()
        opaque = Surface(id="opaque", kind=SurfaceKind.CHAT, locator=None,
                         driver=_UndeclaredDriver())
        with self.assertRaises(TargetError):
            Engine(agent, capture_evidence=False, surface=opaque).run()

    def test_refusals_are_glasscage_errors(self):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        supplied.rate = RateLimiter(100.0)
        with self.assertRaises(GlasscageError):
            SurfaceTarget(_surface(driven), origin=supplied)

    def test_no_origin_means_no_validation_and_no_delegation(self):
        agent = ReferenceAgent()
        shim = SurfaceTarget(ChatSurface(agent))       # origin omitted
        self.assertTrue(shim.send("hello").ok)
        with self.assertRaises(AttributeError):
            _ = shim.url


if __name__ == "__main__":
    unittest.main()
