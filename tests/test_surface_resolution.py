# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface resolution contract tests (ADR 0009).

Covers: plural resolution, registration ordering (deliberately not id-sorted), first-wins
deduplication, exact equivalence and message parity between the plural and singular
forms, and the separation between resolution (ConfigError) and ownership validation
(TargetError, raised only when a SurfaceTarget is constructed).
Run: python -m unittest tests.test_surface_resolution -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.errors import ConfigError, GlasscageError, TargetError
from glasscage.refagent import ReferenceAgent
from glasscage.targets import (
    ApplicationTarget,
    ChatDriver,
    ChatSurface,
    Surface,
    SurfaceKind,
    SurfaceTarget,
    chat_surface_of,
    chat_surfaces_of,
)

_NON_CHAT = "only CHAT surfaces are drivable in this release, got "
_NO_CHAT = "ApplicationTarget registers no CHAT surface to drive"
_WRONG_TYPE = "expected a Surface or ApplicationTarget, got "


def _chat(target=None, sid="chat"):
    return ChatSurface(target if target is not None else ReferenceAgent(), surface_id=sid)


def _rest(sid="api"):
    return Surface(id=sid, kind=SurfaceKind.REST, locator="/v1",
                   driver=ChatDriver(ReferenceAgent()))


# ---------------- plural resolution ----------------
class TestPluralResolution(unittest.TestCase):
    def test_single_surface_yields_one_element(self):
        s = _chat()
        self.assertEqual(chat_surfaces_of(s), [s])

    def test_application_yields_all_chat_surfaces_in_registration_order(self):
        app = ApplicationTarget(base_url="https://x.example")
        first = app.add_surface(_chat(sid="alpha"))
        app.add_surface(_rest("api"))
        second = app.add_surface(_chat(sid="beta"))
        self.assertEqual([s.id for s in chat_surfaces_of(app)], ["alpha", "beta"])
        self.assertEqual(chat_surfaces_of(app), [first, second])

    def test_non_chat_surfaces_are_excluded(self):
        app = ApplicationTarget()
        app.add_surface(_rest("r1"))
        app.add_surface(_chat(sid="c1"))
        app.add_surface(_rest("r2"))
        self.assertEqual([s.id for s in chat_surfaces_of(app)], ["c1"])

    def test_single_chat_application_yields_one_element(self):
        app = ApplicationTarget()
        only = app.add_surface(_chat(sid="only"))
        self.assertEqual(chat_surfaces_of(app), [only])


# ---------------- ordering and deduplication ----------------
class TestOrderingAndDedup(unittest.TestCase):
    def test_order_is_registration_not_sorted_by_id(self):
        app = ApplicationTarget()
        app.add_surface(_chat(sid="zulu"))
        app.add_surface(_chat(sid="alpha"))
        ids = [s.id for s in chat_surfaces_of(app)]
        self.assertEqual(ids, ["zulu", "alpha"])
        self.assertNotEqual(ids, sorted(ids))   # explicitly NOT id-sorted

    def test_duplicate_ids_collapse_first_wins(self):
        a, b = _chat(sid="dup"), _chat(sid="dup")
        app = ApplicationTarget(surfaces=[a, b, _chat(sid="other")])
        resolved = chat_surfaces_of(app)
        self.assertEqual([s.id for s in resolved], ["dup", "other"])
        self.assertIs(resolved[0], a)

    def test_order_is_stable_across_calls(self):
        app = ApplicationTarget()
        for sid in ("one", "two", "three"):
            app.add_surface(_chat(sid=sid))
        self.assertEqual([s.id for s in chat_surfaces_of(app)],
                         [s.id for s in chat_surfaces_of(app)])


# ---------------- singular equivalence ----------------
class TestSingularEquivalence(unittest.TestCase):
    def test_singular_is_the_first_plural_result(self):
        s = _chat()
        app_one = ApplicationTarget(surfaces=[_chat(sid="solo")])
        app_many = ApplicationTarget(surfaces=[_chat(sid="a"), _chat(sid="b")])
        for source in (s, app_one, app_many):
            self.assertIs(chat_surface_of(source), chat_surfaces_of(source)[0])

    def test_singular_returns_the_first_registered_surface(self):
        app = ApplicationTarget(base_url="https://x.example")
        first = app.add_surface(_chat(sid="first"))
        app.add_surface(_chat(sid="second"))
        self.assertIs(chat_surface_of(app), first)


# ---------------- refusal parity ----------------
class TestRefusalParity(unittest.TestCase):
    def _both(self, source):
        out = []
        for fn in (chat_surfaces_of, chat_surface_of):
            with self.assertRaises(ConfigError) as ctx:
                fn(source)
            out.append(str(ctx.exception))
        return out

    def test_non_chat_surface_refused_identically(self):
        for msg in self._both(_rest()):
            self.assertTrue(msg.startswith(_NON_CHAT), msg)

    def test_empty_application_refused_identically(self):
        for msg in self._both(ApplicationTarget(base_url="https://x.example")):
            self.assertEqual(msg, _NO_CHAT)

    def test_wrong_type_refused_identically(self):
        for msg in self._both(object()):
            self.assertTrue(msg.startswith(_WRONG_TYPE), msg)
            self.assertIn("object", msg)

    def test_refusals_are_glasscage_errors(self):
        with self.assertRaises(GlasscageError):
            chat_surfaces_of(object())


# ---------------- resolution does not validate ownership ----------------
class TestResolutionDoesNotValidateOwnership(unittest.TestCase):
    def test_mismatched_ownership_resolves_but_is_refused_at_construction(self):
        supplied, driven = ReferenceAgent(), ReferenceAgent()
        supplied.scope = object()                      # governed; driven is not
        surface = _chat(driven)
        self.assertEqual(chat_surfaces_of(surface), [surface])   # resolution succeeds
        with self.assertRaises(TargetError):                     # guard still refuses
            SurfaceTarget(surface, origin=supplied)


if __name__ == "__main__":
    unittest.main()
