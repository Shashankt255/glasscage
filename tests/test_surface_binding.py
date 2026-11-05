# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface binding tests (ADR 0014, PR #15).

`discovery` has emitted `SurfaceCandidate`s since ADR 0003 and nothing consumed them:
"Candidates are never bound to a Driver here... binding cannot happen until per-surface
attribution exists". Attribution landed in ADR 0004/0011 and a REST driver in ADR 0012,
so binding is now possible for the one candidate kind that has a driver.

The load-bearing assertions are that binding stays *pure resolution*: it issues no
request, constructs no target, and raises `ConfigError` rather than `TargetError`, leaving
ownership, governance and the fail-closed scope check at `SurfaceTarget` construction
where ADR 0005 and ADR 0012 put them.

No network: urllib.request.urlopen is patched wherever a bound surface is driven.
Run: python -m unittest tests.test_surface_binding -v
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import Scope
from glasscage.errors import ConfigError, TargetError
from glasscage.targets import (
    ApplicationTarget,
    HttpAction,
    RestDriver,
    RestTarget,
    Surface,
    SurfaceCandidate,
    SurfaceKind,
    SurfaceTarget,
    bind_candidate,
    discover_openapi,
    drivable_surfaces_of,
)
from glasscage.targets import discovery as discovery_mod

_HOST = "api.example"
_BASE = f"https://{_HOST}/v1"

_SPEC = {"paths": {
    "/users": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    "/admin/keys": {"get": {}},
}}


class _Resp:
    def __init__(self, body='{"ok":1}', status=200):
        self._b, self.status = body.encode("utf-8"), status

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patched():
    return mock.patch("urllib.request.urlopen", return_value=_Resp())


def _target(scope_hosts=(_HOST,)):
    t = RestTarget(_BASE)
    if scope_hosts is not None:
        t.scope = Scope(list(scope_hosts))
    return t


def _candidate(kind=SurfaceKind.REST, cid="rest:get:/users",
               locator=None, io_schema=None):
    if locator is None and kind is SurfaceKind.REST:
        locator = {"method": "GET", "path": "/users"}
    return SurfaceCandidate(id=cid, kind=kind, locator=locator,
                            io_schema=io_schema, source="test")


# ---------------- round trip ----------------
class TestRoundTrip(unittest.TestCase):
    def test_discovered_candidate_binds_to_a_surface(self):
        candidate = discover_openapi(_SPEC)[0]
        surface = bind_candidate(candidate, _target())
        self.assertIsInstance(surface, Surface)
        self.assertIs(surface.kind, SurfaceKind.REST)

    def test_bound_surface_keeps_the_candidate_id(self):
        for candidate in discover_openapi(_SPEC):
            with self.subTest(candidate=candidate.id):
                self.assertEqual(bind_candidate(candidate, _target()).id, candidate.id)

    def test_locator_is_carried_through_unmodified(self):
        candidate = _candidate(locator={"method": "POST", "path": "/x", "extra": 1})
        self.assertEqual(bind_candidate(candidate, _target()).locator,
                         {"method": "POST", "path": "/x", "extra": 1})

    def test_io_schema_is_carried_through(self):
        candidate = discover_openapi(_SPEC)[1]      # /users get, carries parameters
        self.assertIsNotNone(candidate.io_schema)
        self.assertEqual(bind_candidate(candidate, _target()).io_schema,
                         candidate.io_schema)

    def test_surface_id_override_is_honoured(self):
        candidate = _candidate()
        self.assertEqual(bind_candidate(candidate, _target(), "custom").id, "custom")

    def test_driver_is_a_rest_driver_over_the_supplied_target(self):
        target = _target()
        surface = bind_candidate(_candidate(), target)
        self.assertIsInstance(surface.driver, RestDriver)
        self.assertIs(surface.driver.target, target)


# ---------------- drivability ----------------
class TestDrivability(unittest.TestCase):
    def test_bound_surface_resolves_as_drivable(self):
        surface = bind_candidate(_candidate(), _target())
        self.assertEqual(drivable_surfaces_of(surface), [surface])

    def test_bound_surface_drives_the_declared_operation(self):
        target = _target()
        surface = bind_candidate(_candidate(), target)
        st = SurfaceTarget(surface, origin=target)
        with _patched():
            obs = st.drive(HttpAction(method="GET", path="/users"))
        self.assertTrue(obs.ok)
        self.assertEqual(target.exchanges[-1]["url"], f"{_BASE}/users")

    def test_bound_surfaces_register_on_an_application(self):
        """The documented idiom: a free function builds the Surface, `add_surface`
        registers it. Binding introduces no new shape."""
        app = ApplicationTarget(base_url=_BASE)
        target = _target()
        for candidate in discover_openapi(_SPEC):
            app.add_candidate(candidate)
        bound = [app.add_surface(bind_candidate(c, target))
                 for c in app.candidates_of(SurfaceKind.REST)]
        self.assertEqual(drivable_surfaces_of(app), bound)


# ---------------- purity ----------------
class TestBindingIsPure(unittest.TestCase):
    def test_binding_issues_no_request(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("no request may be issued")):
            bind_candidate(_candidate(), _target())

    def test_binding_constructs_no_target(self):
        target = _target()
        self.assertIs(bind_candidate(_candidate(), target).driver.target, target)

    def test_binding_does_not_mutate_the_candidate(self):
        candidate = _candidate(io_schema={"parameters": []})
        before = (candidate.id, candidate.kind, dict(candidate.locator),
                  dict(candidate.io_schema), candidate.source)
        bind_candidate(candidate, _target())
        self.assertEqual(
            (candidate.id, candidate.kind, dict(candidate.locator),
             dict(candidate.io_schema), candidate.source), before)

    def test_binding_does_not_mutate_the_target(self):
        target = _target()
        before = (target.url, dict(target.headers), target.scope, target.auth,
                  list(target.exchanges))
        bind_candidate(_candidate(), target)
        self.assertEqual((target.url, dict(target.headers), target.scope, target.auth,
                          list(target.exchanges)), before)


# ---------------- refusal ----------------
class TestRefusal(unittest.TestCase):
    def test_mcp_tool_candidate_is_refused(self):
        candidate = _candidate(kind=SurfaceKind.MCP_TOOL, cid="mcp_tool:run_sql",
                               locator="run_sql")
        with self.assertRaises(ConfigError) as ctx:
            bind_candidate(candidate, _target())
        self.assertIn("no driver", str(ctx.exception))
        self.assertIn("mcp_tool", str(ctx.exception).lower())

    def test_every_driverless_kind_is_refused_by_name(self):
        """The locator is deliberately REST-shaped and valid, so the kind gate is the only
        thing that can refuse these. With a malformed locator the locator check would
        refuse them instead and this would pass against a binder that accepts every
        kind."""
        for kind in (SurfaceKind.GRAPHQL, SurfaceKind.FUNCTION, SurfaceKind.MCP_TOOL,
                     SurfaceKind.RAG, SurfaceKind.VECTOR_DB, SurfaceKind.CHAT):
            with self.subTest(kind=kind):
                candidate = SurfaceCandidate(
                    id=f"{kind.value}:x", kind=kind,
                    locator={"method": "GET", "path": "/x"}, source="test")
                with self.assertRaises(ConfigError) as ctx:
                    bind_candidate(candidate, _target())
                self.assertIn("no driver", str(ctx.exception))

    def test_a_non_candidate_is_refused(self):
        with self.assertRaises(ConfigError):
            bind_candidate(object(), _target())

    def test_a_rest_candidate_without_a_usable_locator_is_refused(self):
        # Built directly rather than via `_candidate`, whose default would substitute a
        # usable locator for None and make the first case vacuous.
        for locator in (None, "just-a-string", {}, {"method": "GET"}):
            with self.subTest(locator=locator):
                candidate = SurfaceCandidate(id="rest:get:/x", kind=SurfaceKind.REST,
                                             locator=locator, source="test")
                with self.assertRaises(ConfigError):
                    bind_candidate(candidate, _target())

    def test_binding_never_raises_target_error(self):
        """Ownership and scope refusals belong to `SurfaceTarget` (ADR 0005/0012), not
        here. A scopeless target must bind and be refused later."""
        surface = bind_candidate(_candidate(), _target(scope_hosts=None))
        self.assertIsInstance(surface, Surface)
        with self.assertRaises(TargetError):
            SurfaceTarget(surface, origin=surface.driver.target)


# ---------------- validation stays downstream ----------------
class TestValidationStaysDownstream(unittest.TestCase):
    def test_empty_scope_binds_then_is_refused(self):
        surface = bind_candidate(_candidate(), _target(scope_hosts=[]))
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(surface, origin=surface.driver.target)
        self.assertIn("empty scope", str(ctx.exception))

    def test_governance_mismatch_is_still_caught_downstream(self):
        supplied, driven = _target(), _target()
        supplied.rate = object()
        surface = bind_candidate(_candidate(), driven)
        with self.assertRaises(TargetError):
            SurfaceTarget(surface, origin=supplied)

    def test_a_bound_surface_is_governed_like_a_hand_built_one(self):
        from glasscage.targets import rest_surface_from_target
        target = _target()
        bound = bind_candidate(_candidate(), target)
        hand = rest_surface_from_target(target, "GET", "/users")
        self.assertEqual(bound.locator, hand.locator)
        self.assertEqual(bound.id, hand.id)
        self.assertIs(type(bound.driver), type(hand.driver))


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_binding_the_same_candidates_twice_is_equal(self):
        target = _target()
        a = [bind_candidate(c, target).id for c in discover_openapi(_SPEC)]
        b = [bind_candidate(c, target).id for c in discover_openapi(_SPEC)]
        self.assertEqual(a, b)

    def test_bound_ids_follow_discovery_order(self):
        target = _target()
        candidates = discover_openapi(_SPEC)
        self.assertEqual([bind_candidate(c, target).id for c in candidates],
                         [c.id for c in candidates])


# ---------------- producer freeze ----------------
class TestDiscoveryUnchanged(unittest.TestCase):
    def test_discovery_json_is_unperturbed_by_binding(self):
        candidates = discover_openapi(_SPEC)
        before = discovery_mod.to_json(candidates)
        for c in candidates:
            bind_candidate(c, _target())
        self.assertEqual(discovery_mod.to_json(candidates), before)

    def test_discovery_markdown_is_unperturbed_by_binding(self):
        candidates = discover_openapi(_SPEC)
        before = discovery_mod.to_markdown(candidates)
        for c in candidates:
            bind_candidate(c, _target())
        self.assertEqual(discovery_mod.to_markdown(candidates), before)

    def test_discovery_still_emits_only_rest_and_mcp_tool(self):
        """Binding is REST-only because discovery emits no CHAT candidate. If that ever
        changes, this fails and the binder registry must be revisited."""
        kinds = {c.kind for c in discover_openapi(_SPEC)}
        self.assertEqual(kinds, {SurfaceKind.REST})


if __name__ == "__main__":
    unittest.main()
