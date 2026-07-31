# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""REST driver and contract tests (ADR 0012, PR #12 Commit 1).

Covers: HttpAction consumption, fail-closed scope (R1), canonical request serialization
and custody determinism (R2), the SurfaceTarget.drive contract (R4), declared ownership
and governance, widened resolution with INV-1 ordering preserved, and the alias contract.

No network: urllib.request.urlopen is patched throughout.
Run: python -m unittest tests.test_rest_driver -v
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import AuditLog, RateLimiter, Scope
from glasscage.errors import ConfigError, TargetError
from glasscage.refagent import ReferenceAgent
from glasscage.targets import (
    ApplicationTarget, ChatSurface, HttpAction, Observation, PromptAction, RestDriver,
    RestTarget, Surface, SurfaceKind, SurfaceTarget, ToolCallAction, canonical_request,
    chat_surface_of, chat_surfaces_of, drivable_surfaces_of, rest_surface_from_target,
)

_HOST = "api.example"
_BASE = f"https://{_HOST}/v1"


def _target(scope_hosts=(_HOST,), **kw):
    t = RestTarget(_BASE, **kw)
    if scope_hosts is not None:
        t.scope = Scope(list(scope_hosts))
    return t


class _Resp:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, body='{"ok":1}', status=200):
        self._b, self.status = body.encode("utf-8"), status

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patched(body='{"ok":1}', status=200):
    return mock.patch("urllib.request.urlopen", return_value=_Resp(body, status))


# ---------------- action consumption ----------------
class TestActionConsumption(unittest.TestCase):
    def test_http_action_is_driven(self):
        s = rest_surface_from_target(_target(), "GET", "/users")
        with _patched():
            obs = s.drive(HttpAction(method="GET", path="/users"))
        self.assertTrue(obs.ok)
        self.assertEqual(obs.status, 200)
        self.assertEqual(obs.text, '{"ok":1}')

    def test_prompt_action_is_refused_by_name(self):
        s = rest_surface_from_target(_target(), "GET", "/users")
        obs = s.drive(PromptAction(prompt="hello"))
        self.assertFalse(obs.ok)
        self.assertIn("PromptAction", obs.error)
        self.assertIsNone(obs.custody_hash)

    def test_tool_call_action_is_refused(self):
        s = rest_surface_from_target(_target(), "GET", "/users")
        obs = s.drive(ToolCallAction(name="t"))
        self.assertFalse(obs.ok)
        self.assertIn("ToolCallAction", obs.error)


# ---------------- R1: fail-closed scope ----------------
class TestFailClosedScope(unittest.TestCase):
    def test_absent_scope_is_refused(self):
        s = rest_surface_from_target(_target(scope_hosts=None), "GET", "/u")
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(s, origin=s.driver.target)
        self.assertIn("no scope", str(ctx.exception))

    def test_empty_scope_is_refused(self):
        s = rest_surface_from_target(_target(scope_hosts=[]), "GET", "/u")
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(s, origin=s.driver.target)
        self.assertIn("empty scope", str(ctx.exception))

    def test_non_empty_scope_is_accepted(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        self.assertIsNotNone(SurfaceTarget(s, origin=s.driver.target))

    def test_refusal_precedes_any_request(self):
        s = rest_surface_from_target(_target(scope_hosts=None), "GET", "/u")
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("no request may be issued")):
            with self.assertRaises(TargetError):
                SurfaceTarget(s, origin=s.driver.target)

    def test_out_of_scope_host_is_refused_before_the_socket(self):
        t = _target(scope_hosts=["allowed.example"])
        s = rest_surface_from_target(t, "GET", "/u")
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("socket must not open")):
            with self.assertRaises(PermissionError):
                s.drive(HttpAction(method="GET", path="/u"))

    def test_scope_receives_the_full_absolute_url(self):
        t = _target()
        seen = []
        t.scope = mock.Mock(allowed={_HOST}, check=lambda u: seen.append(u))
        s = rest_surface_from_target(t, "GET", "/users")
        with _patched():
            s.drive(HttpAction(method="GET", path="/users"))
        self.assertEqual(seen, [f"{_BASE}/users"])

    def test_rate_limiter_is_called_per_request(self):
        t = _target()
        t.rate = mock.Mock(spec=RateLimiter)
        s = rest_surface_from_target(t, "GET", "/u")
        with _patched():
            s.drive(HttpAction(method="GET", path="/u"))
            s.drive(HttpAction(method="GET", path="/u"))
        self.assertEqual(t.rate.wait.call_count, 2)

    def test_audit_records_each_request(self):
        t = _target()
        t.audit = AuditLog(None)
        s = rest_surface_from_target(t, "GET", "/u")
        with _patched():
            s.drive(HttpAction(method="GET", path="/u"))
        self.assertEqual(len(t.audit.entries), 1)
        self.assertTrue(t.audit.verify())


# ---------------- R2: canonical serialization and custody ----------------
class TestCanonicalAndCustody(unittest.TestCase):
    def test_custody_hash_is_sha256_of_canonical_and_response(self):
        from glasscage.audit import sha256
        t = _target()
        s = rest_surface_from_target(t, "GET", "/u")
        a = HttpAction(method="GET", path="/u")
        with _patched(body="RESP"):
            obs = s.drive(a)
        self.assertEqual(obs.custody_hash,
                         sha256(canonical_request(a, f"{_BASE}/u"), "RESP"))

    def test_identical_requests_hash_identically(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        a = HttpAction(method="GET", path="/u", query={"b": "2", "a": "1"})
        with _patched():
            first = s.drive(a).custody_hash
        with _patched():
            second = s.drive(a).custody_hash
        self.assertEqual(first, second)

    def test_query_and_header_ordering_do_not_change_the_hash(self):
        url = f"{_BASE}/u"
        a = HttpAction(method="GET", path="/u", query={"a": "1", "b": "2"},
                       headers={"X-B": "2", "X-A": "1"})
        b = HttpAction(method="GET", path="/u", query={"b": "2", "a": "1"},
                       headers={"X-A": "1", "X-B": "2"})
        self.assertEqual(canonical_request(a, url), canonical_request(b, url))

    def test_body_serialization_is_key_sorted(self):
        url = f"{_BASE}/u"
        a = HttpAction(method="POST", path="/u", body={"z": 1, "a": 2})
        b = HttpAction(method="POST", path="/u", body={"a": 2, "z": 1})
        self.assertEqual(canonical_request(a, url), canonical_request(b, url))
        self.assertIn('{"a":2,"z":1}', canonical_request(a, url))

    def test_method_is_uppercased_and_url_is_absolute(self):
        c = canonical_request(HttpAction(method="post", path="/u"), f"{_BASE}/u")
        self.assertTrue(c.startswith(f"POST {_BASE}/u"))

    def test_distinct_endpoints_produce_distinct_canonical_forms(self):
        one = canonical_request(HttpAction(method="GET", path="/a"), f"{_BASE}/a")
        two = canonical_request(HttpAction(method="GET", path="/b"), f"{_BASE}/b")
        self.assertNotEqual(one, two)

    def test_transport_failure_still_carries_custody(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        with mock.patch("urllib.request.urlopen", side_effect=OSError("boom")):
            obs = s.drive(HttpAction(method="GET", path="/u"))
        self.assertFalse(obs.ok)
        self.assertEqual(len(obs.custody_hash), 64)


# ---------------- R4: the probe contract ----------------
class TestProbeContract(unittest.TestCase):
    def test_surface_target_drive_returns_an_observation(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        st = SurfaceTarget(s, origin=s.driver.target)
        with _patched():
            obs = st.drive(HttpAction(method="GET", path="/u"))
        self.assertIsInstance(obs, Observation)
        self.assertTrue(obs.ok)

    def test_drive_is_available_on_a_chat_surface_too(self):
        agent = ReferenceAgent()
        st = SurfaceTarget(ChatSurface(agent), origin=agent)
        obs = st.drive(PromptAction(prompt="hello"))
        self.assertTrue(obs.ok)

    def test_send_remains_the_chat_contract(self):
        agent = ReferenceAgent()
        st = SurfaceTarget(ChatSurface(agent), origin=agent)
        self.assertTrue(st.send("hello").ok)


# ---------------- ownership ----------------
class TestOwnership(unittest.TestCase):
    def test_driver_declares_its_target(self):
        t = _target()
        self.assertIs(RestDriver(t).target, t)

    def test_governance_parity_is_enforced(self):
        supplied, driven = _target(), _target()
        supplied.rate = RateLimiter(100.0)
        s = rest_surface_from_target(driven, "GET", "/u")
        with self.assertRaises(TargetError):
            SurfaceTarget(s, origin=supplied)


# ---------------- widened resolution ----------------
class TestWidenedResolution(unittest.TestCase):
    def test_rest_surface_resolves(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        self.assertEqual(drivable_surfaces_of(s), [s])

    def test_registration_order_is_preserved_across_kinds(self):
        agent = ReferenceAgent()
        app = ApplicationTarget(base_url="https://x.example")
        r = app.add_surface(rest_surface_from_target(_target(), "GET", "/u", "r"))
        c = app.add_surface(ChatSurface(agent, surface_id="c"))
        self.assertEqual(drivable_surfaces_of(app), [r, c])

    def test_kinds_without_a_driver_are_still_refused(self):
        for kind in (SurfaceKind.GRAPHQL, SurfaceKind.FUNCTION, SurfaceKind.MCP_TOOL,
                     SurfaceKind.RAG, SurfaceKind.VECTOR_DB):
            s = Surface(id="x", kind=kind, locator=None,
                        driver=RestDriver(_target()))
            with self.assertRaises(ConfigError):
                drivable_surfaces_of(s)

    def test_alias_delegates_and_keeps_its_signature(self):
        s = rest_surface_from_target(_target(), "GET", "/u")
        self.assertEqual(chat_surfaces_of(s), drivable_surfaces_of(s))
        self.assertIs(chat_surface_of(s), drivable_surfaces_of(s)[0])

    def test_alias_error_types_unchanged(self):
        with self.assertRaises(ConfigError):
            chat_surfaces_of(object())


if __name__ == "__main__":
    unittest.main()
