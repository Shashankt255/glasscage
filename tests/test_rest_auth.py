# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""REST transport-boundary authentication tests (ADR 0013, PR #13).

`ApplicationTarget.auth` was declared by ADR 0001 and had no production reader. It is
now consumed at the REST transport boundary and nowhere else.

The load-bearing assertions here are negative: a credential must reach the outbound
request headers and none of the twelve sinks the decision prohibits. That matters more
than usual because `redaction` matches `SECRET_PATTERNS` - API-key and password shapes -
which a bearer token does not match, so a leak into evidence would be unrecoverable.

No network: urllib.request.urlopen is patched throughout.
Run: python -m unittest tests.test_rest_auth -v
"""

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import audit as audit_mod
from glasscage import repro, sarif
from glasscage.audit import AuditLog, Scope
from glasscage.errors import TargetError
from glasscage.models import ReconResult
from glasscage.probes import all_probes
from glasscage.recon import run_recon
from glasscage.refagent import ReferenceAgent
from glasscage.target import HTTPChatTarget
from glasscage.targets import (
    ApplicationTarget,
    AuthContext,
    ChatSurface,
    HttpAction,
    RestTarget,
    SurfaceTarget,
    rest_surface_from_target,
)

_HOST = "api.example"
_BASE = f"https://{_HOST}/v1"

# Deliberately shaped so SECRET_PATTERNS does NOT match it: the point of the negative
# assertions is that redaction could not save us if the credential escaped.
_TOKEN = "GLSSCG-AUTH-CANARY-9f2c"
_COOKIE = "GLSSCG-COOKIE-CANARY-4a71"
_CLEAN = '{"users":[{"id":1}]}'
# `to_sarif` and `to_replay` both skip findings that are not vulnerable/inconclusive, so
# a clean response would leave those exporters empty and the sink assertions vacuous.
# This body makes the probe return VULNERABLE, which is what puts a finding into them.
_SECRET_BODY = '{"leaked":"sk-ABCDEFGHIJKLMNOP0123"}'


class _Resp:
    def __init__(self, body=_CLEAN, status=200):
        self._b, self.status = body.encode("utf-8"), status

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Capture:
    """Records the urllib Request objects actually issued."""

    def __init__(self, body=_CLEAN):
        self.requests, self.body = [], body

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        return _Resp(self.body)

    @property
    def headers(self):
        return self.requests[-1].headers


def _auth():
    return AuthContext(scheme="bearer",
                       headers={"Authorization": f"Bearer {_TOKEN}"},
                       cookies={"sid": _COOKIE})


def _rest_target(auth=None, headers=None, method="GET", path="/users"):
    t = RestTarget(_BASE, headers=headers or {})
    t.scope = Scope([_HOST])
    t.auth = auth
    return t, rest_surface_from_target(t, method, path)


def _driven(auth=None, headers=None, method="GET", path="/users"):
    t, s = _rest_target(auth, headers, method, path)
    return t, SurfaceTarget(s, origin=t)


def _probe():
    return next(p for p in all_probes() if p.name == "rest-response-disclosure")


# ---------------- INV-1: default is inert ----------------
class TestInertDefault(unittest.TestCase):
    def test_absent_auth_sends_no_extra_headers(self):
        _, st = _driven(auth=None)
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertNotIn("Authorization", cap.headers)

    def test_default_auth_context_contributes_nothing(self):
        _, st = _driven(auth=AuthContext())
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertNotIn("Authorization", cap.headers)

    def test_canonical_request_is_unchanged_by_auth(self):
        """The canonical form must be identical with and without credentials, or custody
        and Finding identity would depend on who was authenticated."""
        seen = []
        for auth in (None, _auth()):
            _, st = _driven(auth=auth)
            with mock.patch("urllib.request.urlopen", _Capture()):
                seen.append(st.drive(HttpAction(method="GET", path="/users")).request)
        self.assertEqual(seen[0], seen[1])


# ---------------- INV-2: reaches the wire and nothing else ----------------
class TestCredentialReachesTheWire(unittest.TestCase):
    def test_auth_header_is_sent(self):
        _, st = _driven(auth=_auth())
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertEqual(cap.headers.get("Authorization"), f"Bearer {_TOKEN}")


class TestCredentialReachesNothingElse(unittest.TestCase):
    """One test per prohibited sink. No sink is verified by inference from another."""

    def setUp(self):
        self.target, self.st = _driven(auth=_auth())
        self.target.audit = AuditLog(None)
        self.cap = _Capture(_SECRET_BODY)
        with mock.patch("urllib.request.urlopen", self.cap):
            self.obs = self.st.drive(HttpAction(method="GET", path="/users"))
            self.findings = _probe().run(self.st, ReconResult())
        # Guard the guards: a PASSED finding is dropped by both exporters below, which
        # would make their assertions pass without inspecting anything.
        self.assertEqual(self.findings[0].status.value, "vulnerable")

    def _assert_clean(self, blob, label):
        self.assertNotIn(_TOKEN, blob, label)
        self.assertNotIn(_COOKIE, blob, label)

    def test_not_in_http_action(self):
        action = HttpAction(method="GET", path="/users")
        self._assert_clean(json.dumps(action.headers), "HttpAction.headers")

    def test_not_in_canonical_request(self):
        self._assert_clean(self.obs.request, "canonical_request")

    def test_not_in_observation_request(self):
        self._assert_clean(str(self.obs.request), "Observation.request")

    def test_not_in_custody(self):
        self._assert_clean(self.obs.custody_hash or "", "custody_hash")
        self._assert_clean(str(self.obs.response), "Observation.response")

    def test_not_in_finding_identity(self):
        f = self.findings[0]
        self._assert_clean(f.prompt, "Finding.prompt")
        self._assert_clean(f.raw_request, "Finding.raw_request")
        self._assert_clean(f.evidence_hash, "Finding.evidence_hash")

    def test_not_in_reports(self):
        self._assert_clean(json.dumps([f.__dict__ for f in self.findings], default=str),
                           "serialized findings")

    def test_not_in_sarif(self):
        doc = sarif.to_sarif("demo", self.findings, {})
        self.assertTrue(doc["runs"][0]["results"], "SARIF carried no result to inspect")
        self._assert_clean(json.dumps(doc, default=str), "SARIF")

    def test_not_in_replay(self):
        rp = sarif.to_replay("demo", {"url": _BASE, "headers": {}}, self.findings)
        self.assertTrue(rp["steps"], "replay bundle carried no step to inspect")
        self._assert_clean(json.dumps(rp, default=str), "replay bundle")

    def test_not_in_har(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.har")
            audit_mod.har_export(self.target.exchanges, path)
            with open(path, encoding="utf-8") as fh:
                self._assert_clean(fh.read(), "HAR export")

    def test_not_in_evidence_or_exchanges(self):
        self._assert_clean(json.dumps(self.target.exchanges, default=str), "exchanges")

    def test_not_in_audit_log(self):
        self.assertTrue(self.target.audit.entries)
        self._assert_clean(json.dumps(self.target.audit.entries, default=str),
                           "audit entries")

    def test_not_in_reproduction_steps(self):
        steps = repro.build(self.findings[0], target=self.st)
        self._assert_clean("\n".join(steps), "reproduction steps")


class TestNotInExceptionMessages(unittest.TestCase):
    def test_transport_error_message_carries_no_credential(self):
        _, st = _driven(auth=_auth())
        with mock.patch("urllib.request.urlopen", side_effect=OSError("boom")):
            obs = st.drive(HttpAction(method="GET", path="/users"))
        self.assertFalse(obs.ok)
        self.assertNotIn(_TOKEN, obs.error or "")

    def test_http_error_message_carries_no_credential(self):
        _, st = _driven(auth=_auth())
        err = urllib.error.HTTPError(f"{_BASE}/users", 401, "Unauthorized", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            obs = st.drive(HttpAction(method="GET", path="/users"))
        self.assertNotIn(_TOKEN, obs.error or "")

    def test_parity_refusal_message_carries_no_credential(self):
        supplied, _ = _rest_target(auth=_auth())
        driven, surface = _rest_target(auth=None)
        driven.scope = supplied.scope
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(surface, origin=supplied)
        self.assertNotIn(_TOKEN, str(ctx.exception))
        self.assertNotIn(_COOKIE, str(ctx.exception))


# ---------------- INV-3: precedence ----------------
class TestPrecedence(unittest.TestCase):
    def test_target_header_overrides_auth(self):
        _, st = _driven(auth=_auth(), headers={"Authorization": "Bearer FROM-TARGET"})
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertEqual(cap.headers.get("Authorization"), "Bearer FROM-TARGET")

    def test_action_header_overrides_everything(self):
        _, st = _driven(auth=_auth(), headers={"Authorization": "Bearer FROM-TARGET"})
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users",
                                headers={"Authorization": "Bearer FROM-ACTION"}))
        self.assertEqual(cap.headers.get("Authorization"), "Bearer FROM-ACTION")

    def test_auth_supplies_headers_it_alone_declares(self):
        auth = AuthContext(scheme="api_key", headers={"X-Api-Key": _TOKEN})
        _, st = _driven(auth=auth, headers={"X-Trace": "1"})
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertEqual(cap.headers.get("X-api-key"), _TOKEN)
        self.assertEqual(cap.headers.get("X-trace"), "1")


# ---------------- INV-4/5: controls and CHAT untouched ----------------
class TestBoundariesUntouched(unittest.TestCase):
    def test_auth_is_not_an_operational_control(self):
        from glasscage.targets.compat import _CONTROLS
        self.assertEqual(_CONTROLS, ("scope", "rate", "audit"))

    def test_chat_target_does_not_consume_auth(self):
        """ADR 0013 confines consumption to REST; CHAT keeps `config['headers']`."""
        t = HTTPChatTarget({"url": "https://x.example", "headers": {}})
        self.assertFalse(hasattr(t, "auth"))

    def test_chat_surface_still_drives(self):
        agent = ReferenceAgent()
        self.assertTrue(SurfaceTarget(ChatSurface(agent), origin=agent).send("hi").ok)


# ---------------- INV-6: determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_identical_authenticated_requests_hash_identically(self):
        hashes = []
        for _ in range(2):
            _, st = _driven(auth=_auth())
            with mock.patch("urllib.request.urlopen", _Capture()):
                hashes.append(st.drive(HttpAction(method="GET", path="/u")).custody_hash)
        self.assertEqual(hashes[0], hashes[1])

    def test_custody_hash_is_independent_of_credentials(self):
        out = []
        for auth in (None, _auth()):
            _, st = _driven(auth=auth)
            with mock.patch("urllib.request.urlopen", _Capture()):
                out.append(st.drive(HttpAction(method="GET", path="/u")).custody_hash)
        self.assertEqual(out[0], out[1])


# ---------------- INV-7: representation ----------------
class TestRepresentationIsSafe(unittest.TestCase):
    def test_auth_context_repr_hides_material(self):
        r = repr(_auth())
        self.assertNotIn(_TOKEN, r)
        self.assertNotIn(_COOKIE, r)
        self.assertIn("bearer", r)          # scheme still names the mechanism

    def test_application_target_repr_hides_material(self):
        app = ApplicationTarget(base_url="https://x.example", auth=_auth())
        for rendered in (repr(app), str(app), f"{app}"):
            self.assertNotIn(_TOKEN, rendered)
            self.assertNotIn(_COOKIE, rendered)

    def test_str_of_auth_context_hides_material(self):
        self.assertNotIn(_TOKEN, str(_auth()))


# ---------------- INV-8: never in the URL ----------------
class TestNeverInUrl(unittest.TestCase):
    def test_credential_absent_from_issued_url(self):
        target, st = _driven(auth=_auth())
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertNotIn(_TOKEN, cap.requests[-1].full_url)
        self.assertNotIn(_TOKEN, target.exchanges[-1]["url"])

    def test_credential_absent_from_audited_url(self):
        target, st = _driven(auth=_auth())
        target.audit = AuditLog(None)
        with mock.patch("urllib.request.urlopen", _Capture()):
            st.drive(HttpAction(method="GET", path="/users"))
        self.assertNotIn(_TOKEN, json.dumps(target.audit.entries))


# ---------------- parity verification ----------------
class TestAuthParity(unittest.TestCase):
    def test_driven_target_without_the_auth_is_refused(self):
        supplied, _ = _rest_target(auth=_auth())
        driven, surface = _rest_target(auth=None)
        driven.scope = supplied.scope
        with self.assertRaises(TargetError) as ctx:
            SurfaceTarget(surface, origin=supplied)
        self.assertIn("unauthenticated", str(ctx.exception))

    def test_refusal_precedes_any_request(self):
        supplied, _ = _rest_target(auth=_auth())
        driven, surface = _rest_target(auth=None)
        driven.scope = supplied.scope
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("no request may be issued")), \
             self.assertRaises(TargetError):
            SurfaceTarget(surface, origin=supplied)

    def test_matching_auth_is_accepted(self):
        auth = _auth()
        t, surface = _rest_target(auth=auth)
        self.assertIsNotNone(SurfaceTarget(surface, origin=t))

    def test_empty_auth_imposes_no_requirement(self):
        supplied, _ = _rest_target(auth=AuthContext())
        driven, surface = _rest_target(auth=None)
        driven.scope = supplied.scope
        self.assertIsNotNone(SurfaceTarget(surface, origin=supplied))


# ---------------- recon parity ----------------
class TestReconIsAuthenticated(unittest.TestCase):
    def test_rest_recon_sends_the_auth_header(self):
        """Recon drives the surface too; unauthenticated recon would report a reachable
        surface as unreachable."""
        _, st = _driven(auth=_auth())
        cap = _Capture()
        with mock.patch("urllib.request.urlopen", cap):
            result = run_recon(st)
        self.assertTrue(result.reachable)
        self.assertEqual(cap.headers.get("Authorization"), f"Bearer {_TOKEN}")


if __name__ == "__main__":
    unittest.main()
