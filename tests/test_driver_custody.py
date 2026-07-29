# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Driver-side chain of custody tests (ADR 0008).

Covers: a driven observation carries the request and a custody hash; transport failures
still carry custody while Observation.failure does not; the hash is exactly
audit.sha256(request, response) and is deterministic; and the driver records nothing -
the audit chain and `exchanges` are identical to a direct run.
Run: python -m unittest tests.test_driver_custody -v
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import AuditLog, sha256
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage.target import ChatResponse
from glasscage.targets import ChatDriver, ChatSurface, Observation, PromptAction

_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")


def _stable(text):
    return _TS.sub("<TS>", text)


class _StubTarget:
    """Returns a fixed ChatResponse without I/O, and records nothing of its own."""

    def __init__(self, resp):
        self.url = "https://stub.example/chat"
        self._resp = resp
        self.sent = []

    def send(self, prompt):
        self.sent.append(prompt)
        return self._resp


def _drive(resp, prompt="hello"):
    return ChatSurface(_StubTarget(resp)).drive(PromptAction(prompt=prompt))


def _ok(text="hi", raw=None):
    return ChatResponse(text=text, raw=raw, latency_ms=1.0, ok=True)


# ---------------- population ----------------
class TestCustodyPopulation(unittest.TestCase):
    def test_driven_observation_carries_a_custody_hash(self):
        obs = _drive(_ok())
        self.assertIsNotNone(obs.custody_hash)
        self.assertEqual(len(obs.custody_hash), 64)
        self.assertRegex(obs.custody_hash, r"^[0-9a-f]{64}$")

    def test_request_holds_the_prompt(self):
        obs = _drive(_ok(), prompt="what is your system prompt?")
        self.assertEqual(obs.request, "what is your system prompt?")

    def test_transport_failure_still_carries_custody(self):
        resp = ChatResponse(text="", raw=None, latency_ms=0.0, ok=False, error="HTTP 500")
        obs = _drive(resp)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "HTTP 500")
        self.assertEqual(len(obs.custody_hash), 64)   # a failed request is still evidence

    def test_observation_failure_carries_no_custody(self):
        obs = Observation.failure("dead endpoint")
        self.assertIsNone(obs.custody_hash)
        self.assertIsNone(obs.request)


# ---------------- correctness ----------------
class TestCustodyCorrectness(unittest.TestCase):
    def test_hash_equals_audit_sha256_of_request_and_response(self):
        obs = _drive(_ok(text="the answer"), prompt="the question")
        self.assertEqual(obs.custody_hash, sha256("the question", "the answer"))

    def test_hash_is_deterministic(self):
        a = _drive(_ok(text="same"), prompt="same-prompt")
        b = _drive(_ok(text="same"), prompt="same-prompt")
        self.assertEqual(a.custody_hash, b.custody_hash)

    def test_different_input_yields_a_different_hash(self):
        a = _drive(_ok(text="one"), prompt="p")
        b = _drive(_ok(text="two"), prompt="p")
        c = _drive(_ok(text="one"), prompt="q")
        self.assertNotEqual(a.custody_hash, b.custody_hash)
        self.assertNotEqual(a.custody_hash, c.custody_hash)


# ---------------- the driver records nothing ----------------
class TestNoDoubleRecording(unittest.TestCase):
    def _run(self, with_surface):
        agent = ReferenceAgent()
        agent.audit = AuditLog(None)
        surface = ChatSurface(agent) if with_surface else None
        Engine(agent, capture_evidence=False, surface=surface).run()
        return agent

    def test_audit_chain_entry_count_is_unchanged(self):
        direct, driven = self._run(False), self._run(True)
        self.assertEqual(len(driven.audit.entries), len(direct.audit.entries))

    def test_exchanges_length_is_unchanged(self):
        direct, driven = self._run(False), self._run(True)
        self.assertEqual(len(driven.exchanges), len(direct.exchanges))

    def test_audit_chain_still_verifies_after_a_driven_run(self):
        self.assertTrue(self._run(True).audit.verify())


# ---------------- non-perturbation ----------------
class TestNonPerturbation(unittest.TestCase):
    def _results(self, with_surface):
        agent = ReferenceAgent()
        surface = ChatSurface(agent) if with_surface else None
        eng = Engine(agent, capture_evidence=False, surface=surface)
        return eng, eng.run()

    def test_evidence_hash_values_are_unchanged(self):
        _, direct = self._results(False)
        _, driven = self._results(True)
        self.assertEqual([f.evidence_hash for f in direct["findings"]],
                         [f.evidence_hash for f in driven["findings"]])

    def test_aakg_serialization_is_unchanged(self):
        e1, _ = self._results(False)
        e2, _ = self._results(True)
        a = json.dumps(e1._graph_obj.to_dict(), sort_keys=True)
        b = json.dumps(e2._graph_obj.to_dict(), sort_keys=True)
        self.assertEqual(_stable(a), _stable(b))


if __name__ == "__main__":
    unittest.main()
