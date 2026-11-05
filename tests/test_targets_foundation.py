# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Unit tests for the Phase 1 targets foundation (PR #1).

Covers: enum shape, ApplicationTarget registry, Surface->Driver delegation, the
ChatResponse->Observation round-trip fidelity, a no-network guarantee, and a
dependency-direction guard (targets must not import engine/probes/aakg).
"""

import unittest

from glasscage.target import ChatResponse
from glasscage.targets import (
    Action,
    ApplicationTarget,
    AuthContext,
    ChatDriver,
    ChatSurface,
    Driver,
    Observation,
    PromptAction,
    Surface,
    SurfaceCandidate,
    SurfaceKind,
)


class _StubTarget:
    """Stand-in for HTTPChatTarget that returns a fixed ChatResponse without I/O."""

    def __init__(self, resp):
        self.url = "https://stub.example/api/chat"
        self._resp = resp
        self.sent = []

    def send(self, prompt):
        self.sent.append(prompt)
        return self._resp


class TestSurfaceKind(unittest.TestCase):
    def test_exactly_seven_kinds(self):
        self.assertEqual(
            {k.value for k in SurfaceKind},
            {"chat", "rest", "graphql", "function", "mcp_tool", "rag", "vector_db"},
        )


class TestApplicationTarget(unittest.TestCase):
    def _surface(self, sid, kind):
        return Surface(id=sid, kind=kind, locator=None, driver=ChatDriver(_StubTarget(None)))

    def test_add_and_filter(self):
        app = ApplicationTarget(base_url="https://x.example")
        s1 = app.add_surface(self._surface("a", SurfaceKind.CHAT))
        app.add_surface(self._surface("b", SurfaceKind.REST))
        self.assertEqual(len(app.surfaces), 2)
        self.assertEqual(app.surfaces_of(SurfaceKind.CHAT), [s1])

    def test_add_is_idempotent_by_id(self):
        app = ApplicationTarget()
        app.add_surface(self._surface("dup", SurfaceKind.CHAT))
        app.add_surface(self._surface("dup", SurfaceKind.CHAT))
        self.assertEqual(len(app.surfaces), 1)

    def test_auth_context_defaults(self):
        app = ApplicationTarget()
        self.assertIsInstance(app.auth, AuthContext)
        self.assertEqual(app.auth.scheme, "none")


class TestSurfaceDelegation(unittest.TestCase):
    def test_drive_delegates_to_driver(self):
        resp = ChatResponse(text="hi", raw={"x": 1}, latency_ms=12.5, ok=True)
        surface = ChatSurface(_StubTarget(resp), surface_id="chat-1")
        obs = surface.drive(PromptAction(prompt="hello"))
        self.assertIsInstance(obs, Observation)
        self.assertTrue(obs.ok)

    def test_chatdriver_conforms_to_driver_protocol(self):
        self.assertIsInstance(ChatDriver(_StubTarget(None)), Driver)


class TestChatResponseRoundTrip(unittest.TestCase):
    def test_fields_map_losslessly(self):
        resp = ChatResponse(
            text="secret leaked", raw={"body": "..."}, latency_ms=42.0,
            ok=True, error=None, trace={"tool_calls": ["t1"]},
        )
        stub = _StubTarget(resp)
        obs = ChatSurface(stub).drive(PromptAction(prompt="p"))
        self.assertEqual(obs.text, resp.text)
        self.assertEqual(obs.ok, resp.ok)
        self.assertEqual(obs.latency_ms, resp.latency_ms)
        self.assertEqual(obs.error, resp.error)
        self.assertEqual(obs.trace, resp.trace)
        self.assertEqual(obs.response, resp.raw)
        self.assertEqual(stub.sent, ["p"])  # prompt actually forwarded

    def test_error_response_maps(self):
        resp = ChatResponse(text="", raw=None, latency_ms=0.0, ok=False, error="boom")
        obs = ChatSurface(_StubTarget(resp)).drive(PromptAction(prompt="p"))
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "boom")

    def test_wrong_action_type_is_a_failure_not_a_raise(self):
        obs = ChatDriver(_StubTarget(None)).drive(
            Surface(id="s", kind=SurfaceKind.CHAT, locator=None,
                    driver=ChatDriver(_StubTarget(None))),
            Action(),
        )
        self.assertFalse(obs.ok)
        self.assertIn("PromptAction", obs.error)


class TestObservation(unittest.TestCase):
    def test_failure_constructor(self):
        o = Observation.failure("dead endpoint")
        self.assertFalse(o.ok)
        self.assertEqual(o.error, "dead endpoint")
        self.assertIsNone(o.custody_hash)

    def test_candidate_is_plain_record(self):
        c = SurfaceCandidate(id="c", kind=SurfaceKind.REST, locator="/api/x", source="openapi")
        self.assertEqual(c.kind, SurfaceKind.REST)
        self.assertEqual(c.source, "openapi")


class TestNoNetwork(unittest.TestCase):
    def test_application_target_construction_does_no_io(self):
        # Building an app + surfaces from a stub must not touch the network. We assert by
        # constructing with a stub target and verifying no send() occurred until driven.
        stub = _StubTarget(ChatResponse(text="", raw=None, latency_ms=0.0, ok=True))
        app = ApplicationTarget(base_url="https://x.example")
        app.add_surface(ChatSurface(stub, surface_id="c"))
        self.assertEqual(stub.sent, [])  # no drive() called => no send()


class TestDependencyDirection(unittest.TestCase):
    def test_targets_source_does_not_import_engine_probes_or_aakg(self):
        # Layering guard. We check the SOURCE imports of every module in glasscage/
        # targets, not runtime sys.modules: importing the subpackage necessarily runs
        # the parent glasscage/__init__.py (which imports the whole pipeline), so a
        # runtime check would report false positives. What matters for layering is that
        # the targets modules themselves never import engine/probes/aakg.
        import ast
        import os

        import glasscage.targets as pkg

        pkg_dir = os.path.dirname(pkg.__file__)
        forbidden = {"engine", "probes", "aakg", "agent_probes"}
        violations = []
        for fn in os.listdir(pkg_dir):
            if not fn.endswith(".py"):
                continue
            tree = ast.parse(open(os.path.join(pkg_dir, fn), encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    tail = node.module.split(".")[-1]
                    if tail in forbidden:
                        violations.append(f"{fn}: from {node.module}")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[-1] in forbidden:
                            violations.append(f"{fn}: import {alias.name}")
        self.assertEqual(violations, [], msg=f"layering violations: {violations}")


if __name__ == "__main__":
    unittest.main()
