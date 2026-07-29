# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Action model tests (ADR 0007).

Covers construction and defaults for the two new action kinds, per-instance mutable
defaults, the unchanged shape of the frozen contract (Action / PromptAction /
Observation), ChatDriver's existing rejection of non-prompt actions, and deterministic
equality and repr.
Run: python -m unittest tests.test_action_model -v
"""

import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.targets import (
    Action,
    ChatDriver,
    HttpAction,
    Observation,
    PromptAction,
    ToolCallAction,
)


class _StubTarget:
    """Records whether the driver ever reached the underlying target."""

    def __init__(self):
        self.url = "https://stub.example/chat"
        self.sent = []

    def send(self, prompt):
        self.sent.append(prompt)
        raise AssertionError("must never be reached for a non-prompt action")


def _fields(cls):
    return {f.name for f in dataclasses.fields(cls)}


# ---------------- construction ----------------
class TestConstruction(unittest.TestCase):
    def test_http_action_requires_method_and_path(self):
        a = HttpAction(method="POST", path="/v1/chat")
        self.assertEqual((a.method, a.path), ("POST", "/v1/chat"))
        with self.assertRaises(TypeError):
            HttpAction(method="GET")

    def test_http_action_optional_fields_default_empty(self):
        a = HttpAction(method="GET", path="/x")
        self.assertEqual(a.query, {})
        self.assertEqual(a.headers, {})
        self.assertIsNone(a.body)

    def test_tool_call_action_requires_a_name(self):
        a = ToolCallAction(name="get_weather")
        self.assertEqual(a.name, "get_weather")
        with self.assertRaises(TypeError):
            ToolCallAction()

    def test_tool_call_arguments_default_empty(self):
        self.assertEqual(ToolCallAction(name="t").arguments, {})


# ---------------- per-instance defaults ----------------
class TestMutableDefaultIsolation(unittest.TestCase):
    def test_http_actions_do_not_share_dicts(self):
        a, b = HttpAction(method="GET", path="/a"), HttpAction(method="GET", path="/b")
        a.headers["X"] = "1"
        a.query["q"] = "2"
        self.assertEqual(b.headers, {})
        self.assertEqual(b.query, {})

    def test_tool_call_actions_do_not_share_arguments(self):
        a, b = ToolCallAction(name="t"), ToolCallAction(name="t")
        a.arguments["k"] = "v"
        self.assertEqual(b.arguments, {})


# ---------------- frozen contract unchanged ----------------
class TestContractStability(unittest.TestCase):
    def test_action_base_declares_no_fields(self):
        self.assertEqual(_fields(Action), set())

    def test_prompt_action_carries_only_prompt(self):
        self.assertEqual(_fields(PromptAction), {"prompt"})

    def test_observation_field_set_is_unchanged(self):
        self.assertEqual(
            _fields(Observation),
            {"ok", "text", "latency_ms", "error", "trace",
             "request", "response", "status", "custody_hash"})

    def test_new_actions_are_action_subclasses(self):
        self.assertTrue(issubclass(HttpAction, Action))
        self.assertTrue(issubclass(ToolCallAction, Action))


# ---------------- existing driver guard ----------------
class TestChatDriverRejectsNonPromptActions(unittest.TestCase):
    def _refused(self, action):
        stub = _StubTarget()
        obs = ChatDriver(stub).drive(None, action)
        self.assertIsInstance(obs, Observation)
        self.assertFalse(obs.ok)
        self.assertEqual(stub.sent, [])          # target never reached
        return obs.error

    def test_http_action_is_refused_by_name(self):
        self.assertIn("HttpAction", self._refused(HttpAction(method="GET", path="/x")))

    def test_tool_call_action_is_refused_by_name(self):
        self.assertIn("ToolCallAction", self._refused(ToolCallAction(name="t")))


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_equality_and_repr_are_stable(self):
        a = HttpAction(method="POST", path="/v1", query={"a": "1"}, body={"b": 2})
        b = HttpAction(method="POST", path="/v1", query={"a": "1"}, body={"b": 2})
        self.assertEqual(a, b)
        self.assertEqual(repr(a), repr(b))
        self.assertEqual(ToolCallAction(name="t", arguments={"x": 1}),
                         ToolCallAction(name="t", arguments={"x": 1}))


if __name__ == "__main__":
    unittest.main()
