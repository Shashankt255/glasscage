# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Probe surface-applicability tests (ADR 0006).

Covers: the declared default, gating of a probe against a surface kind it does not
drive, applicability being checked before capability tier, plugin backward
compatibility for probes that declare nothing, and unchanged behaviour on the CHAT path.
Run: python -m unittest tests.test_probe_applicability -v
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import coverage_provenance
from glasscage.engine import Engine
from glasscage.models import Status
from glasscage.probes import Probe, all_probes
from glasscage.refagent import ReferenceAgent
from glasscage.tal import Tier
from glasscage.targets import ChatSurface, SurfaceKind

_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[0-9.:+\-]*")


def _stable(text):
    return _TS.sub("<TS>", text)


class _RestOnlyProbe(Probe):
    """Declares a kind that is never driven today, so the deny branch is reachable."""

    name = "rest-only-test-probe"
    owasp_id = "LLM01"
    category = "Test"
    surface_kinds = (SurfaceKind.REST,)

    def __init__(self):
        self.calls = 0

    def run(self, target, recon):
        self.calls += 1
        return []


class _RestOnlyHighTierProbe(_RestOnlyProbe):
    """Inapplicable AND tier-gated: applicability must win."""

    name = "rest-only-l3-test-probe"
    min_tier = Tier.L3


class _ChatHighTierProbe(Probe):
    """Applicable but tier-gated: the tier reason must be preserved."""

    name = "chat-l3-test-probe"
    owasp_id = "LLM01"
    category = "Test"
    min_tier = Tier.L3

    def __init__(self):
        self.calls = 0

    def run(self, target, recon):
        self.calls += 1
        return []


class _LegacyPluginProbe:
    """A third-party probe from before ADR 0006: declares no surface_kinds at all."""

    name = "legacy-plugin-test-probe"
    owasp_id = "LLM01"
    category = "Test"
    min_tier = Tier.L0

    def __init__(self):
        self.calls = 0

    def run(self, target, recon):
        self.calls += 1
        return []


def _run(probes, target=None, **kw):
    t = target if target is not None else ReferenceAgent()
    eng = Engine(t, capture_evidence=False, selected_probes=probes, **kw)
    return eng, eng.run()


def _gated(results, name):
    return [f for f in results["findings"] if f.probe_name == name]


# ---------------- declaration ----------------
class TestDeclaration(unittest.TestCase):
    def test_default_is_chat_only(self):
        self.assertEqual(Probe.surface_kinds, (SurfaceKind.CHAT,))

    def test_every_registered_probe_is_chat_applicable(self):
        probes = all_probes()
        self.assertEqual(len(probes), 21)
        for p in probes:
            self.assertIn(SurfaceKind.CHAT, getattr(p, "surface_kinds", ()))

    def test_a_subclass_may_narrow_or_widen(self):
        self.assertEqual(_RestOnlyProbe.surface_kinds, (SurfaceKind.REST,))

        class _Both(Probe):
            surface_kinds = (SurfaceKind.CHAT, SurfaceKind.REST)

        self.assertIn(SurfaceKind.CHAT, _Both.surface_kinds)


# ---------------- gating ----------------
class TestGating(unittest.TestCase):
    def test_inapplicable_probe_yields_one_not_assessable(self):
        probe = _RestOnlyProbe()
        _, res = _run([probe])
        found = _gated(res, probe.name)
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].status, Status.NOT_ASSESSABLE)

    def test_inapplicable_probe_is_never_invoked(self):
        probe = _RestOnlyProbe()
        _run([probe])
        self.assertEqual(probe.calls, 0)

    def test_inapplicable_probe_sends_no_traffic(self):
        class _CountingAgent(ReferenceAgent):
            def __init__(self):
                super().__init__()
                self.sends = 0

            def send(self, prompt):
                self.sends += 1
                return super().send(prompt)

        agent = _CountingAgent()
        before = agent.sends
        _run([_RestOnlyProbe()], target=agent)
        # recon still probes the target; the gated probe adds nothing beyond it.
        self.assertEqual(agent.sends - before, 3)   # recon's three benign probes only

    def test_title_names_driven_kind_and_declared_kinds(self):
        probe = _RestOnlyProbe()
        _, res = _run([probe])
        title = _gated(res, probe.name)[0].title
        self.assertIn("chat", title)
        self.assertIn("rest", title)
        self.assertIn("NOT ASSESSABLE", title)


# ---------------- ordering ----------------
class TestGateOrdering(unittest.TestCase):
    def test_applicability_is_reported_before_tier(self):
        probe = _RestOnlyHighTierProbe()
        _, res = _run([probe])
        f = _gated(res, probe.name)[0]
        self.assertEqual(f.prompt, "(surface-gated)")
        self.assertIn("surface", f.title)

    def test_applicable_but_tier_gated_still_reports_tier(self):
        probe = _ChatHighTierProbe()
        _, res = _run([probe])
        f = _gated(res, probe.name)[0]
        self.assertEqual(f.prompt, "(tier-gated)")
        self.assertIn("requires L3", f.title)
        self.assertEqual(probe.calls, 0)


# ---------------- backward compatibility ----------------
class TestBackwardCompatibility(unittest.TestCase):
    def test_probe_without_surface_kinds_still_runs(self):
        probe = _LegacyPluginProbe()
        _, res = _run([probe])
        self.assertEqual(probe.calls, 1)
        self.assertEqual(_gated(res, probe.name), [])

    def test_default_run_has_no_surface_gated_finding(self):
        _, res = _run(None)
        self.assertTrue(res["findings"])
        self.assertEqual([f for f in res["findings"] if f.prompt == "(surface-gated)"], [])

    def test_chat_surface_driven_run_is_not_gated(self):
        agent = ReferenceAgent()
        eng = Engine(agent, capture_evidence=False, surface=ChatSurface(agent))
        res = eng.run()
        self.assertEqual([f for f in res["findings"] if f.prompt == "(surface-gated)"], [])


# ---------------- integration ----------------
class TestIntegration(unittest.TestCase):
    def test_runtime_coverage_ratio_is_unchanged(self):
        self.assertEqual(coverage_provenance.summarize()["runtime_coverage_ratio"], 0.54)

    def test_aakg_serialization_is_deterministic(self):
        e1, _ = _run(None)
        e2, _ = _run(None)
        a = json.dumps(e1._graph_obj.to_dict(), sort_keys=True)
        b = json.dumps(e2._graph_obj.to_dict(), sort_keys=True)
        self.assertEqual(_stable(a), _stable(b))


if __name__ == "__main__":
    unittest.main()
