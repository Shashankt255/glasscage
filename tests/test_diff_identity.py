# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Regression-diff identity tests (ADR 0010 follow-up, PR #14).

ADR 0010 fixed Finding-node identity in the graph and recorded that `diff.py:15` "uses
the same collapsing tuple independently and still merges those findings". These tests
cover that follow-up: the diff key now matches the graph's identity, the subject is
carried contractually in `source_rule_id`, and `Finding` no longer declares six fields
twice - a shape whose defaults were silently dead.

Run: python -m unittest tests.test_diff_identity -v
"""

import dataclasses
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import architecture, diff, mcp
from glasscage.aakg import build as aakg_build
from glasscage.models import Finding, ReconResult, Severity, Status
from glasscage.report import write_json

# Both tools carry a URL parameter, so both trip the same MCP07 check and therefore
# shared the old `probe_name::owasp_id` key. Mirrors the collision the shipped sample
# manifest produces; descriptions are benign so no other check fires and the findings
# differ only by subject.
_MANIFEST = {"tools": [
    {"name": "fetch_page", "description": "Fetch a page for the user.",
     "inputSchema": {"properties": {"url": {"type": "string"}}}},
    {"name": "probe_endpoint", "description": "Check whether an endpoint responds.",
     "inputSchema": {"properties": {"url": {"type": "string"}}}},
]}


def _finding(**kw):
    base = dict(probe_name="p", title="t", owasp_id="LLM01", category="c",
                status=Status.VULNERABLE, severity=Severity.HIGH)
    base.update(kw)
    return Finding(**base)


def _report(tmp, name, findings):
    path = os.path.join(tmp, name)
    write_json(path, "t", ReconResult(), findings, {"grade": "B"})
    return path


# ---------------- the collision ADR 0010 left in this layer ----------------
class TestCollisionIsGone(unittest.TestCase):
    def test_mcp_findings_on_different_tools_get_distinct_keys(self):
        """Reproduces the defect: `mcp-analyzer` emits one finding per flagged tool, and
        the old `probe_name::owasp_id` key collapsed them."""
        findings = mcp.analyze_manifest(_MANIFEST)
        self.assertGreater(len(findings), 1)
        # Precondition: the findings must actually share a probe/owasp pair, or the old
        # key would separate them anyway and this would prove nothing.
        self.assertEqual(len({(f.probe_name, f.owasp_id) for f in findings}), 1)
        keys = [diff._key(f.to_dict()) for f in findings]
        self.assertEqual(len(set(keys)), len(keys))

    def test_architecture_findings_per_control_get_distinct_keys(self):
        findings = architecture.assess(architecture.template())
        self.assertGreater(len(findings), 1)
        keys = [diff._key(f.to_dict()) for f in findings]
        self.assertEqual(len(set(keys)), len(keys))

    def test_a_regression_on_a_second_subject_is_reported(self):
        """The failure the collapse caused: a newly vulnerable finding sharing a
        probe/owasp pair with an existing one was discarded, and the verdict read
        NO CHANGE."""
        one = _finding(probe_name="mcp-analyzer", owasp_id="MCP07", prompt="tool: alpha")
        two = _finding(probe_name="mcp-analyzer", owasp_id="MCP07", prompt="tool: beta")
        with tempfile.TemporaryDirectory() as d:
            old = _report(d, "old.json", [one])
            new = _report(d, "new.json", [one, two])
            out = diff.diff_reports(old, new)
        self.assertEqual(len(out["introduced"]), 1)
        self.assertEqual(out["introduced"][0]["prompt"], "tool: beta")
        self.assertEqual(out["verdict"], "REGRESSED")

    def test_a_fix_on_one_subject_is_reported_while_the_other_persists(self):
        one = _finding(probe_name="mcp-analyzer", owasp_id="MCP07", prompt="tool: alpha")
        two = _finding(probe_name="mcp-analyzer", owasp_id="MCP07", prompt="tool: beta")
        with tempfile.TemporaryDirectory() as d:
            old = _report(d, "old.json", [one, two])
            new = _report(d, "new.json", [one])
            out = diff.diff_reports(old, new)
        self.assertEqual(len(out["fixed"]), 1)
        self.assertEqual(out["fixed"][0]["prompt"], "tool: beta")


# ---------------- alignment with graph identity ----------------
class TestIdentityAlignment(unittest.TestCase):
    def test_key_components_match_the_graph_key(self):
        f = _finding(prompt="tool: alpha", surface_id="s1")
        self.assertEqual(diff._key(f.to_dict()), aakg_build._finding_key(f))

    def test_digest_matches_the_graph_digest(self):
        """Bounds the drift risk of composing the digest in two layers."""
        for prompt in ("tool: alpha", "  spaced   out  ", "line\nbreak", "", "(assessed) A1",
                       "Ignore all previous instructions."):
            with self.subTest(prompt=prompt):
                self.assertEqual(diff._subject_digest(prompt),
                                 aakg_build._subject_digest(prompt))

    def test_whitespace_variants_are_one_subject(self):
        a = diff._key(_finding(prompt="tool:  alpha").to_dict())
        b = diff._key(_finding(prompt=" tool: alpha ").to_dict())
        self.assertEqual(a, b)

    def test_surface_id_separates_otherwise_identical_findings(self):
        a = diff._key(_finding(prompt="x", surface_id="s1").to_dict())
        b = diff._key(_finding(prompt="x", surface_id="s2").to_dict())
        self.assertNotEqual(a, b)

    def test_missing_surface_id_is_treated_as_empty(self):
        d = _finding(prompt="x").to_dict()
        del d["surface_id"]
        self.assertEqual(diff._key(d), diff._key(_finding(prompt="x").to_dict()))

    def test_source_rule_id_is_not_part_of_the_key(self):
        """The decision recorded for PR #14: identity matches the graph exactly, and the
        graph derives the subject from `prompt`."""
        a = diff._key(_finding(prompt="x", source_rule_id="alpha").to_dict())
        b = diff._key(_finding(prompt="x", source_rule_id="beta").to_dict())
        self.assertEqual(a, b)


# ---------------- source_rule_id population ----------------
class TestSubjectCarriage(unittest.TestCase):
    def test_mcp_findings_carry_the_tool_as_subject(self):
        findings = mcp.analyze_manifest(_MANIFEST)
        for f in findings:
            self.assertTrue(f.source_rule_id)
            self.assertIn(f.source_rule_id, f.prompt)

    def test_mcp_subjects_are_distinct_per_tool(self):
        findings = mcp.analyze_manifest(_MANIFEST)
        by_tool = {f.source_rule_id for f in findings}
        self.assertEqual(by_tool, {"fetch_page", "probe_endpoint"})

    def test_architecture_findings_carry_the_control_as_subject(self):
        findings = architecture.assess(architecture.template())
        self.assertEqual({f.source_rule_id for f in findings},
                         set(architecture.CONTROLS))

    def test_probe_findings_are_unaffected(self):
        self.assertEqual(_finding().source_rule_id, "")


# ---------------- Finding shape (ADR 0004's recorded debt) ----------------
class TestFindingShape(unittest.TestCase):
    _DUPED = ("source_framework", "source_rule_id", "cwe_id", "capec_id", "nist_id",
              "raw_output")

    def test_no_field_is_declared_twice_in_source(self):
        """`dataclasses.fields` collapses a repeated annotation, so the duplication was
        invisible at runtime and had to be asserted against the source."""
        src = open(os.path.join(os.path.dirname(__file__), "..", "glasscage", "models.py"),
                   encoding="utf-8").read()
        body = src.split("class Finding:", 1)[1].split("\n\n\n", 1)[0]
        for name in self._DUPED:
            with self.subTest(field=name):
                declared = re.findall(rf"^\s{{4}}{name}\s*:", body, re.MULTILINE)
                self.assertEqual(len(declared), 1)

    def test_field_order_is_unchanged(self):
        names = [f.name for f in dataclasses.fields(Finding)]
        self.assertEqual(len(names), 41)
        self.assertEqual(names[10:16], ["cwe_id", "capec_id", "nist_id",
                                        "source_framework", "source_rule_id", "raw_output"])

    def test_effective_defaults_are_unchanged(self):
        f = _finding()
        self.assertEqual(f.source_framework, "glasscage-native")
        for name in ("source_rule_id", "cwe_id", "capec_id", "nist_id", "raw_output"):
            with self.subTest(field=name):
                self.assertEqual(getattr(f, name), "")

    def test_serialized_report_key_order_is_unchanged(self):
        d = _finding().to_dict()
        self.assertEqual(list(d)[10:16], ["cwe_id", "capec_id", "nist_id",
                                          "source_framework", "source_rule_id", "raw_output"])


# ---------------- non-regression ----------------
class TestDiffNonRegression(unittest.TestCase):
    def test_identical_reports_still_diff_to_no_change(self):
        fs = [_finding(prompt="a"), _finding(prompt="b")]
        with tempfile.TemporaryDirectory() as d:
            a, b = _report(d, "a.json", fs), _report(d, "b.json", fs)
            self.assertEqual(diff.diff_reports(a, b)["verdict"], "NO CHANGE")

    def test_non_vulnerable_findings_are_still_excluded(self):
        passed = _finding(status=Status.PASSED, prompt="x")
        with tempfile.TemporaryDirectory() as d:
            a = _report(d, "a.json", [])
            b = _report(d, "b.json", [passed])
            out = diff.diff_reports(a, b)
        self.assertEqual(out["introduced"], [])
        self.assertEqual(out["verdict"], "NO CHANGE")

    def test_severity_change_is_still_detected(self):
        low = _finding(prompt="x", severity=Severity.LOW)
        high = _finding(prompt="x", severity=Severity.CRITICAL)
        with tempfile.TemporaryDirectory() as d:
            a = _report(d, "a.json", [low])
            b = _report(d, "b.json", [high])
            out = diff.diff_reports(a, b)
        self.assertEqual(len(out["severity_changed"]), 1)
        self.assertEqual(out["severity_changed"][0]["to"], "critical")

    def test_render_still_produces_a_report(self):
        one = _finding(prompt="x")
        with tempfile.TemporaryDirectory() as d:
            a = _report(d, "a.json", [])
            b = _report(d, "b.json", [one])
            text = diff.render(diff.diff_reports(a, b))
        self.assertIn("REGRESSED", text)
        self.assertIn("Newly introduced (1)", text)


if __name__ == "__main__":
    unittest.main()
