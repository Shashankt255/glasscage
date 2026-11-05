# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Exported coverage claims state their provenance (ADR 0028, PR #29).

PR #28 corrected the markdown renderer. The HTML export takes a different path: it embeds
`coverage.statement(cov)` as `DATA.coverage`, which the page renders as its `Coverage:`
line. That statement still read:

    Tested 19 techniques across 11/13 taxonomy categories (LLM01, LLM02, LLM03, ...)

11/13 counts every category carrying a mapped finding, including ones reached only by
questionnaire or configuration review. Runtime coverage on the same run is 7/13 (0.54).
The word "Tested" was applied to the larger, mixed-provenance count, with no runtime figure
and no caveat - the same overstatement PR #28 removed from markdown, still exported.

`statement()` now leads with the runtime figure when the coverage dict carries provenance,
labels the graph-derived count contextual rather than "tested", and appends the caveat.
Values are read from the dict; a legacy (`--no-aakg`) dict carries none of them, so the
runtime sentence is omitted rather than guessed.

Run: python -m unittest tests.test_html_coverage_honesty -v
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage import coverage as legacy_cov

_TOOLS = ("categories_tested", "categories_not_tested", "categories_not_assessable",
          "known_gaps", "techniques_run", "coverage_ratio")


def _aakg_cov():
    """A coverage dict of the shape the AAKG path supplies (carries provenance)."""
    return {
        "techniques_run": 19,
        "categories_tested": ["LLM01", "LLM02", "LLM03"],
        "categories_not_tested": ["LLM04"],
        "categories_not_assessable": [],
        "known_gaps": {},
        "coverage_ratio": 0.77,
        "runtime_coverage_ratio": 0.54,
        "coverage_provenance": {
            "universe": 13,
            "runtime_tested": ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"],
            "config_review_only": ["MCP03", "MCP07"],
            "questionnaire_only": ["LLM03", "LLM08"],
            "not_tested": ["LLM04", "MULTIMODAL"],
        },
        "coverage_ratio_caveat": (
            "coverage_ratio counts questionnaire and configuration-review findings as "
            "tested; use runtime_coverage_ratio for runtime-tested categories only."),
    }


def _legacy_cov():
    """The shape `--no-aakg` supplies: no provenance keys at all."""
    return {
        "techniques_run": 19,
        "categories_tested": ["LLM01", "LLM02", "LLM03"],
        "categories_not_tested": ["LLM04"],
        "categories_not_assessable": [],
        "known_gaps": {},
        "coverage_ratio": 0.77,
    }


class _HtmlCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def run_demo(self, *extra, name="o"):
        buf = io.StringIO()
        out = os.path.join(self.tmp, name)
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(["--demo", "--no-evidence", "--out", out] + list(extra))
        self.assertEqual(rc, 0)
        return out

    def html_coverage(self, out):
        with open(out + ".html", encoding="utf-8") as fh:
            html = fh.read()
        m = re.search(r"const DATA = (\{.*?\});", html, re.DOTALL)
        self.assertIsNotNone(m, "HTML has no DATA block")
        return json.loads(m.group(1)).get("coverage", ""), html


# ---------------- the exported claim ----------------
class TestExportedStatementIsHonest(_HtmlCase):
    def test_html_states_the_runtime_coverage(self):
        """The defect: the export never showed 7/13 or 0.54."""
        cov, _ = self.html_coverage(self.run_demo())
        self.assertIn("Runtime-tested coverage", cov)
        self.assertIn("7/13", cov)
        self.assertIn("0.54", cov)

    def test_html_keeps_the_graph_derived_count_as_context(self):
        cov, _ = self.html_coverage(self.run_demo())
        self.assertIn("11/13", cov)
        self.assertIn("contextual, mixed provenance", cov)

    def test_tested_is_not_attached_to_the_mixed_count(self):
        """The defect: 'Tested 19 techniques across 10/13 taxonomy categories'."""
        cov, _ = self.html_coverage(self.run_demo())
        self.assertNotIn("Tested 19 techniques across 10/13", cov)
        self.assertNotRegex(cov, r"Tested \d+ techniques across \d+/13 taxonomy categories")

    def test_html_carries_the_provenance_and_caveat(self):
        cov, _ = self.html_coverage(self.run_demo())
        for marker in ("Configuration-review only", "Questionnaire only", "Not tested:"):
            self.assertIn(marker, cov, marker)
        self.assertIn("questionnaire and configuration-review findings as tested", cov)

    def test_the_runtime_figure_precedes_the_graph_derived_one(self):
        cov, _ = self.html_coverage(self.run_demo())
        self.assertLess(cov.index("Runtime-tested"), cov.index("Graph-derived"))

    def test_the_disclaimer_is_retained(self):
        cov, _ = self.html_coverage(self.run_demo())
        self.assertIn("NOT a proof of robustness against adaptive attackers", cov)


# ---------------- values are read, not hard-coded ----------------
class TestValuesAreRead(_HtmlCase):
    def test_runtime_figures_come_from_the_coverage_dict(self):
        c = _aakg_cov()
        c["runtime_coverage_ratio"] = 0.11
        c["coverage_provenance"]["runtime_tested"] = ["LLM01"]
        c["coverage_provenance"]["universe"] = 9
        s = legacy_cov.statement(c)
        self.assertIn("1/9", s)
        self.assertIn("0.11", s)

    def test_source_does_not_hard_code_the_demo_values(self):
        """The executable body must carry no literals. The docstring may cite the
        measured example, so it is excluded."""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "glasscage", "coverage.py")
        with open(path, encoding="utf-8") as fh:
            body = fh.read().split("def statement(")[1]
        doc = re.search(r'""".*?"""', body, re.DOTALL)
        code = body[doc.end():] if doc else body
        self.assertNotIn("0.54", code)
        self.assertNotIn("7/13", code)

    def test_the_runtime_claim_is_made_even_when_the_ratios_coincide(self):
        """A run where every mapped category was runtime-tested must still state the
        runtime figure - the claim is not conditional on the two numbers disagreeing."""
        c = _aakg_cov()
        c["coverage_ratio"] = c["runtime_coverage_ratio"]
        s = legacy_cov.statement(c)
        self.assertIn("Runtime-tested coverage", s)
        self.assertIn("7/13", s)

    def test_a_missing_ratio_is_derived_from_provenance(self):
        c = _aakg_cov()
        del c["runtime_coverage_ratio"]
        s = legacy_cov.statement(c)
        self.assertIn("7/13", s)
        self.assertIn("0.54", s)


# ---------------- legacy consumer and degenerate inputs ----------------
class TestLegacyAndDegenerate(_HtmlCase):
    def test_a_legacy_dict_omits_the_runtime_claim_rather_than_guessing(self):
        s = legacy_cov.statement(_legacy_cov())
        self.assertNotIn("Runtime-tested coverage", s)
        self.assertIn("Graph-derived coverage", s)

    def test_a_legacy_dict_still_does_not_call_the_mixed_count_tested(self):
        s = legacy_cov.statement(_legacy_cov())
        self.assertNotRegex(s, r"Tested \d+ techniques across")

    def test_no_aakg_run_still_produces_valid_html(self):
        out = self.run_demo("--no-aakg", name="legacy")
        cov, html = self.html_coverage(out)
        self.assertIn("Graph-derived coverage", cov)
        self.assertTrue(html.strip().endswith("</html>"))

    def test_legacy_markdown_consumer_still_works(self):
        """`report.py:100` appends the same statement to the legacy markdown path.
        Exercised through the real `--no-aakg` run rather than a synthetic recon."""
        out = self.run_demo("--no-aakg", name="legacymd")
        with open(out + ".md", encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("Graph-derived coverage", md)
        self.assertNotRegex(md, r"Tested \d+ techniques across")

    def test_zero_universe_does_not_divide_by_zero(self):
        c = _aakg_cov()
        del c["runtime_coverage_ratio"]
        c["coverage_provenance"] = {"universe": 0, "runtime_tested": [],
                                    "config_review_only": [], "questionnaire_only": [],
                                    "not_tested": []}
        s = legacy_cov.statement(c)          # must not raise ZeroDivisionError
        self.assertIn("0/0", s)

    def test_empty_categories_do_not_crash(self):
        c = _legacy_cov()
        c["categories_tested"] = []
        c["categories_not_tested"] = []
        s = legacy_cov.statement(c)
        self.assertIn("none", s)

    def test_statement_still_returns_a_string(self):
        """The contract `test_stage_e5` relies on."""
        self.assertIsInstance(legacy_cov.statement(_aakg_cov()), str)
        self.assertIsInstance(legacy_cov.statement(_legacy_cov()), str)


# ---------------- nothing else moves ----------------
class TestNothingElseChanges(_HtmlCase):
    def test_posture_and_risk_are_unchanged(self):
        out = self.run_demo()
        with open(out + ".json", encoding="utf-8") as fh:
            s = json.load(fh)["summary"]
        self.assertEqual(s["posture_score"], 42.7)
        self.assertEqual(s["risk_index"], 57.3)

    def test_markdown_still_carries_the_pr28_section(self):
        out = self.run_demo()
        with open(out + ".md", encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("OWASP runtime-tested: 7/13 (0.54)", md)
        self.assertIn("Coverage (graph-derived)", md)

    def test_json_and_sarif_carry_no_coverage_statement(self):
        out = self.run_demo("--sarif")
        for suffix in (".json", ".sarif"):
            with open(out + suffix, encoding="utf-8") as fh:
                txt = fh.read()
            self.assertNotIn("Runtime-tested coverage", txt, suffix)
            self.assertNotIn("coverage_ratio", txt, suffix)


if __name__ == "__main__":
    unittest.main()
