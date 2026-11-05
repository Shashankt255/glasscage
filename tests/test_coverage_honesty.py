# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Coverage reporting states its provenance (ADR 0027, PR #28).

`aakg/coverage.py` computes an honest `runtime_coverage_ratio`, a `coverage_provenance`
breakdown and a `coverage_ratio_caveat`. None of them reached any artifact. The primary
markdown report rendered only the graph-derived taxonomy counts, under a `[Measured]` label:

    ## Coverage (graph-derived)  [Measured]
    - **OWASP**: 11/13 tested (demonstrated 2, hypothesized 9, not-assessable 0)

11/13 counts every category with a mapped finding, including ones reached by questionnaire,
model-card review, or configuration review. Only **7/13** had a payload actually sent. The operator was shown
the larger number, labelled as a measurement, with no caveat anywhere.

Established during discovery and unchanged by this PR: the inflated ratio does **not** feed
the score. Substituting 0.54 for 0.77 leaves `posture_score` 42.7 and `risk_index` 57.3
identical — `risk_index` is computed before `cov_ratio` is read. This PR is a reporting fix,
not a scoring fix, and the scores are asserted unchanged below.

Run: python -m unittest tests.test_coverage_honesty -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage.aakg import report as GRPT


def _demo_markdown(tmp, *extra):
    buf = io.StringIO()
    out = os.path.join(tmp, "o")
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        cli.main(["--demo", "--no-evidence", "--out", out] + list(extra))
    with open(out + ".md", encoding="utf-8") as fh:
        return fh.read(), out


class _ReportCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def md(self, *extra):
        text, self.out = _demo_markdown(self.tmp, *extra)
        return text

    def section(self, text):
        i = text.find("## Coverage")
        self.assertNotEqual(i, -1, "no Coverage section rendered")
        return text[i:text.find("## (impact figures", i)]


# ---------------- the measured claim ----------------
class TestRuntimeCoverageIsStated(_ReportCase):
    def test_runtime_tested_ratio_is_rendered(self):
        """The defect: the report never showed 7/13 or 0.54."""
        s = self.section(self.md())
        self.assertIn("runtime-tested", s)
        self.assertIn("7/13", s)
        self.assertIn("0.54", s)

    def test_the_runtime_figure_is_the_measured_claim(self):
        s = self.section(self.md())
        line = next(l for l in s.splitlines() if "runtime-tested:" in l)
        self.assertIn("Measured", line)

    def test_the_runtime_figure_precedes_the_graph_derived_one(self):
        s = self.section(self.md())
        self.assertLess(s.index("runtime-tested"), s.index("graph-derived"))

    def test_the_runtime_ratio_comes_from_the_coverage_dict(self):
        """Not hard-coded: a substituted ratio must be what is rendered."""
        g, res = self._graph_with(runtime_coverage_ratio=0.11)
        md = GRPT.to_markdown(g, res, "demo")
        self.assertIn("(0.11)", md)

    def _graph_with(self, **override):
        """A real graph/result pair with the coverage dict adjusted."""
        from glasscage.engine import Engine
        from glasscage.refagent import ReferenceAgent
        eng = Engine(ReferenceAgent(), capture_evidence=False)
        res = eng.run()                      # builds _graph_obj as a side effect
        res["coverage"] = {**(res.get("coverage") or {}), **override}
        return eng._graph_obj, res


# ---------------- provenance breakdown ----------------
class TestProvenanceBreakdown(_ReportCase):
    def test_the_four_provenance_buckets_are_rendered(self):
        s = self.section(self.md())
        for label in ("runtime-tested:", "configuration-review only:",
                      "questionnaire only:", "not tested:"):
            self.assertIn(label, s, label)

    def test_config_review_and_questionnaire_categories_are_named(self):
        s = self.section(self.md())
        self.assertIn("LLM03", s)      # questionnaire-only on the demo target
        self.assertIn("MCP03", s)      # configuration-review only

    def test_untested_categories_are_named(self):
        s = self.section(self.md())
        self.assertIn("LLM04", s)


# ---------------- the caveat ----------------
class TestCaveatIsRendered(_ReportCase):
    def test_the_caveat_text_is_present(self):
        s = self.section(self.md())
        self.assertIn("questionnaire and configuration-review findings as tested", s)

    def test_the_caveat_is_not_truncated(self):
        s = self.section(self.md())
        self.assertIn("use runtime_coverage_ratio for runtime-tested categories only", s)


# ---------------- the mixed figure is not a measurement ----------------
class TestGraphDerivedIsContextual(_ReportCase):
    def test_graph_derived_counts_remain_available(self):
        s = self.section(self.md())
        self.assertIn("11/13", s)

    def test_graph_derived_is_not_labelled_measured(self):
        """The defect: this block carried [Measured]."""
        s = self.section(self.md())
        head = next(l for l in s.splitlines() if "graph-derived" in l and l.startswith("#"))
        self.assertNotIn("[Measured]", head)
        self.assertIn("Observed", head)

    def test_graph_derived_is_marked_mixed_provenance(self):
        s = self.section(self.md())
        self.assertIn("mixed provenance", s)

    def test_the_two_figures_are_distinguishable(self):
        """7/13 and 11/13 must not be conflated into one claim."""
        s = self.section(self.md())
        self.assertIn("7/13", s)
        self.assertIn("11/13", s)
        self.assertLess(s.index("7/13"), s.index("11/13"))

    def test_graph_counts_no_longer_claim_bare_tested(self):
        s = self.section(self.md())
        self.assertIn("categories with a mapped finding", s)


# ---------------- nothing else moves ----------------
class TestNothingElseChanges(_ReportCase):
    def test_posture_score_and_risk_index_are_unchanged(self):
        """This is a reporting fix; the score never depended on the ratio."""
        self.md()
        with open(self.out + ".json", encoding="utf-8") as fh:
            s = json.load(fh)["summary"]
        self.assertEqual(s["posture_score"], 42.7)
        self.assertEqual(s["risk_index"], 57.3)

    def test_json_carries_no_coverage_block(self):
        """PR28 adds no machine-readable output contract."""
        self.md()
        with open(self.out + ".json", encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertNotIn("coverage", rep)

    def test_sarif_is_unaffected(self):
        self.md("--sarif")
        with open(self.out + ".sarif", encoding="utf-8") as fh:
            txt = fh.read()
        self.assertNotIn("runtime_coverage_ratio", txt)
        self.assertNotIn("coverage_ratio_caveat", txt)

    def test_html_still_renders(self):
        self.md()
        with open(self.out + ".html", encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("const DATA", html)
        self.assertTrue(html.strip().endswith("</html>"))

    def test_audience_views_are_unaffected(self):
        self.md("--views", "all")
        for aud in ("executive", "security", "developer"):
            p = f"{self.out}_view_{aud}.md"
            with open(p, encoding="utf-8") as fh:
                txt = fh.read()
            self.assertNotIn("runtime-tested", txt, aud)


# ---------------- degenerate inputs ----------------
class TestDegenerateCoverage(_ReportCase):
    def _graph(self):
        from glasscage.engine import Engine
        from glasscage.refagent import ReferenceAgent
        eng = Engine(ReferenceAgent(), capture_evidence=False)
        res = eng.run()                      # builds _graph_obj as a side effect
        return eng._graph_obj, res

    def test_absent_coverage_renders_no_section_and_does_not_crash(self):
        """No data means no section at all - not an empty heading."""
        g, res = self._graph()
        res["coverage"] = {}
        md = GRPT.to_markdown(g, res, "demo")
        self.assertNotIn("runtime-tested", md)
        self.assertNotIn("## Coverage", md)
        self.assertNotIn("graph-derived) —", md)

    def test_zero_universe_does_not_divide_by_zero(self):
        g, res = self._graph()
        res["coverage"] = {"coverage_provenance": {
            "universe": 0, "runtime_tested": [], "config_review_only": [],
            "questionnaire_only": [], "not_tested": []}}
        md = GRPT.to_markdown(g, res, "demo")   # must not raise ZeroDivisionError
        self.assertIn("0/0", md)

    def test_missing_ratio_is_derived_rather_than_crashing(self):
        g, res = self._graph()
        prov = dict((res.get("coverage") or {}).get("coverage_provenance") or {})
        res["coverage"] = {"coverage_provenance": prov}      # no runtime_coverage_ratio
        md = GRPT.to_markdown(g, res, "demo")
        self.assertIn("runtime-tested", md)

    def test_no_aakg_path_is_unaffected(self):
        buf = io.StringIO()
        out = os.path.join(self.tmp, "legacy")
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(["--demo", "--no-aakg", "--no-evidence", "--out", out])
        self.assertEqual(rc, 0)
        with open(out + ".md", encoding="utf-8") as fh:
            self.assertNotIn("runtime-tested", fh.read())


if __name__ == "__main__":
    unittest.main()
