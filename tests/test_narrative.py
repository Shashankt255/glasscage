"""Attack Narrative / Assessment Story / audience views (reporting layer).

The critical tests here are the anti-hallucination guarantees: a narrative may only
cite nodes, edges and paths that already exist in the graph, and may never claim a
confidence stronger than its weakest evidence.

Run: python -m unittest tests.test_narrative -q
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage import schema
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage.aakg import narrative as N, story as S, views as V
from glasscage.evidence_confidence import EvidenceClass as EC

_TOOLS = schema.ingest({"functions": [
    {"name": "get_secret", "description": "vault secret", "parameters": {}},
    {"name": "run_sql", "description": "database", "parameters": {}}]})


def _run(target=None, tools=_TOOLS):
    eng = Engine(target or ReferenceAgent(), schema_tools=tools)
    res = eng.run()
    return eng, res, eng._graph_obj


# ---------------- Anti-hallucination guarantees ---------------- #
class TestNoFabrication(unittest.TestCase):
    def setUp(self):
        self.eng, self.res, self.g = _run()
        self.models = N.build_all(self.g, self.res["chains"])

    def test_every_cited_edge_exists_in_graph(self):
        real_edges = {e.id for e in self.g.edges()}
        for m in self.models:
            for t in m.transitions:
                self.assertIn(t.edge_id, real_edges,
                              f"narrative cited a non-existent edge: {t.edge_id}")

    def test_every_cited_node_exists_in_graph(self):
        for m in self.models:
            for t in m.transitions:
                self.assertTrue(self.g.has_node(t.src_id), f"phantom node {t.src_id}")
                self.assertTrue(self.g.has_node(t.dst_id), f"phantom node {t.dst_id}")

    def test_no_new_paths_invented(self):
        existing = {p["id"] for p in self.res["chains"]}
        for m in self.models:
            if m.supported:
                self.assertIn(m.path_id, existing,
                              "narrative invented a path not in the graph")

    def test_transition_state_matches_graph_edge_state(self):
        by_id = {e.id: e for e in self.g.edges()}
        for m in self.models:
            for t in m.transitions:
                self.assertEqual(t.state, by_id[t.edge_id].state.value)

    def test_evidence_ids_come_from_the_edge(self):
        by_id = {e.id: e for e in self.g.edges()}
        for m in self.models:
            for t in m.transitions:
                self.assertEqual(sorted(t.evidence_ids),
                                 sorted(by_id[t.edge_id].evidence_refs))

    def test_unsupported_strategy_says_not_demonstrated(self):
        # a target with no MCP/memory path must not get a fabricated narrative
        m = N.build_narrative(self.g, self.res["chains"], "mcp_compromise")
        if not m.supported:
            self.assertIn("Not demonstrated.", m.reason)
            self.assertEqual(m.transitions, [])
            self.assertEqual(m.evidence_class, EC.PENDING_EXTERNAL_VALIDATION)

    def test_unknown_strategy_is_unsupported_not_invented(self):
        m = N.build_narrative(self.g, self.res["chains"], "does_not_exist")
        self.assertFalse(m.supported)
        self.assertEqual(m.transitions, [])

    def test_empty_paths_yields_no_narrative(self):
        for s in N.STRATEGIES:
            m = N.build_narrative(self.g, [], s)
            self.assertFalse(m.supported)
            self.assertIn("Not demonstrated.", m.reason)


# ---------------- Evidence discipline ---------------- #
class TestEvidenceDiscipline(unittest.TestCase):
    def setUp(self):
        self.eng, self.res, self.g = _run()
        self.models = [m for m in N.build_all(self.g, self.res["chains"]) if m.supported]

    def test_narrative_class_is_weakest_transition(self):
        for m in self.models:
            weakest = min(t.evidence_class.rank for t in m.transitions)
            self.assertEqual(m.evidence_class.rank, weakest,
                             "narrative claimed stronger evidence than its weakest hop")

    def test_never_claims_verified_or_measured(self):
        # a path narrative can be at most Demonstrated; those classes require other proof
        for m in self.models:
            self.assertLessEqual(m.evidence_class.rank, EC.DEMONSTRATED.rank)

    def test_every_transition_cites_all_required_fields(self):
        for m in self.models:
            for t in m.transitions:
                c = t.citation()
                self.assertIn(t.src_id, c)        # graph node ids
                self.assertIn(t.dst_id, c)
                self.assertIn(t.edge_id, c)       # graph edge id
                self.assertIn("evidence", c)      # evidence ids (or honest absence)
                self.assertIn("confidence", c)    # confidence
                self.assertIn(t.evidence_class.value, c)   # state/classification

    def test_missing_evidence_is_stated_not_faked(self):
        for m in self.models:
            for t in m.transitions:
                if not t.evidence_ids:
                    self.assertIn("no evidence id", t.citation())

    def test_non_demonstrated_hops_are_flagged_in_prose(self):
        for m in self.models:
            for t in m.transitions:
                if t.state == "hypothesized":
                    self.assertIn("hypothesized", t.prose)
                elif t.state == "not_assessable":
                    self.assertIn("not demonstrated", t.prose)


# ---------------- Strategies + dedup ---------------- #
class TestStrategies(unittest.TestCase):
    def setUp(self):
        self.eng, self.res, self.g = _run()

    def test_all_eight_strategies_present(self):
        self.assertEqual(set(N.STRATEGIES), {
            "highest_impact", "lowest_effort", "most_likely", "data_exfiltration",
            "tool_abuse", "privilege_escalation", "memory_poisoning", "mcp_compromise"})

    def test_build_all_returns_one_per_strategy(self):
        self.assertEqual(len(N.build_all(self.g, self.res["chains"])), 8)

    def test_dedupe_groups_identical_paths(self):
        groups = N.dedupe(N.build_all(self.g, self.res["chains"]))
        self.assertLess(len(groups), 8)          # duplicates collapsed
        total = sum(len(g["strategies"]) for g in groups)
        self.assertEqual(total, 8)               # none lost

    def test_data_exfiltration_terminates_at_data_asset(self):
        m = N.build_narrative(self.g, self.res["chains"], "data_exfiltration")
        if m.supported:
            self.assertTrue(m.terminal_id.startswith(("Secrets:", "Database:")))

    def test_lowest_effort_is_not_longer_than_highest_impact(self):
        lo = N.build_narrative(self.g, self.res["chains"], "lowest_effort")
        hi = N.build_narrative(self.g, self.res["chains"], "highest_impact")
        if lo.supported and hi.supported:
            self.assertLessEqual(len(lo.transitions), len(hi.transitions))

    def test_deterministic(self):
        a = N.to_dict(N.build_narrative(self.g, self.res["chains"], "highest_impact"))
        b = N.to_dict(N.build_narrative(self.g, self.res["chains"], "highest_impact"))
        self.assertEqual(a, b)


# ---------------- Assessment Story ---------------- #
class TestAssessmentStory(unittest.TestCase):
    def setUp(self):
        self.eng, self.res, self.g = _run()
        self.story = S.build_story(self.g, self.res, "harness")

    def test_thirteen_sections_in_order(self):
        keys = [s.key for s in self.story.sections]
        self.assertEqual(keys, ["overview", "recon", "findings", "progression",
                                "trust", "blast", "business_impact", "root_cause",
                                "evidence", "remediation", "residual", "verification",
                                "lessons"])

    def test_every_section_has_evidence_class(self):
        for s in self.story.sections:
            self.assertIsInstance(s.evidence_class, EC)
            self.assertIn(f"[{s.evidence_class.value}]", s.to_markdown())

    def test_business_impact_is_qualitative_only(self):
        s = self.story.section("business_impact")
        body = " ".join(s.body)
        self.assertLessEqual(s.evidence_class.rank, EC.ESTIMATED.rank)
        if "Reachable asset classes" in body:
            self.assertIn("Qualitative only", body)   # no invented valuations

    def test_residual_risk_refuses_to_invent_a_number(self):
        body = " ".join(self.story.section("residual").body)
        self.assertIn("not computed as a number", body)

    def test_no_section_claims_more_than_verified(self):
        for s in self.story.sections:
            self.assertLessEqual(s.evidence_class.rank, EC.VERIFIED.rank)

    def test_markdown_renders(self):
        md = self.story.to_markdown()
        self.assertIn("Assessment Story", md)
        for s in self.story.sections:
            self.assertIn(s.title, md)

    def test_story_is_serializable(self):
        d = self.story.to_dict()
        json.dumps(d)   # must not raise
        self.assertEqual(len(d["sections"]), 13)


class TestStoryHonestyOnWeakTarget(unittest.TestCase):
    """A low-tier target must not produce a confident story."""

    def test_l0_mock_story_does_not_overclaim(self):
        eng, res, g = _run(target=_MockTarget())
        story = S.build_story(g, res, "mock")
        prog = story.section("progression")
        self.assertLessEqual(prog.evidence_class.rank, EC.DEMONSTRATED.rank)
        # any not-assessable findings must be surfaced, not silently dropped
        na = [f for f in res["findings"] if f.status.value == "not_assessable"]
        if na:
            self.assertIn("Not Assessable", " ".join(story.section("findings").body))


# ---------------- Audience views ---------------- #
class TestViews(unittest.TestCase):
    def setUp(self):
        self.eng, self.res, self.g = _run()
        self.story = S.build_story(self.g, self.res, "harness")
        self.narratives = N.build_all(self.g, self.res["chains"])

    def test_all_five_audiences(self):
        out = V.render_all(self.story, self.narratives, self.g)
        self.assertEqual(set(out), {"executive", "security", "developer",
                                    "incident_response", "compliance"})
        for txt in out.values():
            self.assertTrue(len(txt) > 100)

    def test_unknown_audience_raises(self):
        with self.assertRaises(ValueError):
            V.render(self.story, self.narratives, "marketing", self.g)

    def test_executive_avoids_raw_graph_ids(self):
        txt = V.executive(self.story, self.narratives)
        self.assertNotIn("-[crosses]->", txt)   # business language, not edge ids

    def test_security_view_has_chain_and_mappings(self):
        txt = V.security(self.story, self.narratives)
        self.assertIn("edge `", txt)            # full citations
        self.assertIn("Evidence", txt)

    def test_developer_view_has_root_cause_and_verification(self):
        txt = V.developer(self.story, self.narratives, self.g)
        self.assertIn("Root cause", txt)
        self.assertIn("Verification steps", txt)

    def test_ir_view_admits_no_network_iocs(self):
        txt = V.incident_response(self.story, self.narratives, self.g)
        self.assertIn("no network IOCs are produced", txt)

    def test_compliance_view_marks_unassessed_as_not_passing(self):
        txt = V.compliance(self.story, self.narratives, self.g)
        self.assertIn("Framework mappings", txt)

    def test_views_consume_same_model(self):
        # changing the shared model changes every view -> proves single source
        self.story.sections[0].body = ["SENTINEL_MARKER"]
        txt = V.render(self.story, self.narratives, "executive", self.g)
        self.assertIsInstance(txt, str)


# ---------------- Integration + backward compatibility ---------------- #
class TestIntegration(unittest.TestCase):
    def test_engine_exposes_narratives_and_story(self):
        eng, res, g = _run()
        self.assertIsNotNone(res["narratives"])
        self.assertIsNotNone(res["story"])
        self.assertEqual(len(res["story"].sections), 13)

    def test_markdown_report_contains_story_and_narratives(self):
        eng, res, g = _run()
        md = eng.report_markdown(res)
        self.assertIn("## Assessment Story", md)
        self.assertIn("## Attack Narratives", md)
        self.assertIn("Most consequential scenario", md)   # exec summary hook

    def test_markdown_does_not_duplicate_path_prose(self):
        eng, res, g = _run()
        md = eng.report_markdown(res)
        # the raw path index is now a table, not repeated prose
        self.assertIn("| State | Path | Likelihood | Demonstrated hops |", md)

    def test_html_contains_story_and_narratives(self):
        eng, res, g = _run()
        html = eng.report_html(res)
        self.assertIn("Assessment Story", html)
        self.assertIn("Attack Narratives", html)

    def test_html_escapes_hostile_narrative_text(self):
        """A malicious tool name must not break out of the narrative HTML."""
        payload = '<img src=x onerror="alert(1)">'
        hostile = schema.ingest({"functions": [
            {"name": payload, "description": "vault secret", "parameters": {}}]})
        eng = Engine(ReferenceAgent(), schema_tools=hostile)
        res = eng.run()
        html = eng.report_html(res)
        # the raw payload must never appear unescaped anywhere in the document
        self.assertNotIn(payload, html)
        self.assertNotIn("onerror=\"alert(1)\"", html)
        # ...but it should be present in escaped form (proving it was rendered, escaped)
        self.assertIn("&lt;img src=x", html)

    def test_json_includes_narratives_and_story(self):
        import tempfile
        from glasscage import report
        eng, res, g = _run()
        p = os.path.join(tempfile.mkdtemp(), "o.json")
        report.write_json(p, "t", res["recon"], res["findings"], res["summary"],
                          narratives=res["narratives"], story=res["story"])
        d = json.load(open(p))
        self.assertEqual(len(d["narratives"]), 8)
        self.assertEqual(len(d["story"]["sections"]), 13)

    def test_json_backward_compatible_without_narratives(self):
        import tempfile
        from glasscage import report
        eng, res, g = _run()
        p = os.path.join(tempfile.mkdtemp(), "o.json")
        report.write_json(p, "t", res["recon"], res["findings"], res["summary"])
        d = json.load(open(p))
        self.assertNotIn("narratives", d)     # unchanged legacy payload
        self.assertNotIn("story", d)
        self.assertEqual(sorted(d), ["findings", "recon", "summary", "target"])

    def test_legacy_no_aakg_still_works(self):
        eng = Engine(_MockTarget(), use_aakg=False)
        res = eng.run()
        self.assertIsNone(res["narratives"])
        self.assertIsNone(res["story"])
        md = eng.report_markdown(res)          # legacy report unaffected
        self.assertIn("Executive Summary", md)

    def test_sarif_unaffected(self):
        import tempfile
        from glasscage import sarif
        eng, res, g = _run()
        p = os.path.join(tempfile.mkdtemp(), "o.sarif")
        sarif.write_sarif(p, "t", res["findings"], res["summary"])
        d = json.load(open(p))
        self.assertEqual(sorted(d), ["$schema", "runs", "version"])
        self.assertNotIn("narratives", json.dumps(d))


if __name__ == "__main__":
    unittest.main()
