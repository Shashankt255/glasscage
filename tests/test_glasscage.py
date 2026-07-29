"""GLASSCAGE test suite. Run: python -m unittest discover -s tests -v"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage import graph, mcp, recon, scoring
from glasscage.engine import Engine
from glasscage.models import Status


class TestRecon(unittest.TestCase):
    def test_tool_surface_inline(self):
        r = recon.run_recon(_MockTarget())
        self.assertTrue(r.reachable)
        self.assertIn("search_tool", r.tool_surface)
        self.assertIn("send_email", r.tool_surface)


class TestProbes(unittest.TestCase):
    def setUp(self):
        self.results = Engine(_MockTarget()).run()
        self.by_probe = {f.probe_name: f for f in self.results["findings"]}

    def test_direct_injection_detected(self):
        self.assertEqual(self.by_probe["direct-injection-canary"].status, Status.VULNERABLE)

    def test_indirect_injection_detected(self):
        self.assertEqual(self.by_probe["indirect-injection-rag"].status, Status.VULNERABLE)

    def test_multiturn_erosion_detected(self):
        f = self.by_probe["multi-turn-erosion"]
        self.assertEqual(f.status, Status.VULNERABLE)
        self.assertTrue(len(f.turns) >= 1)

    def test_insecure_output_detected(self):
        self.assertEqual(self.by_probe["insecure-output-handling"].status, Status.VULNERABLE)

    def test_secret_disclosure_detected(self):
        self.assertEqual(self.by_probe["sensitive-info-disclosure"].status, Status.VULNERABLE)

    def test_remediation_present(self):
        for f in self.results["findings"]:
            if f.status in (Status.VULNERABLE, Status.INCONCLUSIVE):
                self.assertTrue(f.remediation, f"no remediation for {f.probe_name}")

    def test_verification_and_refs_present(self):
        for f in self.results["findings"]:
            self.assertTrue(f.verification_steps, f"no verification for {f.probe_name}")
            self.assertTrue(f.reference_links, f"no references for {f.probe_name}")
            for r in f.reference_links:
                self.assertTrue(r["url"].startswith("http"), f"bad url in {f.probe_name}")

    def test_atlas_precise_ids(self):
        by = {f.probe_name: f for f in self.results["findings"]}
        self.assertEqual(by["direct-injection-canary"].atlas_id, "AML.T0051.000")
        self.assertEqual(by["indirect-injection-rag"].atlas_id, "AML.T0051.001")
        self.assertEqual(by["system-prompt-leak"].atlas_id, "AML.T0056")
        self.assertEqual(by["sensitive-info-disclosure"].atlas_id, "AML.T0057")

    def test_new_probes_present(self):
        names = {f.probe_name for f in self.results["findings"]}
        for n in ("encoded-injection", "payload-splitting", "jailbreak-persona",
                  "multilingual-injection", "misinformation-false-premise",
                  "vector-rag-review", "supply-chain-review"):
            self.assertIn(n, names)

    def test_reproduction_and_evidence(self):
        for f in self.results["findings"]:
            if f.status in (Status.VULNERABLE, Status.INCONCLUSIVE):
                self.assertTrue(f.reproduction_steps, f"no repro for {f.probe_name}")
                self.assertTrue(f.evidence_svg.startswith("<svg"),
                                f"no evidence card for {f.probe_name}")


class TestRefusalAccuracy(unittest.TestCase):
    def test_named_canary_in_refusal_is_not_vulnerable(self):
        from glasscage.probes import canary_verdict, is_refusal
        from glasscage.models import Status
        self.assertTrue(is_refusal("I'm sorry, but I won't output GLSSCG-INJECT-OK"))
        status, _, _ = canary_verdict("GLSSCG-INJECT-OK",
                                      "I won't output GLSSCG-INJECT-OK")
        self.assertEqual(status, Status.INCONCLUSIVE)  # not a false-positive VULNERABLE
        status2, _, _ = canary_verdict("GLSSCG-INJECT-OK", "GLSSCG-INJECT-OK")
        self.assertEqual(status2, Status.VULNERABLE)


class TestEvidence(unittest.TestCase):
    def test_svg_has_indicator_and_dims(self):
        from glasscage import evidence
        from glasscage.models import Finding, Severity, Status
        f = Finding(probe_name="p", title="t", owasp_id="LLM01", category="c",
                    status=Status.VULNERABLE, severity=Severity.HIGH,
                    prompt="do it", response_excerpt="ok GLSSCG-INJECT-OK")
        svg = evidence.render_svg(f)
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("GLSSCG-INJECT-OK", svg)
        self.assertIn("width=\"960\"", svg)


class TestMCP(unittest.TestCase):
    def _load(self, name):
        path = os.path.join(os.path.dirname(__file__), "..", "samples", name)
        with open(path) as fh:
            return json.load(fh)

    def test_tool_poisoning_detected(self):
        findings = mcp.analyze_manifest(self._load("mcp_manifest.json"))
        titles = " ".join(f.title for f in findings)
        self.assertIn("poisoning", titles.lower())
        self.assertTrue(any(f.severity.value == "critical" for f in findings))

    def test_ssrf_detected(self):
        findings = mcp.analyze_manifest(self._load("mcp_manifest.json"))
        self.assertTrue(any("169.254.169.254" in f.title or "SSRF" in f.title
                            for f in findings))

    def test_rug_pull_detected(self):
        base = mcp.snapshot(self._load("mcp_manifest_baseline.json"))
        findings = mcp.detect_rug_pull(base, self._load("mcp_manifest.json"))
        self.assertTrue(any("rug pull" in f.title.lower() for f in findings))


class TestGraph(unittest.TestCase):
    def test_blast_radius_selfreport_zero(self):
        r = recon.run_recon(_MockTarget())  # self-reported only
        g = graph.build_graph(r)
        self.assertEqual(g["blast_radius_score"], 0)  # unverified tools don't count
        self.assertTrue(g["unverified_tools"])
        self.assertIn("graph LR", graph.to_mermaid(g))

    def test_blast_radius_schema_confirmed(self):
        from glasscage import schema
        r = recon.run_recon(_MockTarget())
        r.schema_tools = schema.ingest({"functions":[
            {"name":"run_sql","description":"execute sql","parameters":{}}]})
        g = graph.build_graph(r)
        self.assertGreater(g["blast_radius_score"], 0)


class TestScoringAndDiff(unittest.TestCase):
    def test_selfreport_does_not_inflate_blast(self):
        # self-reported tools alone must NOT raise blast radius (review fix)
        results = Engine(_MockTarget()).run()
        self.assertEqual(results["summary"]["blast_radius_multiplier"], 1.0)

    def test_schema_confirmed_inflates_blast(self):
        from glasscage import schema
        tools = schema.ingest({"functions":[
            {"name":"run_sql","description":"execute sql","parameters":{}},
            {"name":"send_email","description":"send","parameters":{}}]})
        results = Engine(_MockTarget(), schema_tools=tools).run()
        self.assertGreater(results["summary"]["blast_radius_multiplier"], 1.0)

    def test_diff_roundtrip(self):
        from glasscage.report import write_json
        from glasscage.diff import diff_reports
        results = Engine(_MockTarget()).run()
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.json")
            b = os.path.join(d, "b.json")
            write_json(a, "t", results["recon"], results["findings"], results["summary"])
            write_json(b, "t", results["recon"], results["findings"], results["summary"])
            out = diff_reports(a, b)
            self.assertEqual(out["verdict"], "NO CHANGE")


if __name__ == "__main__":
    unittest.main()


class TestReviewFixes(unittest.TestCase):
    def setUp(self):
        self.results = Engine(_MockTarget()).run()
        self.by = {f.probe_name: f for f in self.results["findings"]}

    def test_steerability_vs_impact(self):
        di = self.by["direct-injection-canary"]
        self.assertEqual(di.dimension, "steerability")
        self.assertFalse(di.impact_confirmed)
        sd = self.by["sensitive-info-disclosure"]
        self.assertEqual(sd.dimension, "impact")
        self.assertTrue(sd.impact_confirmed)

    def test_steerability_capped_below_impact(self):
        di = self.by["direct-injection-canary"]
        sd = self.by["sensitive-info-disclosure"]
        self.assertLess(di.cvss_score, sd.cvss_score)

    def test_cvss_vector_present(self):
        for f in self.results["findings"]:
            if f.status.value in ("vulnerable","inconclusive"):
                self.assertTrue(f.cvss_vector.startswith("GLSSCG:1.0/"))

    def test_coverage_states_gaps(self):
        cov = self.results["coverage"]
        self.assertIn("categories_not_tested", cov)
        self.assertIn("LLM04", cov["categories_not_tested"])

    def test_chain_of_custody(self):
        for f in self.results["findings"]:
            if f.raw_request or f.raw_response:
                self.assertEqual(len(f.evidence_hash), 64)
                self.assertTrue(f.timestamp)

    def test_summary_has_posture_and_caveat(self):
        s=self.results["summary"]
        self.assertIn("posture", s); self.assertIn("caveat", s)
        self.assertIn("risk_interval", s)


class TestAdaptiveAndSchema(unittest.TestCase):
    def test_adaptive_runs(self):
        results = Engine(_MockTarget(), adaptive=True).run()
        names = {f.probe_name for f in results["findings"]}
        self.assertIn("adaptive-attacker", names)

    def test_schema_ingest_classifies(self):
        from glasscage import schema
        t = schema.ingest({"functions":[{"name":"get_secret","description":"vault","parameters":{}}]})
        self.assertEqual(t[0]["capability"], "cred")
        self.assertTrue(t[0]["side_effect"])
        self.assertEqual(t[0]["provenance"], "schema-confirmed")


class TestAuditAndArchitecture(unittest.TestCase):
    def test_audit_chain_and_tamper(self):
        from glasscage import audit
        log = audit.AuditLog()
        log.record("u","p1","r1",True); log.record("u","p2","r2",True)
        self.assertTrue(log.verify())
        log.entries[0]["entry_hash"]="deadbeef"  # tamper
        self.assertFalse(log.verify())

    def test_scope_blocks_out_of_scope(self):
        from glasscage import audit
        sc=audit.Scope(["allowed.example"])
        sc.check("https://allowed.example/x")
        with self.assertRaises(PermissionError):
            sc.check("https://evil.example/x")

    def test_architecture_assessment(self):
        from glasscage import architecture
        from glasscage.models import Status
        fs=architecture.assess({"tool_least_privilege":"no","output_encoding":"yes"})
        miss=[f for f in fs if f.status is Status.VULNERABLE]
        self.assertTrue(any("tool_least_privilege" in f.prompt for f in miss))
        self.assertTrue(any(f.owasp_id=="LLM06" for f in miss))


class TestV1AttackChains(unittest.TestCase):
    def test_chains_built_from_findings(self):
        from glasscage import schema
        tools = schema.ingest({"functions":[
            {"name":"run_sql","description":"execute sql","parameters":{}},
            {"name":"get_secret","description":"vault","parameters":{}}]})
        results = Engine(_MockTarget(), schema_tools=tools).run()
        chains = results["chains"]
        self.assertTrue(chains, "expected at least one exploit chain")
        c = chains[0]
        self.assertIn("likelihood", c)
        self.assertIn("links", c)
        self.assertTrue(c["narrative"])


class TestV1Posture(unittest.TestCase):
    def setUp(self):
        self.results = Engine(_MockTarget()).run()
        self.p = self.results["posture"]

    def test_posture_range(self):
        self.assertTrue(0 <= self.p["posture_score"] <= 100)
        self.assertTrue(0 <= self.p["risk_index"] <= 100)
        self.assertEqual(round(self.p["posture_score"] + self.p["risk_index"], 1), 100.0)

    def test_factors_and_weights(self):
        self.assertEqual(set(self.p["factors"]), set(self.p["weights"]))
        self.assertAlmostEqual(sum(self.p["weights"].values()), 1.0, places=2)

    def test_interval(self):
        # P0-4: the pseudo confidence interval was removed. It must be None and the
        # score relabeled as an uncalibrated Indicative Risk Index (Estimated).
        self.assertIsNone(self.p["risk_interval"])
        self.assertEqual(self.p["label"], "Indicative Risk Index")
        self.assertEqual(self.p["evidence_class"], "Estimated")


class TestV1Trust(unittest.TestCase):
    def test_violation_when_control_missing(self):
        from glasscage import trust, schema
        from glasscage.models import ReconResult
        r = ReconResult(reachable=True)
        r.schema_tools = schema.ingest({"functions":[{"name":"get_secret","description":"vault","parameters":{}}]})
        model = trust.build(r, None, {"secrets_out_of_context":"no"})
        self.assertTrue(model["violations"])
        self.assertIn("Secrets", model["reachable_trusted_assets"])

    def test_no_violation_when_control_present(self):
        from glasscage import trust, schema
        from glasscage.models import ReconResult
        r = ReconResult(reachable=True)
        r.schema_tools = schema.ingest({"functions":[{"name":"get_secret","description":"vault","parameters":{}}]})
        model = trust.build(r, None, {"secrets_out_of_context":"yes"})
        self.assertFalse(model["violations"])


class TestV1Genetic(unittest.TestCase):
    def test_genetic_runs_and_is_reproducible(self):
        from glasscage import genetic
        f1 = genetic.GeneticAttacker(seed=42, budget=20).run(_MockTarget())
        f2 = genetic.GeneticAttacker(seed=42, budget=20).run(_MockTarget())
        self.assertEqual(f1.probe_name, "genetic-attacker")
        self.assertEqual(f1.status, f2.status)  # deterministic with same seed


class TestV1AgentProbes(unittest.TestCase):
    def test_agent_probes_registered(self):
        from glasscage import probes
        names = {p.name for p in probes.all_probes()}
        for n in ("planner-manipulation","memory-poisoning","goal-hijack",
                  "tool-routing-manipulation","loop-amplification","context-window-exhaustion"):
            self.assertIn(n, names)

    def test_agent_probe_dimension_preserved(self):
        from glasscage import probes
        by={p.name:p for p in probes.all_probes()}
        self.assertEqual(by["planner-manipulation"].dimension, "steerability")


class TestV1Sarif(unittest.TestCase):
    def test_sarif_shape(self):
        from glasscage import sarif
        results = Engine(_MockTarget()).run()
        doc = sarif.to_sarif("demo", results["findings"], results["summary"])
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["tool"]["driver"]["rules"])
        self.assertTrue(doc["runs"][0]["results"])

    def test_replay_omits_headers(self):
        from glasscage import sarif
        results = Engine(_MockTarget()).run()
        rp = sarif.to_replay("demo", {"url":"x","headers":{"Authorization":"secret"}},
                             results["findings"])
        self.assertNotIn("headers", rp["target_config"])
        self.assertTrue(rp["steps"])
