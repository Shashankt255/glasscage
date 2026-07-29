"""Stage D tests: external adapter normalization, taxonomy crosswalk, validation.
Run: python -m unittest tests.test_stage_d -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cli import _MockTarget
from glasscage.refagent import ReferenceAgent

FX = os.path.join(os.path.dirname(__file__), "..", "glasscage", "adapters", "fixtures")


# ---------------- D1: taxonomy crosswalk ----------------
class TestTaxonomy(unittest.TestCase):
    def test_full_crosswalk_fields(self):
        from glasscage import taxonomy
        x = taxonomy.enrich("LLM01")
        for k in ("atlas", "cwe", "capec", "nist"):
            self.assertTrue(x[k], f"missing {k} for LLM01")

    def test_classify_maps_external_rules(self):
        from glasscage import taxonomy
        self.assertEqual(taxonomy.classify("dan.Dan_11_0"), "LLM01")
        self.assertEqual(taxonomy.classify("pii:direct"), "LLM02")
        self.assertEqual(taxonomy.classify("ssrf-tool"), "MCP07")

    def test_enrich_all_fills_native_findings(self):
        from glasscage import taxonomy
        from glasscage.models import Finding, Severity, Status
        f = Finding(probe_name="p", title="t", owasp_id="LLM02", category="c",
                    status=Status.VULNERABLE, severity=Severity.HIGH)
        taxonomy.enrich_all([f])
        self.assertEqual(f.cwe_id, "CWE-200")
        self.assertTrue(f.capec_id and f.nist_id)


# ---------------- D1: adapter parsers ----------------
class TestAdapterParsers(unittest.TestCase):
    def _parse(self, tool, fn):
        from glasscage.adapters import external as e
        parser = {"garak": e.parse_garak, "promptfoo": e.parse_promptfoo,
                  "pyrit": e.parse_pyrit, "deepteam": e.parse_deepteam,
                  "fuzzyai": e.parse_fuzzyai}[tool]
        return parser(os.path.join(FX, fn))

    def test_garak_parser(self):
        fs = self._parse("garak", "garak.report.jsonl")
        self.assertEqual(len(fs), 2)  # 2 hits above threshold, 1 below excluded
        f = fs[0]
        self.assertEqual(f.source_framework, "garak")
        self.assertTrue(f.source_rule_id)
        self.assertTrue(f.cwe_id and f.capec_id and f.nist_id)
        self.assertTrue(f.raw_output)

    def test_all_parsers_normalize(self):
        for tool, fn in [("garak", "garak.report.jsonl"), ("promptfoo", "promptfoo.json"),
                         ("pyrit", "pyrit.json"), ("deepteam", "deepteam.json"),
                         ("fuzzyai", "fuzzyai.json")]:
            fs = self._parse(tool, fn)
            self.assertTrue(fs, f"{tool} produced no findings")
            for f in fs:
                self.assertEqual(f.source_framework, tool)
                self.assertTrue(f.owasp_id)
                self.assertTrue(f.timestamp is not None)

    def test_garak_excludes_subthreshold(self):
        # the leakreplay attempt scored 0.1 -> must NOT be a finding
        fs = self._parse("garak", "garak.report.jsonl")
        self.assertFalse(any("leakreplay" in f.source_rule_id for f in fs))


# ---------------- D1: adapter run() honesty ----------------
class TestAdapterHonesty(unittest.TestCase):
    def test_from_file_path(self):
        from glasscage.adapters import GarakAdapter
        res = GarakAdapter().run(_MockTarget(),
                                 {"from_file": os.path.join(FX, "garak.report.jsonl")})
        self.assertTrue(res.available)
        self.assertEqual(len(res.findings), 2)

    def test_not_tested_when_absent(self):
        from glasscage.adapters import PyRITAdapter
        res = PyRITAdapter().run(_MockTarget())   # not installed, no file
        self.assertFalse(res.available)
        self.assertIn("Not Tested", res.error)
        self.assertEqual(res.findings, [])       # never fabricated


# ---------------- D4: validation harness ----------------
class TestValidation(unittest.TestCase):
    def test_cross_framework_and_not_tested(self):
        from glasscage import validation
        v = validation.validate(
            ReferenceAgent(), ["native", "fake", "garak", "pyrit"],
            adapter_files={"garak": os.path.join(FX, "garak.report.jsonl")})
        runs = {r["tool"]: r for r in v["runs"]}
        self.assertEqual(runs["native"]["mode"], "live")
        self.assertEqual(runs["garak"]["mode"], "from_file")
        self.assertEqual(runs["pyrit"]["mode"], "not_tested")
        self.assertIn("pyrit", v["not_tested"])
        self.assertEqual(v["native_reproducibility"]["category_agreement"], 1.0)

    def test_paper_report_generation(self):
        from glasscage import benchmark, validation
        bench = benchmark.run_corpus(os.path.join(os.path.dirname(__file__), "..",
                                                  "benchmark", "corpus.json"))
        v = validation.validate(ReferenceAgent(), ["native", "fake"])
        md = validation.paper_report(bench, v)
        self.assertIn("Validation Report", md)
        self.assertIn("Wilson", md)
        self.assertIn("Not Tested", md or "")

    def test_no_synthetic_data_for_unavailable(self):
        # unavailable tools must contribute zero findings to the union
        from glasscage import validation
        v = validation.validate(ReferenceAgent(), ["native", "deepteam", "fuzzyai"])
        for r in v["runs"]:
            if r["tool"] in ("deepteam", "fuzzyai"):
                self.assertEqual(r["detections"], 0)
                self.assertEqual(r["mode"], "not_tested")


# ---------------- Backward compatibility ----------------
class TestStageDCompat(unittest.TestCase):
    def test_engine_findings_carry_full_taxonomy(self):
        from glasscage.engine import Engine
        res = Engine(ReferenceAgent()).run()
        vulns = [f for f in res["findings"] if f.status.value == "vulnerable"]
        self.assertTrue(vulns)
        # native findings now carry CWE/CAPEC/NIST via enrich_all
        self.assertTrue(any(f.cwe_id for f in vulns))
        self.assertTrue = any(f.nist_id for f in vulns)


if __name__ == "__main__":
    unittest.main()
