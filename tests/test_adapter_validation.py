"""P0-5: adapter validation is honest and never fabricates.
Run: python -m unittest tests.test_adapter_validation -q
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import adapter_validation as av

FX = os.path.join(os.path.dirname(__file__), "..", "glasscage", "adapters", "fixtures")


class TestAdapterValidation(unittest.TestCase):
    def test_default_is_pending_not_measured(self):
        rep = av.validate_adapters()   # no genuine outputs
        self.assertEqual(rep["summary"]["genuine"], 0)   # nothing genuine-validated
        for r in rep["results"]:
            self.assertNotEqual(r["evidence_class"], "Measured")   # never fabricated
            self.assertIn(r["evidence_class"], ("Experimental", "Pending External Validation"))

    def test_all_five_frameworks_present(self):
        names = {r["framework"] for r in av.validate_adapters()["results"]}
        self.assertEqual(names, {"garak", "promptfoo", "pyrit", "deepteam", "fuzzyai"})

    def test_supplying_output_marks_genuine_measured(self):
        # Mechanism test: an operator-supplied path is treated as genuine -> Measured.
        # (In real use this must be REAL tool output; here we exercise the code path.)
        rep = av.validate_adapters({"garak": os.path.join(FX, "garak.report.jsonl")})
        garak = next(r for r in rep["results"] if r["framework"] == "garak")
        self.assertEqual(garak["level"], "genuine")
        self.assertEqual(garak["evidence_class"], "Measured")
        self.assertGreater(garak["parsed_findings"], 0)

    def test_fixture_is_experimental_not_validation(self):
        rep = av.validate_adapters()
        promptfoo = next(r for r in rep["results"] if r["framework"] == "promptfoo")
        self.assertEqual(promptfoo["level"], "fixture")
        self.assertIn("Pending External Validation", rep["note"])


if __name__ == "__main__":
    unittest.main()
