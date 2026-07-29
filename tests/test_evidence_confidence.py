"""Evidence Confidence Classification: no claim may exceed its evidence.
Run: python -m unittest tests.test_evidence_confidence -q
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.evidence_confidence import EvidenceClass as EC, from_state, tag, legend
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage import schema

_TOOLS = schema.ingest({"functions": [{"name": "get_secret", "description": "vault", "parameters": {}}]})


class TestEvidenceClass(unittest.TestCase):
    def test_ordering_and_clamp(self):
        self.assertGreater(EC.DEMONSTRATED.rank, EC.HYPOTHESIZED.rank)
        self.assertGreater(EC.VERIFIED.rank, EC.MEASURED.rank)
        # a Measured claim clamped to an Estimated ceiling becomes Estimated
        self.assertEqual(EC.MEASURED.at_most(EC.ESTIMATED), EC.ESTIMATED)
        self.assertEqual(EC.HYPOTHESIZED.at_most(EC.VERIFIED), EC.HYPOTHESIZED)

    def test_state_mapping(self):
        self.assertEqual(from_state("demonstrated"), EC.DEMONSTRATED)
        self.assertEqual(from_state("hypothesized"), EC.HYPOTHESIZED)
        self.assertEqual(from_state("not_assessable"), EC.PENDING_EXTERNAL_VALIDATION)

    def test_all_eight_classes_defined(self):
        self.assertEqual(len(list(EC)), 8)


class TestReportEvidenceTagging(unittest.TestCase):
    def setUp(self):
        eng = Engine(ReferenceAgent(), schema_tools=_TOOLS)
        self.md = eng.report_markdown(eng.run())

    def test_posture_tagged_estimated_not_measured(self):
        self.assertIn("Indicative Risk Index", self.md)
        self.assertIn("[Estimated]", self.md)
        # posture must NOT be presented with statistical/measured language
        self.assertNotIn("interval [", self.md)
        self.assertNotIn("Posture Score", self.md)

    def test_legend_present(self):
        self.assertIn("Evidence classification", self.md)

    def test_evidence_ledger_verified(self):
        self.assertIn("[Verified]", self.md)

    def test_no_section_untagged(self):
        # each major section header carries a class or a per-item state tag
        for section in ("Trust Boundary", "Blast Radius", "Coverage"):
            self.assertIn(section, self.md)


if __name__ == "__main__":
    unittest.main()
