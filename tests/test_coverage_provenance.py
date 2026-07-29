import unittest

from glasscage import coverage_provenance as cp


class TestCoverageProvenance(unittest.TestCase):
    def test_runtime_ratio_is_honest(self):
        s = cp.summarize()
        # Runtime coverage must never exceed total and must match the counted set.
        self.assertEqual(s["runtime_coverage_ratio"],
                         round(len(s["runtime_tested"]) / s["universe"], 2))
        self.assertLessEqual(len(s["runtime_tested"]), s["universe"])

    def test_buckets_partition_universe(self):
        s = cp.summarize()
        total = (len(s["runtime_tested"]) + len(s["config_review_only"])
                 + len(s["questionnaire_only"]) + len(s["not_tested"]))
        self.assertEqual(total, s["universe"])

    def test_known_runtime_categories_present(self):
        rt = set(cp.summarize()["runtime_tested"])
        # These are runtime-tested (payload sent) in the current probe set.
        for cat in ("LLM01", "LLM02", "LLM07"):
            self.assertIn(cat, rt)


if __name__ == "__main__":
    unittest.main()
