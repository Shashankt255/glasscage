# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Tests for the CBH chain reference loader (chain_reference.py)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import chain_reference


class TestChainReference(unittest.TestCase):

    def test_chains_for_llm01_returns_ssrf_and_rce(self):
        chains = chain_reference.chains_for("LLM01")
        classes = {c["vuln_class"] for c in chains}
        self.assertIn("ssrf", classes)
        self.assertIn("rce", classes)

    def test_chains_for_llm06_returns_idor(self):
        chains = chain_reference.chains_for("LLM06")
        classes = {c["vuln_class"] for c in chains}
        self.assertIn("idor", classes)

    def test_chains_for_unknown_returns_empty(self):
        self.assertEqual(chain_reference.chains_for("LLM99"), [])

    def test_chain_has_required_fields(self):
        chains = chain_reference.chains_for("LLM01")
        self.assertTrue(len(chains) > 0)
        for c in chains:
            self.assertIn("vuln_class", c)
            self.assertIn("ai_chain", c)
            self.assertIn("pattern_count", c)
            self.assertIn("report_count", c)

    def test_severity_reference_loads(self):
        ref = chain_reference.severity_reference()
        self.assertGreater(len(ref), 50)
        for entry in ref:
            self.assertIn(entry["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_severity_for_finding_exact(self):
        sev = chain_reference.severity_for_finding("/.git/config reachable on prod webapp")
        self.assertEqual(sev, "CRITICAL")

    def test_severity_for_finding_no_match(self):
        self.assertIsNone(chain_reference.severity_for_finding("completely unknown finding xyz"))

    def test_severity_for_finding_substring(self):
        sev = chain_reference.severity_for_finding("Found open Redis (no AUTH) on port 6379")
        self.assertEqual(sev, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
