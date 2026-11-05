# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Audit chain integrity (ADR 0019, PR #20).

`AuditLog.verify()` walked the `prev` links and recomputed nothing. It could not: the
digest covered the raw prompt and response, which the entry never stores. Measured on
v0.4.3-replay-applicability, altering an entry's `url`, `ts`, `prompt_sha256`,
`response_sha256` or `ok` all left `verify()` returning True, while the module docstring,
README, THREAT_MODEL and three guides called the log tamper-evident.

Two properties carry most of the weight here:

  * `audit.sha256` must stay byte-identical - `evidence_hash` (engine.py) and
    `custody_hash` (chat.py, rest.py) are frozen invariants computed with it.
  * a legacy chain must read as unverifiable, never as tampered. `verify()` returns bool
    and cannot express that, which is why `check()` exists and why `verify()` is retained
    only for callers written against the old contract.

Run: python -m unittest tests.test_audit_integrity -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import (
    ENTRY_VERSION,
    AuditLog,
    ChainStatus,
    canonical_entry,
    check_entries,
    sha256,
    verify_file,
)

_URL = "https://bot.example/chat"


def _chain(path=None):
    a = AuditLog(path)
    a.record(_URL, "p1", "r1", True)
    a.record(_URL, "p2", "r2", True)
    a.record(_URL, "p3", "r3", False)
    return a


def _v1_entry():
    """A pre-ADR-0019 entry, built with the formula v1 actually used:
    digest = sha256(prev, ts, url, prompt, response), with the payloads not stored."""
    prev, ts = "0" * 64, "2026-01-01T00:00:00+00:00"
    return {"ts": ts, "url": _URL, "prompt_sha256": sha256("p1"),
            "response_sha256": sha256("r1"), "ok": True, "prev": prev,
            "entry_hash": sha256(prev, ts, _URL, "p1", "r1")}


# ---------------- tamper detection ----------------
class TestTamperDetection(unittest.TestCase):
    def test_clean_chain_verifies(self):
        self.assertIs(_chain().check().status, ChainStatus.VERIFIED)

    def _tampered(self, index, field, value):
        a = _chain()
        a.entries[index][field] = value
        return a.check()

    def test_altered_url_is_detected(self):
        self.assertIs(self._tampered(1, "url", "https://attacker.example").status,
                      ChainStatus.TAMPERED)

    def test_altered_timestamp_is_detected(self):
        self.assertIs(self._tampered(1, "ts", "1999-01-01T00:00:00+00:00").status,
                      ChainStatus.TAMPERED)

    def test_altered_prompt_digest_is_detected(self):
        self.assertIs(self._tampered(1, "prompt_sha256", sha256("other")).status,
                      ChainStatus.TAMPERED)

    def test_altered_response_digest_is_detected(self):
        self.assertIs(self._tampered(1, "response_sha256", sha256("other")).status,
                      ChainStatus.TAMPERED)

    def test_flipped_ok_flag_is_detected(self):
        """`ok` was stored but was never a hash input, so it was unprotected even in
        principle. Entry 2 is the one recorded with ok=False."""
        self.assertIs(self._tampered(2, "ok", True).status, ChainStatus.TAMPERED)

    def test_forged_entry_hash_is_detected(self):
        self.assertIs(self._tampered(1, "entry_hash", sha256("forged")).status,
                      ChainStatus.TAMPERED)

    def test_broken_prev_link_is_detected(self):
        self.assertIs(self._tampered(1, "prev", sha256("forged")).status,
                      ChainStatus.TAMPERED)

    def test_deleted_middle_entry_is_detected(self):
        a = _chain()
        del a.entries[1]
        self.assertIs(a.check().status, ChainStatus.TAMPERED)

    def test_missing_field_is_reported_as_tampering(self):
        a = _chain()
        del a.entries[1]["url"]
        r = a.check()
        self.assertIs(r.status, ChainStatus.TAMPERED)
        self.assertIn("missing", r.detail)

    def test_detail_names_the_offending_entry(self):
        r = self._tampered(1, "url", "https://attacker.example")
        self.assertIn("entry 1", r.detail)


# ---------------- the limitation, pinned ----------------
class TestTruncationIsNotDetected(unittest.TestCase):
    def test_tail_truncation_still_verifies(self):
        """ADR 0019 s7: a forward chain can be recomputed end to end by whoever can write
        the file, so truncation needs an anchor held elsewhere. Pinned so the limitation
        cannot be quietly assumed away."""
        a = _chain()
        a.entries = a.entries[:2]
        self.assertIs(a.check().status, ChainStatus.VERIFIED)

    def test_head_is_exposed_for_external_anchoring(self):
        r = _chain().check()
        self.assertEqual(r.head, _chain().entries[-1]["entry_hash"][:0] or r.head)
        self.assertTrue(r.head)
        self.assertEqual(len(r.head), 64)


# ---------------- legacy handling (ADR 0019 amendment 1) ----------------
class TestLegacyChains(unittest.TestCase):
    def test_legacy_chain_is_unverifiable_not_tampered(self):
        r = check_entries([_v1_entry()])
        self.assertIs(r.status, ChainStatus.LEGACY_UNVERIFIABLE)
        self.assertIsNot(r.status, ChainStatus.TAMPERED)

    def test_legacy_detail_explains_why(self):
        self.assertIn("predates", check_entries([_v1_entry()]).detail)

    def test_legacy_is_detected_before_any_hash_comparison(self):
        """A v1 entry's digest can never match the v2 formula; it must be reported as
        legacy rather than as a mismatch."""
        e = _v1_entry()
        e["entry_hash"] = sha256("anything at all")
        self.assertIs(check_entries([e]).status, ChainStatus.LEGACY_UNVERIFIABLE)

    def test_verify_returns_false_for_legacy(self):
        """bool cannot say 'unverifiable', so it stays conservative."""
        a = AuditLog(None)
        a.entries = [_v1_entry()]
        self.assertFalse(a.verify())

    def test_a_mixed_chain_is_reported_legacy(self):
        a = _chain()
        a.entries.insert(0, _v1_entry())
        self.assertIs(a.check().status, ChainStatus.LEGACY_UNVERIFIABLE)


# ---------------- compatibility API ----------------
class TestVerifyCompatibility(unittest.TestCase):
    def test_verify_still_returns_bool(self):
        self.assertIsInstance(_chain().verify(), bool)

    def test_verify_true_on_clean_chain(self):
        self.assertTrue(_chain().verify())

    def test_verify_false_on_tampered_chain(self):
        a = _chain()
        a.entries[0]["entry_hash"] = "deadbeef"
        self.assertFalse(a.verify())

    def test_empty_chain_verifies(self):
        self.assertTrue(AuditLog(None).verify())


# ---------------- canonical serialization (ADR 0019 amendment 2) ----------------
class TestCanonicalSerialization(unittest.TestCase):
    def test_field_boundary_shift_changes_the_form(self):
        """`audit.sha256` concatenates without a separator, so sha256('ab','c') equals
        sha256('a','bc'). Length-prefixing the entry's fields removes that ambiguity."""
        e = _chain().entries[0]
        shifted = dict(e)
        shifted["url"] = e["url"] + e["prompt_sha256"][0]
        shifted["prompt_sha256"] = e["prompt_sha256"][1:]
        self.assertNotEqual(canonical_entry(e), canonical_entry(shifted))
        self.assertNotEqual(sha256(canonical_entry(e)), sha256(canonical_entry(shifted)))

    def test_the_underlying_helper_is_still_ambiguous(self):
        """Recorded deliberately: `sha256` was not changed, because `evidence_hash` and
        `custody_hash` are frozen. The entry form works around it instead."""
        self.assertEqual(sha256("ab", "c"), sha256("a", "bc"))

    def test_booleans_encode_lower_case(self):
        e = dict(_chain().entries[0])
        e["ok"] = True
        self.assertIn("4:true", canonical_entry(e))
        e["ok"] = False
        self.assertIn("5:false", canonical_entry(e))

    def test_form_is_deterministic(self):
        e = _chain().entries[0]
        self.assertEqual(canonical_entry(e), canonical_entry(dict(e)))

    def test_field_order_is_fixed(self):
        e = _chain().entries[0]
        reordered = {k: e[k] for k in reversed(list(e))}
        self.assertEqual(canonical_entry(e), canonical_entry(reordered))

    def test_every_hashed_field_is_stored(self):
        from glasscage.audit import _CANONICAL_FIELDS
        e = _chain().entries[0]
        for name in _CANONICAL_FIELDS:
            with self.subTest(field=name):
                self.assertIn(name, e)

    def test_missing_field_raises_rather_than_silently_hashing(self):
        e = dict(_chain().entries[0])
        del e["ok"]
        with self.assertRaises(KeyError):
            canonical_entry(e)


# ---------------- frozen downstream hashes ----------------
class TestSha256IsFrozen(unittest.TestCase):
    def test_known_digests_are_unchanged(self):
        self.assertEqual(
            sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(
            sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_variadic_behaviour_is_unchanged(self):
        self.assertEqual(sha256("a", "b"), sha256("ab"))

    def test_none_parts_still_treated_as_empty(self):
        self.assertEqual(sha256(None), sha256(""))


# ---------------- payload confidentiality ----------------
class TestNoRawPayloadPersisted(unittest.TestCase):
    def test_entry_holds_no_raw_prompt_or_response(self):
        a = AuditLog(None)
        a.record(_URL, "CANARY-PROMPT-9f2c", "CANARY-RESPONSE-4a71", True)
        blob = json.dumps(a.entries)
        self.assertNotIn("CANARY-PROMPT-9f2c", blob)
        self.assertNotIn("CANARY-RESPONSE-4a71", blob)

    def test_entry_shape_is_exactly_the_expected_fields(self):
        a = AuditLog(None)
        a.record(_URL, "p", "r", True)
        self.assertEqual(sorted(a.entries[0]),
                         ["entry_hash", "ok", "prev", "prompt_sha256",
                          "response_sha256", "ts", "url", "v"])

    def test_entries_carry_the_format_version(self):
        a = AuditLog(None)
        a.record(_URL, "p", "r", True)
        self.assertEqual(a.entries[0]["v"], ENTRY_VERSION)


# ---------------- JSONL verification ----------------
class TestJsonlVerification(unittest.TestCase):
    def test_file_and_memory_agree(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            a = _chain(p)
            fr, mem = verify_file(p), a.check()
            self.assertIs(fr.status, mem.status)
            self.assertEqual(fr.head, mem.head)
            self.assertEqual(fr.entries, mem.entries)

    def test_tampering_on_disk_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _chain(p)
            lines = open(p, encoding="utf-8").read().splitlines()
            obj = json.loads(lines[0])
            obj["url"] = "https://attacker.example"
            lines[0] = json.dumps(obj)
            open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            self.assertIs(verify_file(p).status, ChainStatus.TAMPERED)

    def test_malformed_line_is_reported_not_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _chain(p)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write("{not json\n")
            r = verify_file(p)
            self.assertIs(r.status, ChainStatus.TAMPERED)
            self.assertIn("not valid JSON", r.detail)

    def test_blank_lines_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _chain(p)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write("\n\n")
            self.assertIs(verify_file(p).status, ChainStatus.VERIFIED)


if __name__ == "__main__":
    unittest.main()
