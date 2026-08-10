# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Audit-log append semantics (ADR 0020, PR #21).

`--audit-log` is documented as append-only, but `AuditLog.__init__` started every chain at
genesis and never read the file. Two runs to one path therefore wrote two chains into one
file, and the verifier added in ADR 0019 reported the result as tampered at the first entry
of the second run - the integrity control accusing a correctly-used custody log.

A log file is now one chain. Opening an existing one verifies it under the ADR 0019 v2
rules and resumes from its head; a tampered or legacy file is refused rather than extended,
because appending to it would grow a chain that cannot be vouched for.

Two properties carry the weight here:

  * refusal must write nothing - a refused run may not leave a partial entry behind;
  * resuming inherits ADR 0019's accepted limitation unchanged. Verification proves the
    entries present are internally consistent, not that none were removed.

Run: python -m unittest tests.test_audit_append -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import (AuditLog, ChainStatus, canonical_entry, check_entries,
                             sha256, verify_file)
from glasscage.errors import ConfigError, GlasscageError

_URL = "https://bot.example/chat"


def _run(path, n=2, start=1):
    """One 'run' against a log path: open, record n entries, return the log."""
    a = AuditLog(path)
    for i in range(start, start + n):
        a.record(_URL, f"p{i}", f"r{i}", True)
    return a


def _v1_entry():
    """A pre-ADR-0019 entry, built with the formula v1 used."""
    prev, ts = "0" * 64, "2026-01-01T00:00:00+00:00"
    return {"ts": ts, "url": _URL, "prompt_sha256": sha256("p1"),
            "response_sha256": sha256("r1"), "ok": True, "prev": prev,
            "entry_hash": sha256(prev, ts, _URL, "p1", "r1")}


def _write(path, entries):
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


# ---------------- resume ----------------
class TestResume(unittest.TestCase):
    def test_two_runs_to_one_path_verify(self):
        """The defect: this reported `tampered` at entry N of run two."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _run(p, 2, 1)
            _run(p, 1, 3)
            self.assertIs(verify_file(p).status, ChainStatus.VERIFIED)

    def test_three_runs_verify(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            for start in (1, 3, 5):
                _run(p, 2, start)
            r = verify_file(p)
            self.assertIs(r.status, ChainStatus.VERIFIED)
            self.assertEqual(r.entries, 6)

    def test_first_new_entry_links_to_the_previous_head(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            first = _run(p, 2, 1)
            head = first.entries[-1]["entry_hash"]
            prior = len(first.entries)
            second = _run(p, 1, 3)
            # prior entries are loaded, so the first NEW entry sits at index `prior`
            self.assertEqual(second.entries[prior]["prev"], head)

    def test_prior_entries_are_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _run(p, 2, 1)
            second = _run(p, 1, 3)
            self.assertEqual(len(second.entries), 3)
            self.assertIs(second.check().status, ChainStatus.VERIFIED)

    def test_line_count_grows_by_the_new_entries_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _run(p, 2, 1)
            _run(p, 3, 3)
            self.assertEqual(sum(1 for _ in open(p, encoding="utf-8")), 5)

    def test_head_advances_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _run(p, 1, 1)
            head1 = verify_file(p).head
            _run(p, 1, 2)
            self.assertNotEqual(verify_file(p).head, head1)


# ---------------- genesis ----------------
class TestGenesisCases(unittest.TestCase):
    _GENESIS = "0" * 64

    def test_path_none_starts_at_genesis(self):
        self.assertEqual(AuditLog(None).prev, self._GENESIS)

    def test_nonexistent_path_starts_at_genesis(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(AuditLog(os.path.join(d, "new.jsonl")).prev, self._GENESIS)

    def test_empty_file_starts_at_genesis(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "e.jsonl")
            open(p, "w").close()
            a = AuditLog(p)
            self.assertEqual(a.prev, self._GENESIS)
            self.assertEqual(a.entries, [])

    def test_blank_lines_only_starts_at_genesis(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.jsonl")
            open(p, "w", encoding="utf-8").write("\n\n\n")
            self.assertEqual(AuditLog(p).prev, self._GENESIS)

    def test_a_fresh_path_still_produces_a_verifiable_chain(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "fresh.jsonl")
            _run(p, 3, 1)
            self.assertIs(verify_file(p).status, ChainStatus.VERIFIED)


# ---------------- refusal ----------------
class TestRefusal(unittest.TestCase):
    def _tampered_log(self, d):
        p = os.path.join(d, "t.jsonl")
        _run(p, 1, 1)
        e = json.loads(open(p, encoding="utf-8").read().strip())
        e["url"] = "https://attacker.example"
        _write(p, [e])
        return p

    def test_tampered_log_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError) as ctx:
                AuditLog(self._tampered_log(d))
        self.assertIn("does not verify", str(ctx.exception))

    def test_legacy_log_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v1.jsonl")
            _write(p, [_v1_entry()])
            with self.assertRaises(ConfigError) as ctx:
                AuditLog(p)
        self.assertIn("predates the integrity format", str(ctx.exception))

    def test_refusal_names_the_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._tampered_log(d)
            with self.assertRaises(ConfigError) as ctx:
                AuditLog(p)
        self.assertIn(os.path.basename(p), str(ctx.exception))

    def test_refusal_writes_nothing(self):
        """A refused run may not leave a partial entry behind."""
        with tempfile.TemporaryDirectory() as d:
            p = self._tampered_log(d)
            before = open(p, "rb").read()
            with self.assertRaises(ConfigError):
                AuditLog(p)
            self.assertEqual(open(p, "rb").read(), before)

    def test_legacy_refusal_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v1.jsonl")
            _write(p, [_v1_entry()])
            before = open(p, "rb").read()
            with self.assertRaises(ConfigError):
                AuditLog(p)
            self.assertEqual(open(p, "rb").read(), before)

    def test_refusal_is_a_glasscage_error(self):
        """So the CLI's existing handler turns it into `error: ...` and exit 2."""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(GlasscageError):
                AuditLog(self._tampered_log(d))

    def test_no_recovery_mechanism_is_offered(self):
        """ADR 0020: refuse and name the path. Nothing rotates, migrates or repairs."""
        with tempfile.TemporaryDirectory() as d:
            p = self._tampered_log(d)
            names_before = sorted(os.listdir(d))
            with self.assertRaises(ConfigError):
                AuditLog(p)
            self.assertEqual(sorted(os.listdir(d)), names_before)


# ---------------- F2: non-object JSONL lines ----------------
class TestNonObjectLines(unittest.TestCase):
    def _file(self, d, body):
        p = os.path.join(d, "x.jsonl")
        open(p, "w", encoding="utf-8").write(body)
        return p

    def test_json_array_line_is_tampered_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            r = verify_file(self._file(d, "[1,2,3]\n"))
            self.assertIs(r.status, ChainStatus.TAMPERED)
            self.assertIn("not a JSON object", r.detail)

    def test_bare_string_and_number_lines(self):
        for body in ('"hello"\n', "42\n", "true\n", "null\n"):
            with self.subTest(body=body.strip()):
                with tempfile.TemporaryDirectory() as d:
                    self.assertIs(verify_file(self._file(d, body)).status,
                                  ChainStatus.TAMPERED)

    def test_check_entries_handles_a_non_object_directly(self):
        r = check_entries([[1, 2, 3]])
        self.assertIs(r.status, ChainStatus.TAMPERED)

    def test_unparseable_line_still_reported_as_before(self):
        with tempfile.TemporaryDirectory() as d:
            r = verify_file(self._file(d, "{not json\n"))
            self.assertIs(r.status, ChainStatus.TAMPERED)
            self.assertIn("not valid JSON", r.detail)


# ---------------- preserved ADR 0019 contracts ----------------
class TestAdr0019Preserved(unittest.TestCase):
    def _chain(self):
        a = AuditLog(None)
        a.record(_URL, "p1", "r1", True)
        a.record(_URL, "p2", "r2", True)
        a.record(_URL, "p3", "r3", False)
        return a

    def test_all_tamper_cases_still_detected(self):
        for idx, field, val in ((1, "url", "https://attacker.example"),
                                (1, "ts", "1999-01-01T00:00:00+00:00"),
                                (1, "prompt_sha256", sha256("other")),
                                (1, "response_sha256", sha256("other")),
                                (2, "ok", True),
                                (1, "entry_hash", sha256("forged")),
                                (1, "prev", sha256("forged"))):
            with self.subTest(field=field):
                a = self._chain()
                a.entries[idx][field] = val
                self.assertIs(a.check().status, ChainStatus.TAMPERED)

    def test_deleted_middle_entry_still_detected(self):
        a = self._chain()
        del a.entries[1]
        self.assertIs(a.check().status, ChainStatus.TAMPERED)

    def test_truncation_is_still_an_accepted_limitation(self):
        """ADR 0019 s8, unchanged by resume: verification proves the entries present are
        consistent, not that none were removed."""
        a = self._chain()
        a.entries = a.entries[:2]
        self.assertIs(a.check().status, ChainStatus.VERIFIED)

    def test_truncated_file_still_verifies_after_resume(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            _run(p, 3, 1)
            lines = open(p, encoding="utf-8").read().splitlines()
            _write(p, [json.loads(x) for x in lines[:2]])
            self.assertIs(verify_file(p).status, ChainStatus.VERIFIED)

    def test_verify_keeps_its_bool_contract(self):
        self.assertIsInstance(self._chain().verify(), bool)
        self.assertTrue(self._chain().verify())

    def test_legacy_still_reported_legacy_by_check_entries(self):
        self.assertIs(check_entries([_v1_entry()]).status,
                      ChainStatus.LEGACY_UNVERIFIABLE)

    def test_entry_shape_and_canonical_form_unchanged(self):
        a = AuditLog(None)
        a.record(_URL, "p", "r", True)
        self.assertEqual(sorted(a.entries[0]),
                         ["entry_hash", "ok", "prev", "prompt_sha256",
                          "response_sha256", "ts", "url", "v"])
        self.assertIn("4:true", canonical_entry(a.entries[0]))

    def test_no_raw_payload_persisted_across_resume(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            a = AuditLog(p)
            a.record(_URL, "CANARY-PROMPT-9f2c", "CANARY-RESPONSE-4a71", True)
            b = AuditLog(p)
            b.record(_URL, "CANARY-PROMPT-2nd", "CANARY-RESPONSE-2nd", True)
            blob = open(p, encoding="utf-8").read()
            for canary in ("CANARY-PROMPT-9f2c", "CANARY-RESPONSE-4a71",
                           "CANARY-PROMPT-2nd", "CANARY-RESPONSE-2nd"):
                self.assertNotIn(canary, blob)

    def test_sha256_helper_unchanged(self):
        self.assertEqual(
            sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(sha256("a", "b"), sha256("ab"))


if __name__ == "__main__":
    unittest.main()
