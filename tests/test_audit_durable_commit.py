# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Durable-before-visible audit commit (ADR 0024, PR #25).

`AuditLog.record()` advanced `self.prev` and appended to `self.entries` before writing the
line. A failed write therefore left the in-memory chain pointing at an entry that was never
persisted, and the next successful record chained from that unpersisted hash - writing a
gap into the file.

Measured on `v0.4.8-transport-custody-exception`:

    unit    : one failed write -> in-memory 2, on-disk 1, prev != disk head
    unit    : failure then success -> on-disk chain `tampered`,
              "entry 1 does not link to its predecessor"
    CLI     : intermittent write fault -> 21 exchanges, 19 entries on disk,
              ON-DISK CHAIN `tampered`, CLI reported `verified (21 entries)`, exit 0
    ADR 0020: that file can then never be appended to again (ConfigError)

The integrity control was accusing a file the tool itself had gapped - the same class of
harm PR #21 corrected, reintroduced by a different mechanism.

INV-25: for a path-backed log, the in-memory chain never advances past what is durably on
disk. After any `record()`, successful or failed, `len(entries)` equals the number of lines
in the file and `prev` equals the file's head. A failed write leaves a verifiable prefix,
never a gap.

Run: python -m unittest tests.test_audit_durable_commit -v
"""

import builtins
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import AuditLog, ChainStatus, canonical_entry, sha256, verify_file


class _DurableCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self._real_open = builtins.open
        self.addCleanup(lambda: setattr(builtins, "open", self._real_open))

    def path(self, name="c.jsonl"):
        return os.path.join(self.tmp, name)

    def fail_writes(self, path, only=None):
        """Fail the audit append for `path`. `only` = set of 1-based call numbers to fail;
        None fails every one. Models a disk-full / permission fault."""
        real, n = self._real_open, [0]

        def patched(f, *a, **k):
            if str(f) == path and a and "a" in str(a[0]):
                n[0] += 1
                if only is None or n[0] in only:
                    raise OSError(28, "No space left on device")
            return real(f, *a, **k)

        builtins.open = patched
        return n

    def lines(self, path):
        with self._real_open(path, encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]


# ---------------- INV-25 ----------------
class TestInMemoryNeverAheadOfDisk(_DurableCase):
    def test_success_leaves_memory_and_disk_equal(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.assertEqual(len(log.entries), verify_file(p).entries)
        self.assertEqual(log.prev, verify_file(p).head)

    def test_write_failure_commits_nothing_in_memory(self):
        """The defect: this left in-memory 2 against on-disk 1."""
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.fail_writes(p)
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        self.assertEqual(len(log.entries), 1)
        self.assertEqual(len(log.entries), verify_file(p).entries)

    def test_write_failure_does_not_advance_prev(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        before = log.prev
        self.fail_writes(p)
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        self.assertEqual(log.prev, before)
        self.assertEqual(log.prev, verify_file(p).head)

    def test_failure_on_the_very_first_record_leaves_genesis(self):
        p = self.path()
        log = AuditLog(p)
        self.fail_writes(p)
        with self.assertRaises(OSError):
            log.record("u", "p1", "r1", True)
        self.assertEqual(log.prev, "0" * 64)
        self.assertEqual(log.entries, [])

    def test_no_in_memory_only_entry_survives_a_failure(self):
        p = self.path()
        log = AuditLog(p)
        self.fail_writes(p)
        with self.assertRaises(OSError):
            log.record("u", "CANARY", "r", True)
        self.assertEqual(log.entries, [])
        self.assertIs(log.check().status, ChainStatus.VERIFIED)


# ---------------- the corruption this closes ----------------
class TestFailureThenSuccess(_DurableCase):
    def test_on_disk_chain_verifies_after_failure_then_success(self):
        """The defect: this produced `tampered` - entry 1 did not link to its
        predecessor, because prev had advanced over an unpersisted entry."""
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        log.record("u", "p3", "r3", True)
        r = verify_file(p)
        self.assertIs(r.status, ChainStatus.VERIFIED, r.detail)
        self.assertEqual(r.entries, 2)

    def test_the_later_entry_chains_from_the_last_persisted_entry(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        log.record("u", "p3", "r3", True)
        rows = self.lines(p)
        self.assertEqual(rows[1]["prev"], rows[0]["entry_hash"])

    def test_no_gap_is_written(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        log.record("u", "p3", "r3", True)
        prev = "0" * 64
        for i, row in enumerate(self.lines(p)):
            self.assertEqual(row["prev"], prev, f"gap at entry {i}")
            prev = row["entry_hash"]

    def test_memory_and_disk_agree_after_recovery(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            log.record("u", "p2", "r2", True)
        log.record("u", "p3", "r3", True)
        self.assertEqual(len(log.entries), verify_file(p).entries)
        self.assertEqual(log.prev, verify_file(p).head)


# ---------------- intermittent and sustained faults ----------------
class TestIntermittentAndSustained(_DurableCase):
    def test_intermittent_faults_never_produce_a_tampered_chain(self):
        """The end-to-end shape: writes 5 and 6 fail, then recover."""
        p = self.path()
        log = AuditLog(p)
        self.fail_writes(p, only={5, 6})
        failures = 0
        for i in range(12):
            try:
                log.record("u", f"p{i}", f"r{i}", True)
            except OSError:
                failures += 1
        self.assertEqual(failures, 2)
        r = verify_file(p)
        self.assertIs(r.status, ChainStatus.VERIFIED, r.detail)
        self.assertEqual(r.entries, 10)
        self.assertEqual(len(log.entries), r.entries)

    def test_sustained_failure_leaves_a_verifiable_prefix(self):
        p = self.path()
        log = AuditLog(p)
        for i in range(3):
            log.record("u", f"p{i}", f"r{i}", True)
        self.fail_writes(p)
        for i in range(4):
            with self.assertRaises(OSError):
                log.record("u", f"x{i}", f"y{i}", True)
        r = verify_file(p)
        self.assertIs(r.status, ChainStatus.VERIFIED, r.detail)
        self.assertEqual(r.entries, 3)
        self.assertEqual(len(log.entries), 3)

    def test_every_persisted_entry_is_one_record_call(self):
        p = self.path()
        log = AuditLog(p)
        self.fail_writes(p, only={2, 4})
        ok = 0
        for i in range(6):
            try:
                log.record("u", f"p{i}", f"r{i}", True)
                ok += 1
            except OSError:
                pass
        self.assertEqual(verify_file(p).entries, ok)


# ---------------- ADR 0020 resume is unchanged ----------------
class TestResumeUnchanged(_DurableCase):
    def test_a_second_log_resumes_from_the_persisted_head(self):
        p = self.path()
        a = AuditLog(p)
        a.record("u", "p1", "r1", True)
        a.record("u", "p2", "r2", True)
        head = verify_file(p).head
        b = AuditLog(p)
        self.assertEqual(b.prev, head)
        self.assertEqual(len(b.entries), 2)
        b.record("u", "p3", "r3", True)
        r = verify_file(p)
        self.assertIs(r.status, ChainStatus.VERIFIED)
        self.assertEqual(r.entries, 3)

    def test_resume_after_a_write_failure_still_verifies(self):
        p = self.path()
        a = AuditLog(p)
        a.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            a.record("u", "p2", "r2", True)
        builtins.open = self._real_open
        b = AuditLog(p)
        b.record("u", "p3", "r3", True)
        r = verify_file(p)
        self.assertIs(r.status, ChainStatus.VERIFIED, r.detail)
        self.assertEqual(r.entries, 2)

    def test_the_file_remains_appendable_after_a_failure(self):
        """ADR 0020 refuses a tampered file. A gapped file was unusable forever."""
        p = self.path()
        a = AuditLog(p)
        a.record("u", "p1", "r1", True)
        self.fail_writes(p, only={1})
        with self.assertRaises(OSError):
            a.record("u", "p2", "r2", True)
        builtins.open = self._real_open
        AuditLog(p)  # must not raise ConfigError

    def test_records_append_rather_than_truncate(self):
        p = self.path()
        a = AuditLog(p)
        a.record("u", "p1", "r1", True)
        a.record("u", "p2", "r2", True)
        self.assertEqual(len(self.lines(p)), 2)


# ---------------- unchanged contracts ----------------
class TestUnchangedContracts(_DurableCase):
    def test_path_none_log_is_unaffected(self):
        log = AuditLog(None)
        e = log.record("u", "p", "r", True)
        self.assertEqual(len(log.entries), 1)
        self.assertEqual(log.prev, e["entry_hash"])
        self.assertIs(log.check().status, ChainStatus.VERIFIED)

    def test_path_none_records_repeatedly(self):
        log = AuditLog(None)
        for i in range(5):
            log.record("u", f"p{i}", f"r{i}", True)
        self.assertEqual(len(log.entries), 5)
        self.assertIs(log.check().status, ChainStatus.VERIFIED)

    def test_the_write_failure_propagates_unchanged(self):
        p = self.path()
        log = AuditLog(p)
        self.fail_writes(p)
        with self.assertRaises(OSError) as ctx:
            log.record("u", "p", "r", True)
        self.assertEqual(ctx.exception.errno, 28)

    def test_record_returns_the_entry_it_persisted(self):
        p = self.path()
        log = AuditLog(p)
        e = log.record("u", "p", "r", True)
        self.assertEqual(self.lines(p)[0], e)

    def test_entry_shape_and_hash_are_unchanged(self):
        p = self.path()
        log = AuditLog(p)
        e = log.record("u", "p", "r", True)
        self.assertEqual(sorted(e), ["entry_hash", "ok", "prev", "prompt_sha256",
                                     "response_sha256", "ts", "url", "v"])
        self.assertEqual(e["entry_hash"], sha256(canonical_entry(e)))
        self.assertIn("entry_hash", self.lines(p)[0])

    def test_prev_advances_on_success(self):
        p = self.path()
        log = AuditLog(p)
        first = log.record("u", "p1", "r1", True)
        self.assertEqual(log.prev, first["entry_hash"])
        second = log.record("u", "p2", "r2", True)
        self.assertEqual(second["prev"], first["entry_hash"])
        self.assertEqual(log.prev, second["entry_hash"])

    def test_no_raw_payload_is_persisted(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "CANARY-PROMPT-8c31", "CANARY-RESPONSE-2f7a", True)
        with self._real_open(p, encoding="utf-8") as fh:
            blob = fh.read()
        self.assertNotIn("CANARY-PROMPT-8c31", blob)
        self.assertNotIn("CANARY-RESPONSE-2f7a", blob)

    def test_ok_false_is_recorded(self):
        p = self.path()
        log = AuditLog(p)
        log.record("u", "p", "r", False)
        self.assertIs(self.lines(p)[0]["ok"], False)


if __name__ == "__main__":
    unittest.main()
