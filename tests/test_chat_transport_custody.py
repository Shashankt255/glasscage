# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Chat transport custody exception boundary (ADR 0023, PR #24).

`HTTPChatTarget.send()` called `_record()` from inside the `try` whose broad
`except Exception` also calls `_record()`. A failure raised by custody itself was
therefore caught as though it were a transport fault: a fabricated `ok=False`
`ChatResponse` was built from the audit error text, and a SECOND exchange was recorded
for one network call.

Measured on `v0.4.7-harness-transport-custody` with one network call:

    audit.record raises        -> 2 exchanges, 0 audit entries
    audit file write fails     -> 2 exchanges, 2 audit entries, chain still VERIFIED
                                  entry 1 carried the digest of
                                  "[Errno 28] No space left on device"

Over a full CLI run with the disk filling mid-assessment: 18 network calls, 32 HAR
entries, 4 audit entries on disk, `Audit chain: verified (32 entries)`, exit 0.

Every count below is measured server-side or against the real transport, never inferred.
The transport try/except now assigns the outcome only; custody is recorded once after it -
the shape `RestDriver.drive` has always had (ADR 0008 §1).

Run: python -m unittest tests.test_chat_transport_custody -v
"""

import builtins
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage.audit import AuditLog, ChainStatus, sha256, verify_file
from glasscage.target import HTTPChatTarget


class _Handler(http.server.BaseHTTPRequestHandler):
    """Counts real requests server-side. Mode is set per test."""

    hits: list = []
    mode = "ok"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        type(self).hits.append(self.rfile.read(n).decode("utf-8", "replace"))
        if type(self).mode == "http500":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (b"this is not json"
                if type(self).mode == "badjson"
                else json.dumps({"response": "hello"}).encode())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _TransportCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        cls._port = cls._srv.server_address[1]
        threading.Thread(target=cls._srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls._srv.shutdown()
        cls._srv.server_close()

    def setUp(self):
        _Handler.hits = []
        _Handler.mode = "ok"
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    @property
    def calls(self):
        """Real network calls, counted by the server."""
        return len(_Handler.hits)

    def target(self, audit_path=None, url=None):
        t = HTTPChatTarget({"url": url or f"http://127.0.0.1:{self._port}/chat",
                            "name": "chat-local",
                            "body_template": {"prompt": "{{PROMPT}}"},
                            "response_path": "response"})
        t.audit = AuditLog(audit_path)
        return t

    def failing_write(self, path):
        """Fail only the audit append for `path` - a disk-full / permission fault."""
        real = builtins.open

        def patched(f, *a, **k):
            if str(f) == path and a and "a" in str(a[0]):
                raise OSError(28, "No space left on device")
            return real(f, *a, **k)

        builtins.open = patched
        self.addCleanup(lambda: setattr(builtins, "open", real))


# ---------------- 1-3: the happy path records exactly once ----------------
class TestSuccessfulExchangeRecordsOnce(_TransportCase):
    def test_one_network_call_one_exchange_one_entry(self):
        t = self.target()
        t.send("hi")
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(t.exchanges), 1)
        self.assertEqual(len(t.audit.entries), 1)

    def test_entry_corresponds_to_the_transport_exchange(self):
        """The entry attests to what was actually sent and received."""
        t = self.target()
        r = t.send("hi")
        e = t.audit.entries[0]
        self.assertEqual(e["url"], t.url)
        self.assertEqual(e["prompt_sha256"], sha256(_Handler.hits[0]))
        self.assertEqual(e["response_sha256"], sha256('{"response": "hello"}'))
        self.assertIs(e["ok"], True)
        self.assertIs(r.ok, True)
        self.assertEqual(t.exchanges[0]["status"], 200)

    def test_exchange_metadata_names_the_real_target(self):
        """The exchange dict is what HAR is built from (`audit.har_export` reads its
        `url`/`method`), so wrong metadata there puts a false host into an evidentiary
        artifact. Distinct from the audit entry's url, which is written by a different
        call and asserted above."""
        t = self.target()
        t.send("hi")
        x = t.exchanges[0]
        self.assertEqual(x["url"], t.url)
        self.assertEqual(x["method"], t.method)
        self.assertEqual(x["request_body"], _Handler.hits[0])
        self.assertEqual(x["response_body"], '{"response": "hello"}')

    def test_repeated_calls_stay_one_to_one(self):
        t = self.target()
        for _ in range(5):
            t.send("hi")
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (5, 5, 5))

    def test_chain_verifies(self):
        t = self.target()
        t.send("hi")
        self.assertIs(t.audit.check().status, ChainStatus.VERIFIED)


# ---------------- 4-5: the custody-failure boundary ----------------
class TestCustodyFailureDoesNotDoubleRecord(_TransportCase):
    def test_audit_record_raising_records_one_exchange_not_two(self):
        """The defect: this produced 2 exchanges for 1 network call."""
        class Boom(AuditLog):
            def record(self, *a, **k):
                raise RuntimeError("audit backend unavailable")

        t = self.target()
        t.audit = Boom(None)
        with self.assertRaises(RuntimeError):
            t.send("hi")
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(t.exchanges), 1, "custody failure re-entered the transport")

    def test_audit_write_failure_records_one_entry_not_two(self):
        """The damaging case: this produced 2 exchanges, the second fabricated.

        Entry count amended for ADR 0024: custody is committed durably before it becomes
        visible, so a failed write commits nothing in memory either. The transport
        assertions below are unchanged - one network call is still one exchange."""
        p = os.path.join(self.tmp, "chain.jsonl")
        t = self.target(p)
        self.failing_write(p)
        with self.assertRaises(OSError):
            t.send("hi")
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(t.exchanges), 1)
        self.assertEqual(len(t.audit.entries), 0)

    def test_no_fabricated_response_is_recorded(self):
        """A failing custody backend must not become a recorded 'exchange'.
        Previously entry 1 carried the digest of the OSError text and status 0."""
        p = os.path.join(self.tmp, "chain.jsonl")
        t = self.target(p)
        self.failing_write(p)
        with self.assertRaises(OSError):
            t.send("hi")
        for e in t.audit.entries:
            self.assertIs(e["ok"], True)
            self.assertNotEqual(e["response_sha256"],
                                sha256("[Errno 28] No space left on device"))
        for x in t.exchanges:
            self.assertNotIn("No space left on device", str(x["response_body"]))
            self.assertNotEqual(x["status"], 0)

    def test_the_recorded_entry_is_the_real_exchange(self):
        """Amended for ADR 0024: a failed write leaves no entry to inspect, so the
        assertion moves to the exchange - which still carries the real response - and to
        the absence of any in-memory-only custody."""
        p = os.path.join(self.tmp, "chain.jsonl")
        t = self.target(p)
        self.failing_write(p)
        with self.assertRaises(OSError):
            t.send("hi")
        self.assertEqual(t.exchanges[0]["response_body"], '{"response": "hello"}')
        self.assertEqual(t.audit.entries, [])
        self.assertEqual(sha256('{"response": "hello"}'),
                         sha256(t.exchanges[0]["response_body"]))

    def test_custody_failure_does_not_repeat_the_network_call(self):
        class Boom(AuditLog):
            def record(self, *a, **k):
                raise RuntimeError("nope")

        t = self.target()
        t.audit = Boom(None)
        with self.assertRaises(RuntimeError):
            t.send("hi")
        self.assertEqual(self.calls, 1, "the transport was re-driven")


# ---------------- transport failures still record exactly once ----------------
class TestTransportFailuresUnchanged(_TransportCase):
    def test_connection_refused_records_once_without_a_network_call(self):
        t = self.target(url="http://127.0.0.1:9/chat")
        r = t.send("hi")
        self.assertIs(r.ok, False)
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (0, 1, 1))

    def test_non_json_body_records_once(self):
        _Handler.mode = "badjson"
        t = self.target()
        r = t.send("hi")
        self.assertIs(r.ok, False)
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (1, 1, 1))
        self.assertEqual(t.exchanges[0]["status"], 0)

    def test_http_500_records_once_with_its_status(self):
        _Handler.mode = "http500"
        t = self.target()
        r = t.send("hi")
        self.assertIs(r.ok, False)
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (1, 1, 1))
        self.assertEqual(t.exchanges[0]["status"], 500)
        self.assertIs(t.audit.entries[0]["ok"], False)

    def test_response_path_failure_records_once_as_not_ok(self):
        t = self.target()
        t.response_path = "nope.missing"
        r = t.send("hi")
        self.assertIs(r.ok, False)
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (1, 1, 1))
        self.assertEqual(t.exchanges[0]["status"], 200)
        self.assertIs(t.audit.entries[0]["ok"], False)

    def test_a_failed_exchange_is_never_recorded_as_successful(self):
        _Handler.mode = "http500"
        t = self.target()
        t.send("hi")
        self.assertIs(t.audit.entries[0]["ok"], False)


# ---------------- a later success after a failure ----------------
class TestRecoveryAfterCustodyFailure(_TransportCase):
    def test_a_later_exchange_still_records_exactly_once(self):
        p = os.path.join(self.tmp, "chain.jsonl")
        t = self.target(p)
        real = builtins.open
        fail = {"on": True}

        def patched(f, *a, **k):
            if fail["on"] and str(f) == p and a and "a" in str(a[0]):
                raise OSError(28, "No space left on device")
            return real(f, *a, **k)

        builtins.open = patched
        self.addCleanup(lambda: setattr(builtins, "open", real))
        with self.assertRaises(OSError):
            t.send("first")
        fail["on"] = False
        t.send("second")
        self.assertEqual(self.calls, 2)
        self.assertEqual(len(t.exchanges), 2)
        # Amended for ADR 0024: the first exchange committed nothing, so only the second
        # is in custody. The transport assertions above are unchanged.
        self.assertEqual(len(t.audit.entries), 1)
        self.assertIs(t.audit.check().status, ChainStatus.VERIFIED)


# ---------------- existing audit semantics are untouched ----------------
class TestAuditSemanticsUnchanged(_TransportCase):
    def test_no_raw_payload_is_persisted(self):
        p = os.path.join(self.tmp, "c.jsonl")
        t = self.target(p)
        t.send("CANARY-PROMPT-4b19")
        blob = open(p, encoding="utf-8").read()
        self.assertNotIn("CANARY-PROMPT-4b19", blob)
        self.assertNotIn("hello", blob)

    def test_append_resume_across_two_targets_on_one_path(self):
        """ADR 0020 resume is unchanged by this fix."""
        p = os.path.join(self.tmp, "c.jsonl")
        a = self.target(p)
        a.send("one")
        first = verify_file(p)
        b = self.target(p)
        b.send("two")
        second = verify_file(p)
        self.assertIs(second.status, ChainStatus.VERIFIED)
        self.assertEqual(second.entries, 2)
        self.assertEqual(first.entries, 1)
        self.assertNotEqual(second.head, first.head)

    def test_file_entry_count_equals_network_calls(self):
        p = os.path.join(self.tmp, "c.jsonl")
        t = self.target(p)
        for _ in range(4):
            t.send("hi")
        self.assertEqual(verify_file(p).entries, self.calls)

    def test_scope_and_rate_are_still_consulted_before_transport(self):
        """CLI control wiring (ADR 0021) is unaffected: an out-of-scope host is refused
        before any request, and nothing is recorded."""
        from glasscage.audit import Scope
        t = self.target()
        t.scope = Scope(["elsewhere.example"])
        with self.assertRaises(PermissionError):
            t.send("hi")
        self.assertEqual((self.calls, len(t.exchanges), len(t.audit.entries)), (0, 0, 0))

    def test_a_target_without_an_audit_log_still_records_exchanges(self):
        t = self.target()
        t.audit = None
        t.send("hi")
        self.assertEqual(len(t.exchanges), 1)


# ---------------- the ordering contract itself ----------------
class TestCustodyIsOutsideTheTransportHandler(unittest.TestCase):
    """The defect was positional. Pin the position, not only its effects."""

    def _src(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "glasscage", "target.py")
        return open(p, encoding="utf-8").read()

    def test_send_has_exactly_one_record_call(self):
        body = self._src().split("def send(", 1)[1].split("def _record(", 1)[0]
        self.assertEqual(body.count("self._record("), 1,
                         "custody must be recorded from exactly one site in send()")

    def test_the_record_call_follows_every_except_clause(self):
        body = self._src().split("def send(", 1)[1].split("def _record(", 1)[0]
        self.assertGreater(body.index("self._record("), body.rindex("except "),
                           "custody must be recorded after the transport handlers, "
                           "never inside them")

    def test_send_returns_once_after_recording(self):
        body = self._src().split("def send(", 1)[1].split("def _record(", 1)[0]
        self.assertEqual(body.count("return resp_obj"), 1)
        self.assertGreater(body.index("return resp_obj"), body.index("self._record("))


if __name__ == "__main__":
    unittest.main()
