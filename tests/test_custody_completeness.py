# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Custody completeness at run exit (ADR 0025, PR #26).

PR #25 made the audit chain durable before visible, so the CLI's `Audit chain: verified
(N)` line became true about the file. It stayed silent about what was lost. A failing
custody backend surfaced only as a `"probe ... crashed"` note in the report JSON, and the
run exited 0.

Measured on `v0.4.9-durable-audit-commit`, an audit backend failing from write 5:

    network calls   18
    exchanges       18
    audit entries    4   (== on disk, chain `verified`)
    exit code        0   <- an assessment reported successful with 14 exchanges
                            missing from custody

`exchanges` holds exactly one record per exchange the transport performed (ADR 0022/0023);
after ADR 0024 the chain holds exactly what reached disk. The difference is therefore
custody loss and nothing else - which is why a refused connection, an HTTP 500 and a
`response_path` failure all reconcile to zero: each appends one exchange AND one entry.

Every count below comes from the real CLI driving a real target over a real socket, with a
real `OSError` raised by the audit append. No counter is mocked.

Run: python -m unittest tests.test_custody_completeness -v
"""

import builtins
import contextlib
import http.server
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage.audit import ChainStatus, verify_file

_DIAG = "custody incomplete"


class _Handler(http.server.BaseHTTPRequestHandler):
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
        body = (b"this is not json" if type(self).mode == "badjson"
                else json.dumps({"response": "hello"}).encode())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _CliCase(unittest.TestCase):
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
        self._real_open = builtins.open
        self.addCleanup(lambda: setattr(builtins, "open", self._real_open))
        self.cfg = os.path.join(self.tmp, "target.json")
        with self._real_open(self.cfg, "w", encoding="utf-8") as fh:
            json.dump({"url": f"http://127.0.0.1:{self._port}/chat", "name": "chat-local",
                       "body_template": {"prompt": "{{PROMPT}}"},
                       "response_path": "response"}, fh)

    @property
    def calls(self):
        return len(_Handler.hits)

    def audit(self, name="a.jsonl"):
        return os.path.join(self.tmp, name)

    def fail_audit_from(self, path, nth):
        """Make the audit append raise a real OSError from the nth write onward."""
        real, n = self._real_open, [0]

        def patched(f, *a, **k):
            if str(f) == path and a and "a" in str(a[0]):
                n[0] += 1
                if n[0] >= nth:
                    raise OSError(28, "No space left on device")
            return real(f, *a, **k)

        builtins.open = patched

    def run_cli(self, *extra, audit=None, out="o"):
        argv = ["--config", self.cfg, "--authorized", "--scope", "127.0.0.1",
                "--no-evidence", "--out", os.path.join(self.tmp, out)]
        if audit:
            argv += ["--audit-log", audit]
        so, se = io.StringIO(), io.StringIO()
        exc = None
        try:
            with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
                rc = cli.main(argv + list(extra))
        except BaseException as e:
            rc, exc = None, e
        return rc, so.getvalue(), se.getvalue(), exc


# ---------------- the real end-to-end failure path ----------------
class TestIncompleteCustodyFailsClosed(_CliCase):
    """Real CLI -> real socket -> real AuditLog, with a real OSError on the append."""

    def _run_with_loss(self, out="o"):
        a = self.audit()
        self.fail_audit_from(a, 5)
        rc, so, se, exc = self.run_cli(audit=a, out=out)
        builtins.open = self._real_open
        return a, rc, so, se, exc

    def test_an_exchange_actually_occurred(self):
        a, rc, so, se, exc = self._run_with_loss()
        self.assertGreater(self.calls, 0, "no real network exchange took place")

    def test_custody_entries_are_actually_absent(self):
        a, rc, so, se, exc = self._run_with_loss()
        on_disk = verify_file(a)
        self.assertLess(on_disk.entries, self.calls)
        self.assertIs(on_disk.status, ChainStatus.VERIFIED)

    def test_exit_status_is_non_zero(self):
        a, rc, so, se, exc = self._run_with_loss()
        self.assertIsNotNone(rc, f"run raised instead of returning: {exc!r}")
        self.assertNotEqual(rc, 0)

    def test_exactly_one_diagnostic_is_emitted(self):
        a, rc, so, se, exc = self._run_with_loss()
        self.assertEqual(se.count(_DIAG), 1)

    def test_the_diagnostic_names_the_shortfall(self):
        a, rc, so, se, exc = self._run_with_loss()
        lost = self.calls - verify_file(a).entries
        line = next(l for l in se.splitlines() if _DIAG in l)
        self.assertIn(f"{lost} of {self.calls}", line)

    def test_the_shortfall_equals_exchanges_minus_entries(self):
        a, rc, so, se, exc = self._run_with_loss()
        lost = self.calls - verify_file(a).entries
        self.assertGreater(lost, 0)
        self.assertIn(str(lost), se)

    def test_the_diagnostic_blames_custody_not_the_target(self):
        a, rc, so, se, exc = self._run_with_loss()
        line = next(l for l in se.splitlines() if _DIAG in l)
        self.assertIn("chain of custody", line)
        self.assertIn("target was assessed", line)

    def test_the_diagnostic_goes_to_stderr_only(self):
        a, rc, so, se, exc = self._run_with_loss()
        self.assertNotIn(_DIAG, so)

    def test_artifacts_are_still_written(self):
        a, rc, so, se, exc = self._run_with_loss()
        for suffix in (".md", ".html", ".json"):
            self.assertTrue(os.path.exists(os.path.join(self.tmp, "o" + suffix)), suffix)

    def test_the_surviving_chain_still_verifies(self):
        a, rc, so, se, exc = self._run_with_loss()
        self.assertIs(verify_file(a).status, ChainStatus.VERIFIED)

    def test_the_exit_status_is_stable_across_runs(self):
        first = self._run_with_loss(out="o1")[1]
        _Handler.hits = []
        second = self._run_with_loss(out="o2")[1]
        self.assertEqual(first, second)

    def test_it_is_distinguishable_from_a_refusal(self):
        """Exit 2 already means refused; incomplete custody is a different outcome."""
        a, rc, so, se, exc = self._run_with_loss()
        self.assertNotIn(rc, (0, 2))


# ---------------- negative paths: none of these is custody loss ----------------
class TestFailuresThatAreNotCustodyLoss(_CliCase):
    def test_complete_custody_exits_zero_with_no_diagnostic(self):
        a = self.audit()
        rc, so, se, exc = self.run_cli(audit=a)
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se)
        self.assertEqual(verify_file(a).entries, self.calls)

    def test_http_500_is_not_custody_loss(self):
        _Handler.mode = "http500"
        a = self.audit()
        rc, so, se, exc = self.run_cli(audit=a)
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se)

    def test_non_json_response_is_not_custody_loss(self):
        _Handler.mode = "badjson"
        a = self.audit()
        rc, so, se, exc = self.run_cli(audit=a)
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se)

    def test_connection_refused_is_not_custody_loss(self):
        cfg = os.path.join(self.tmp, "dead.json")
        with self._real_open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:9/chat", "name": "dead",
                       "body_template": {"prompt": "{{PROMPT}}"},
                       "response_path": "response"}, fh)
        a = self.audit()
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main(["--config", cfg, "--authorized", "--scope", "127.0.0.1",
                           "--no-evidence", "--out", os.path.join(self.tmp, "d"),
                           "--audit-log", a])
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se.getvalue())

    def test_response_path_failure_is_not_custody_loss(self):
        cfg = os.path.join(self.tmp, "badpath.json")
        with self._real_open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"url": f"http://127.0.0.1:{self._port}/chat", "name": "bp",
                       "body_template": {"prompt": "{{PROMPT}}"},
                       "response_path": "nope.missing"}, fh)
        a = self.audit()
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main(["--config", cfg, "--authorized", "--scope", "127.0.0.1",
                           "--no-evidence", "--out", os.path.join(self.tmp, "bp"),
                           "--audit-log", a])
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se.getvalue())

    def test_out_of_scope_refusal_is_unchanged(self):
        """ADR 0021: refused before any exchange, so completeness never applies."""
        a = self.audit()
        so, se = io.StringIO(), io.StringIO()
        with self.assertRaises(PermissionError), \
             contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
                cli.main(["--config", self.cfg, "--authorized",
                          "--scope", "elsewhere.example", "--no-evidence",
                          "--out", os.path.join(self.tmp, "oos"), "--audit-log", a])
        self.assertEqual(self.calls, 0)
        self.assertNotIn(_DIAG, se.getvalue())

    def test_zero_exchange_run_is_not_custody_loss(self):
        """`--arch-template` builds no target, so nothing is reconciled."""
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main(["--arch-template"])
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se.getvalue())

    def test_audit_log_absent_is_unchanged(self):
        rc, so, se, exc = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se)

    def test_demo_surface_is_unchanged(self):
        a = self.audit("demo.jsonl")
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main(["--demo", "--no-evidence",
                           "--out", os.path.join(self.tmp, "demo"), "--audit-log", a])
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se.getvalue())
        self.assertEqual(verify_file(a).entries, 21)

    def test_harness_surface_is_unchanged(self):
        a = self.audit("h.jsonl")
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main(["--harness", "--no-evidence",
                           "--out", os.path.join(self.tmp, "h"), "--audit-log", a])
        self.assertEqual(rc, 0)
        self.assertNotIn(_DIAG, se.getvalue())
        self.assertEqual(verify_file(a).entries, 25)


# ---------------- recon-time failure keeps its existing behaviour ----------------
class TestReconTimeFailureUnchanged(_CliCase):
    def test_a_first_write_failure_still_propagates(self):
        """Recon runs outside the engine's per-probe handler, so the OSError escapes.
        ADR 0025 does not change that; it is asserted here so it cannot drift."""
        a = self.audit()
        self.fail_audit_from(a, 1)
        rc, so, se, exc = self.run_cli(audit=a)
        builtins.open = self._real_open
        self.assertIsInstance(exc, OSError)
        self.assertIsNone(rc)


# ---------------- the reconciliation is a real comparison ----------------
class TestReconciliationSemantics(_CliCase):
    def test_complete_custody_reconciles_to_zero(self):
        a = self.audit()
        rc, so, se, exc = self.run_cli(audit=a)
        self.assertEqual(self.calls, verify_file(a).entries)

    def test_a_single_lost_entry_is_reported(self):
        """The boundary: exactly one missing exchange must still fail closed."""
        a = self.audit()
        rc0, so0, se0, _ = self.run_cli(audit=a, out="warm")
        total = self.calls
        _Handler.hits = []
        b = self.audit("b.jsonl")
        self.fail_audit_from(b, total)      # every write but the last succeeds
        rc, so, se, exc = self.run_cli(audit=b, out="one")
        builtins.open = self._real_open
        lost = self.calls - verify_file(b).entries
        self.assertEqual(lost, 1)
        self.assertEqual(rc, 3)
        self.assertIn("1 of", se)


if __name__ == "__main__":
    unittest.main()
