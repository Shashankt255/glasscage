# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Operational controls precede traffic (ADR 0021, PR #22).

`--scope`, `--rate` and `--audit-log` were attached to the target further down `main()`
than the branches that drive it. `--orchestrate` and `--validate` each build an Engine
over the constructed target and return before that wiring was reached, so on exactly the
two paths that send traffic the allowlist refused nothing, the rate limiter throttled
nothing and the audit log was never created - and the run still exited 0.

Measured on `v0.4.5-audit-append` against a local counting server: `--orchestrate` sent
21 requests and `--validate` sent 63 to a host excluded by `--scope`, while the normal
assessment path correctly refused with `PermissionError` and sent none.

These tests drive `cli.main` end to end and count requests server-side, because the
defect was one of ordering inside `main()` - a test that calls `orchestrator.orchestrate`
directly cannot see it, which is why the existing suite stayed green.

Run: python -m unittest tests.test_cli_safety_wiring -v
"""

import contextlib
import io
import json
import os
import sys
import threading
import http.server
import socketserver
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage.audit import ChainStatus, verify_file
from glasscage.errors import ConfigError


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        type(self).hits.append(self.rfile.read(n).decode("utf-8", "replace"))
        body = json.dumps({"response": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _ServerCase(unittest.TestCase):
    """A local counting endpoint. Binds 127.0.0.1 on an ephemeral port."""

    @classmethod
    def setUpClass(cls):
        cls._srv = socketserver.TCPServer(("127.0.0.1", 0), _CountingHandler)
        cls._port = cls._srv.server_address[1]
        cls._thread = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        cls._thread.start()
        cls.url = f"http://127.0.0.1:{cls._port}/chat"

    @classmethod
    def tearDownClass(cls):
        cls._srv.shutdown()
        cls._srv.server_close()

    def setUp(self):
        _CountingHandler.hits = []
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.cfg = os.path.join(self.tmp, "target.json")
        with open(self.cfg, "w", encoding="utf-8") as fh:
            json.dump({"url": self.url, "name": "local",
                       "body_template": {"prompt": "{{PROMPT}}"},
                       "response_path": "response"}, fh)
        self.addCleanup(self._tmp.cleanup)

    @property
    def hits(self):
        return len(_CountingHandler.hits)

    def out(self, name="o"):
        return os.path.join(self.tmp, name)

    def run_cli(self, *extra, scope="127.0.0.1", audit=None, rate=None):
        argv = ["--config", self.cfg, "--authorized", "--no-evidence",
                "--scope", scope, "--out", self.out()]
        if audit:
            argv += ["--audit-log", audit]
        if rate:
            argv += ["--rate", str(rate)]
        argv += list(extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()


# ---------------- AC3 / AC4: scope is honoured on every driving path ----------------
class TestScopeHonouredOnEveryDrivingPath(_ServerCase):
    OUT_OF_SCOPE = "example.com"   # 127.0.0.1 is deliberately excluded

    def test_orchestrate_refuses_an_out_of_scope_host(self):
        """AC3. Baseline sent 21 requests here and exited 0."""
        with self.assertRaises(PermissionError):
            self.run_cli("--orchestrate", "native", scope=self.OUT_OF_SCOPE)
        self.assertEqual(self.hits, 0)

    def test_validate_refuses_an_out_of_scope_host(self):
        """AC4. Baseline sent 63 requests here and exited 0."""
        with self.assertRaises(PermissionError):
            self.run_cli("--validate", scope=self.OUT_OF_SCOPE)
        self.assertEqual(self.hits, 0)

    def test_normal_assessment_still_refuses(self):
        with self.assertRaises(PermissionError):
            self.run_cli(scope=self.OUT_OF_SCOPE)
        self.assertEqual(self.hits, 0)

    def test_refusal_names_the_out_of_scope_host(self):
        """AC11: the same PermissionError contract, not a new error type."""
        with self.assertRaises(PermissionError) as ctx:
            self.run_cli("--orchestrate", "native", scope=self.OUT_OF_SCOPE)
        self.assertIn("out-of-scope", str(ctx.exception))
        self.assertIn("127.0.0.1", str(ctx.exception))

    def test_an_in_scope_host_is_still_driven(self):
        """The allowlist must not refuse what it permits."""
        rc, _ = self.run_cli("--orchestrate", "native")
        self.assertEqual(rc, 0)
        self.assertGreater(self.hits, 0)


# ---------------- AC5 / AC6: custody is recorded on every driving path -------------
class TestAuditWrittenOnEveryDrivingPath(_ServerCase):
    def _audit(self, name="a.jsonl"):
        return os.path.join(self.tmp, name)

    def test_orchestrate_writes_a_verifying_audit_log(self):
        """AC5. Baseline wrote no file at all."""
        a = self._audit()
        rc, _ = self.run_cli("--orchestrate", "native", audit=a)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(a), "no audit log was written")
        r = verify_file(a)
        self.assertIs(r.status, ChainStatus.VERIFIED)
        self.assertEqual(r.entries, self.hits)

    def test_validate_writes_a_verifying_audit_log(self):
        """AC6."""
        a = self._audit()
        rc, _ = self.run_cli("--validate", audit=a)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(a), "no audit log was written")
        r = verify_file(a)
        self.assertIs(r.status, ChainStatus.VERIFIED)
        self.assertEqual(r.entries, self.hits)

    def test_normal_assessment_still_writes_a_verifying_log(self):
        a = self._audit()
        self.run_cli(audit=a)
        r = verify_file(a)
        self.assertIs(r.status, ChainStatus.VERIFIED)
        self.assertEqual(r.entries, self.hits)

    def test_every_recorded_entry_is_one_request(self):
        """Custody is complete, not merely present."""
        a = self._audit()
        self.run_cli("--orchestrate", "native", audit=a)
        self.assertEqual(verify_file(a).entries, self.hits)

    def test_orchestrate_log_resumes_across_runs(self):
        """ADR 0020 append semantics reach this path too, now that it is wired."""
        a = self._audit()
        self.run_cli("--orchestrate", "native", audit=a)
        first = verify_file(a).entries
        self.run_cli("--orchestrate", "native", audit=a)
        r = verify_file(a)
        self.assertIs(r.status, ChainStatus.VERIFIED)
        self.assertEqual(r.entries, self.hits)
        self.assertGreater(r.entries, first)


# ---------------- AC7: rate limiting applies on every driving path -----------------
class TestRateAppliedOnEveryDrivingPath(_ServerCase):
    RATE = 10.0   # one request per 0.1s

    def test_orchestrate_is_throttled(self):
        """AC7. Baseline ran 21 requests in 0.06s with --rate 0.5 set."""
        t0 = time.perf_counter()
        self.run_cli("--orchestrate", "native", rate=self.RATE)
        elapsed = time.perf_counter() - t0
        floor = (self.hits - 1) / self.RATE
        self.assertGreater(self.hits, 1)
        self.assertGreaterEqual(elapsed, floor * 0.9,
                                f"{self.hits} requests in {elapsed:.2f}s; "
                                f"--rate {self.RATE} requires about {floor:.2f}s")

    def test_normal_assessment_is_throttled(self):
        t0 = time.perf_counter()
        self.run_cli(rate=self.RATE)
        elapsed = time.perf_counter() - t0
        floor = (self.hits - 1) / self.RATE
        self.assertGreaterEqual(elapsed, floor * 0.9)


# ---------------- AC10: a tampered custody log refuses on the new paths ------------
class TestTamperedAuditRefusesOnDrivingPaths(_ServerCase):
    def _tampered(self):
        a = os.path.join(self.tmp, "t.jsonl")
        self.run_cli(audit=a)                      # produce a genuine chain
        lines = open(a, encoding="utf-8").read().splitlines()
        e = json.loads(lines[0])
        e["url"] = "https://attacker.example"
        lines[0] = json.dumps(e)
        with open(a, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _CountingHandler.hits = []
        return a

    def test_orchestrate_refuses_a_tampered_log(self):
        a = self._tampered()
        with self.assertRaises(ConfigError):
            self.run_cli("--orchestrate", "native", audit=a)

    def test_validate_refuses_a_tampered_log(self):
        a = self._tampered()
        with self.assertRaises(ConfigError):
            self.run_cli("--validate", audit=a)

    def test_refusal_sends_no_traffic_and_writes_nothing(self):
        a = self._tampered()
        before = open(a, "rb").read()
        names = sorted(os.listdir(self.tmp))
        with self.assertRaises(ConfigError):
            self.run_cli("--orchestrate", "native", audit=a)
        self.assertEqual(self.hits, 0, "traffic was sent despite a refused custody log")
        self.assertEqual(open(a, "rb").read(), before)
        self.assertEqual(sorted(os.listdir(self.tmp)), names)


# ---------------- AC9: paths that never construct a target are unaffected ----------
class TestPreTargetPathsUnaffected(_ServerCase):
    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()

    def test_arch_template_needs_no_target(self):
        rc, _ = self._run(["--arch-template"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.hits, 0)

    def test_discover_needs_no_target(self):
        spec = os.path.join(self.tmp, "spec.json")
        with open(spec, "w", encoding="utf-8") as fh:
            json.dump({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                       "paths": {"/c": {"post": {"operationId": "c", "responses": {}}}}}, fh)
        rc, _ = self._run(["--discover", spec, "--out", self.out("d")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.hits, 0)

    def test_benchmark_needs_no_target(self):
        corpus = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "benchmark", "corpus.json")
        rc, _ = self._run(["--benchmark", corpus, "--out", self.out("b")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.hits, 0)

    def test_mcp_only_mode_needs_no_target(self):
        man = os.path.join(self.tmp, "m.json")
        with open(man, "w", encoding="utf-8") as fh:
            json.dump({"tools": [{"name": "send_email", "description": "d"}]}, fh)
        rc, _ = self._run(["--mcp-manifest", man])
        self.assertEqual(rc, 0)
        self.assertEqual(self.hits, 0)

    def test_an_audit_log_is_not_created_when_no_target_is_built(self):
        """The wiring moved up, but not above target construction: a path that never
        builds a target must not open a custody log for a run that cannot happen."""
        a = os.path.join(self.tmp, "unused.jsonl")
        self._run(["--arch-template", "--audit-log", a])
        self.assertFalse(os.path.exists(a))


# ---------------- ordering contract ----------------
class TestWiringPrecedesEveryDrivingBranch(unittest.TestCase):
    """The defect was positional. Pin the position, not just its effects."""

    def _src(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "cli.py")
        return open(p, encoding="utf-8").read()

    def test_controls_are_wired_before_orchestrate_and_validate(self):
        src = self._src()
        wiring = src.index("target.audit = audit_mod.AuditLog(args.audit_log)")
        for branch in ("if args.orchestrate:", "if args.validate:"):
            self.assertLess(wiring, src.index(branch),
                            f"safety wiring must precede `{branch}`")

    def test_controls_are_wired_after_target_construction(self):
        src = self._src()
        self.assertLess(src.index("target = _MockTarget()"),
                        src.index("target.audit = audit_mod.AuditLog(args.audit_log)"))

    def test_all_three_controls_are_wired_together(self):
        src = self._src()
        scope = src.index("target.scope = audit_mod.Scope(args.scope)")
        rate = src.index("target.rate = audit_mod.RateLimiter(args.rate)")
        audit = src.index("target.audit = audit_mod.AuditLog(args.audit_log)")
        for pos in (scope, rate, audit):
            self.assertLess(pos, src.index("if args.orchestrate:"))


if __name__ == "__main__":
    unittest.main()
