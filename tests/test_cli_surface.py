# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""CLI surface-exposure tests (ADR 0015, PR #16).

ADR 0002 deferred a CLI flag "until a discovery PR gives it something to select";
discovery landed in ADR 0003 and binding in ADR 0014, so the REST programme built across
PRs #12-#15 is reachable from the CLI for the first time.

Two guarantees carry most of the weight here. `--discover` is untouched: it remains an
inventory command that drives nothing, in every combination, which is why a dedicated
`--rest-spec` exists rather than an overloaded `--discover`. And ADR 0012 R1 is preserved
by the *existing* boundary — a REST run without `--scope` is refused by `require_scope` at
SurfaceTarget construction, not by new logic in `cli.py`.

No network: urllib.request.urlopen is patched throughout.
Run: python -m unittest tests.test_cli_surface -v
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage.errors import TargetError
from glasscage.targets import discovery as discovery_mod

_SPEC = {"paths": {"/users": {"get": {}}, "/admin/keys": {"get": {}}}}
_REST_CFG = {"url": "https://api.example/v1"}
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[0-9:.+\-]+")


class _Resp:
    def __init__(self, body='{"users":[]}'):
        self._b, self.status = body.encode("utf-8"), 200

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patched(body='{"users":[]}'):
    return mock.patch("urllib.request.urlopen", return_value=_Resp(body))


class _Run:
    """Runs cli.main in a temp dir with stdout captured."""

    def __init__(self, argv, body='{"users":[]}', patch=True, spec=None):
        self.argv, self.body, self.patch, self.spec = argv, body, patch, spec or _SPEC

    def __enter__(self):
        self._d = tempfile.TemporaryDirectory()
        d = self._d.name
        self.spec_path = os.path.join(d, "spec.json")
        self.cfg_path = os.path.join(d, "rest.json")
        with open(self.spec_path, "w", encoding="utf-8") as fh:
            json.dump(self.spec, fh)
        with open(self.cfg_path, "w", encoding="utf-8") as fh:
            json.dump(_REST_CFG, fh)
        self.out = os.path.join(d, "r")
        return self

    def __exit__(self, *a):
        self._d.cleanup()
        return False

    def go(self, argv):
        buf = io.StringIO()
        ctx = _patched(self.body) if self.patch else mock.patch(
            "urllib.request.urlopen",
            side_effect=AssertionError("no request may be issued"))
        with ctx, redirect_stdout(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()

    def rest_argv(self, *extra):
        return ["--rest-spec", self.spec_path, "--rest-config", self.cfg_path,
                "--out", self.out, "--no-evidence", "--no-aakg", *extra]

    def report(self):
        with open(f"{self.out}.json", encoding="utf-8") as fh:
            return json.load(fh)


# ---------------- end to end ----------------
class TestRestAssessment(unittest.TestCase):
    def test_rest_assessment_runs_and_writes_a_report(self):
        with _Run(None) as r:
            rc, _ = r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            self.assertEqual(rc, 0)
            data = r.report()
        self.assertTrue(data["findings"])

    def test_every_discovered_operation_is_driven(self):
        with _Run(None) as r:
            r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            data = r.report()
        ids = {f["surface_id"] for f in data["findings"] if f["surface_id"]}
        self.assertEqual(ids, {"rest:get:/users", "rest:get:/admin/keys"})

    def test_rest_probe_produced_a_finding_per_surface(self):
        with _Run(None) as r:
            r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            data = r.report()
        rest = [f for f in data["findings"]
                if f["probe_name"] == "rest-response-disclosure"]
        self.assertEqual({f["surface_id"] for f in rest},
                         {"rest:get:/users", "rest:get:/admin/keys"})

    def test_a_secret_in_the_response_is_reported(self):
        with _Run(None, body='{"k":"sk-ABCDEFGHIJKLMNOP0123"}') as r:
            r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            data = r.report()
        vuln = [f for f in data["findings"] if f["status"] == "vulnerable"]
        self.assertTrue(vuln)
        self.assertTrue(all(f["probe_name"] == "rest-response-disclosure" for f in vuln))


# ---------------- ADR 0012 R1 ----------------
class TestScopeIsStillRequired(unittest.TestCase):
    def test_rest_run_without_scope_is_refused(self):
        """Refused by `require_scope` at SurfaceTarget construction — cli.py adds no
        refusal logic of its own."""
        with _Run(None, patch=False) as r:
            with self.assertRaises(TargetError) as ctx:
                r.go(r.rest_argv("--authorized"))
        self.assertIn("scope", str(ctx.exception).lower())

    def test_refusal_precedes_any_request(self):
        with _Run(None, patch=False) as r:      # urlopen raises if called
            with self.assertRaises(TargetError):
                r.go(r.rest_argv("--authorized"))

    def test_the_cli_cannot_produce_an_empty_scope(self):
        """`--scope` takes `nargs="+"`, so a bare `--scope` is an argparse error. The
        empty-allowlist branch of ADR 0012 R1 is therefore unreachable from the CLI, and
        the absent-scope refusal above is the only one an operator can hit."""
        with _Run(None, patch=False) as r:
            with self.assertRaises(SystemExit):
                r.go(r.rest_argv("--authorized", "--scope"))


# ---------------- --authorized ----------------
class TestAuthorizedGate(unittest.TestCase):
    def test_rest_path_refuses_without_authorized(self):
        with _Run(None, patch=False) as r:
            rc, _ = r.go(r.rest_argv("--scope", "api.example"))
        self.assertEqual(rc, 2)

    def test_refusal_writes_no_report(self):
        with _Run(None, patch=False) as r:
            r.go(r.rest_argv("--scope", "api.example"))
            self.assertFalse(os.path.exists(f"{r.out}.json"))

    def test_rest_config_without_spec_is_refused(self):
        """Asserts the *reason*, not just SystemExit: against a build with no
        `--rest-config` flag at all, argparse would exit with "unrecognized arguments"
        and a bare assertRaises could not tell the two apart."""
        err = io.StringIO()
        with _Run(None, patch=False) as r:
            with redirect_stderr(err), self.assertRaises(SystemExit):
                r.go(["--rest-config", r.cfg_path, "--out", r.out, "--authorized"])
        self.assertIn("--rest-spec", err.getvalue())
        self.assertNotIn("unrecognized", err.getvalue())


# ---------------- --discover is untouched ----------------
class TestDiscoverUnchanged(unittest.TestCase):
    def _expected_md(self):
        return discovery_mod.to_markdown(discovery_mod.discover(_SPEC))

    # Every filesystem assertion below stays INSIDE the `with`: the temp directory is
    # removed on exit, so an `assertFalse(os.path.exists(...))` outside it would pass
    # whatever the CLI did.
    def test_discover_standalone_still_returns_without_assessing(self):
        with _Run(None, patch=False) as r:       # urlopen raises if called
            rc, out = r.go(["--discover", r.spec_path, "--out", r.out])
            self.assertEqual(rc, 0)
            self.assertIn(self._expected_md(), out)
            self.assertFalse(os.path.exists(f"{r.out}.json"))

    def test_discover_output_is_identical_with_rest_spec_present(self):
        """`--rest-spec` must not imply, suppress or alter `--discover`."""
        with _Run(None, patch=False) as r:
            _, without = r.go(["--discover", r.spec_path, "--out", r.out])
            _, with_ = r.go(["--discover", r.spec_path, "--out", r.out,
                             "--rest-spec", r.spec_path])
            self.assertEqual(without, with_)

    def test_discover_with_config_still_ignores_config_and_returns(self):
        """Pre-existing behaviour, deliberately unchanged by PR #16 (EIA risk R-6)."""
        with _Run(None, patch=False) as r:
            rc, out = r.go(["--discover", r.spec_path, "--out", r.out,
                            "--config", r.cfg_path])
            self.assertEqual(rc, 0)
            self.assertIn(self._expected_md(), out)
            self.assertFalse(os.path.exists(f"{r.out}.json"))

    def test_discover_with_rest_config_still_returns_without_assessing(self):
        with _Run(None, patch=False) as r:
            rc, _ = r.go(["--discover", r.spec_path, "--out", r.out,
                          "--rest-config", r.cfg_path, "--authorized",
                          "--scope", "api.example"])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(f"{r.out}.json"))

    def test_discover_writes_its_inventory_files(self):
        with _Run(None, patch=False) as r:
            r.go(["--discover", r.spec_path, "--out", r.out])
            self.assertTrue(os.path.exists(f"{r.out}_surfaces.md"))
            self.assertTrue(os.path.exists(f"{r.out}_surfaces.json"))


# ---------------- existing invocations ----------------
class TestExistingInvocationsUnchanged(unittest.TestCase):
    def test_harness_still_runs(self):
        with _Run(None, patch=False) as r:
            rc, _ = r.go(["--harness", "--out", r.out, "--no-evidence", "--no-aakg"])
        self.assertEqual(rc, 0)

    def test_harness_run_drives_no_surface(self):
        with _Run(None, patch=False) as r:
            r.go(["--harness", "--out", r.out, "--no-evidence", "--no-aakg"])
            data = r.report()
        self.assertEqual({f["surface_id"] for f in data["findings"]}, {""})

    def test_no_target_still_errors(self):
        with _Run(None, patch=False) as r:
            with self.assertRaises(SystemExit):
                r.go(["--out", r.out])


# ---------------- gating visibility (EIA risk R-1) ----------------
class TestGatingIsVisible(unittest.TestCase):
    def test_chat_probes_are_gated_on_a_rest_run(self):
        """Recorded expectation, not a surprise: ADR 0006 gates every chat probe on a
        REST surface, so a REST report is mostly NOT ASSESSABLE."""
        with _Run(None) as r:
            r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            data = r.report()
        gated = [f for f in data["findings"] if f["status"] == "not_assessable"]
        assessed = [f for f in data["findings"] if f["status"] != "not_assessable"]
        self.assertEqual(len(assessed), 2)          # the REST probe, once per surface
        self.assertEqual(len(gated), 42)            # 21 chat probes x 2 surfaces
        self.assertTrue(all(f["prompt"] == "(surface-gated)" for f in gated))

    def test_gated_findings_name_the_driven_kind(self):
        with _Run(None) as r:
            r.go(r.rest_argv("--authorized", "--scope", "api.example"))
            data = r.report()
        titles = {f["title"] for f in data["findings"]
                  if f["status"] == "not_assessable"}
        self.assertTrue(all("rest surface" in t for t in titles))


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_two_identical_rest_runs_agree(self):
        shapes = []
        for _ in range(2):
            with _Run(None) as r:
                r.go(r.rest_argv("--authorized", "--scope", "api.example"))
                data = r.report()
            shapes.append(_TS.sub("<TS>", json.dumps(
                [(f["probe_name"], f["status"], f["surface_id"], f["evidence_hash"])
                 for f in data["findings"]], sort_keys=True)))
        self.assertEqual(shapes[0], shapes[1])


if __name__ == "__main__":
    unittest.main()
