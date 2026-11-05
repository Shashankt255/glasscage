# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Replay surface applicability (ADR 0018, PR #19).

`--replay` crashed a REST assessment. `cli.py` fell back to `target.body_template` and
`target.response_path` whenever `--config` was absent, which is exactly the REST path's
condition, and `RestTarget` declares neither. PR #16 made the combination reachable.

Fixing the attribute read alone would not have been enough: the bundle carries
`body_template`/`response_path` and the emitted runner builds an `HTTPChatTarget` and
calls `send()`, so the format is chat-shaped by construction. No format exists for a
non-chat surface, so none is written.

The load-bearing assertions are the chat ones: this must change nothing for `--demo`,
`--harness` or `--config`, whose bundles and runners are frozen against `v0.4.2`.

Run: python -m unittest tests.test_replay_surface -v
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage.audit import Scope
from glasscage.errors import ConfigError
from glasscage.targets import (
    ApplicationTarget,
    ChatSurface,
    RestTarget,
    Surface,
    SurfaceKind,
    bind_candidate,
    discover_openapi,
    rest_surface_from_target,
)

_SPEC = {"paths": {"/users": {"get": {}}}}
_CFG = {"url": "https://api.example/v1"}

# Frozen against c883228 (v0.4.2-correctness).
_RUNNER_SHA = "8453f77bb5a65d823c94a9062d2c70b7a5ea52a48472e83aa1f3cf7f31883246"


class _Resp:
    status = 200

    def read(self):
        return b'{"users":[]}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Run:
    def __enter__(self):
        self._d = tempfile.TemporaryDirectory()
        d = self._d.name
        self.spec = os.path.join(d, "s.json")
        self.cfg = os.path.join(d, "r.json")
        with open(self.spec, "w", encoding="utf-8") as fh:
            json.dump(_SPEC, fh)
        with open(self.cfg, "w", encoding="utf-8") as fh:
            json.dump(_CFG, fh)
        self.out = os.path.join(d, "o")
        return self

    def __exit__(self, *a):
        self._d.cleanup()
        return False

    def go(self, argv):
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=_Resp()), \
                redirect_stdout(out_buf), redirect_stderr(err_buf):
            rc = cli.main(argv)
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def rest_argv(self, *extra):
        return ["--rest-spec", self.spec, "--rest-config", self.cfg, "--out", self.out,
                "--no-evidence", "--no-aakg", "--authorized", "--scope", "api.example",
                *extra]

    def bundle_exists(self):
        return os.path.exists(f"{self.out}.replay.json")

    def runner_exists(self):
        return os.path.exists(f"{self.out}_replay_runner.py")


# ---------------- the crash ----------------
class TestRestReplayDoesNotCrash(unittest.TestCase):
    def test_rest_replay_completes(self):
        """Reproduces the defect: this raised AttributeError at cli.py:426."""
        with _Run() as r:
            rc, _, _ = r.go(r.rest_argv("--replay"))
            self.assertEqual(rc, 0)

    def test_rest_replay_with_other_exports_completes(self):
        with _Run() as r:
            rc, _, _ = r.go(r.rest_argv("--replay", "--sarif", "--har"))
            self.assertEqual(rc, 0)

    def test_exit_code_matches_a_run_without_replay(self):
        with _Run() as r:
            without, _, _ = r.go(r.rest_argv())
        with _Run() as r:
            with_, _, _ = r.go(r.rest_argv("--replay"))
        self.assertEqual(with_, without)


# ---------------- nothing is written ----------------
class TestNoArtifactIsWritten(unittest.TestCase):
    def test_no_bundle_is_written(self):
        with _Run() as r:
            r.go(r.rest_argv("--replay"))
            self.assertFalse(r.bundle_exists())

    def test_no_runner_is_written(self):
        with _Run() as r:
            r.go(r.rest_argv("--replay"))
            self.assertFalse(r.runner_exists())

    def test_wrote_line_omits_the_bundle(self):
        with _Run() as r:
            _, out, _ = r.go(r.rest_argv("--replay"))
            self.assertNotIn(".replay.json", out)


# ---------------- the warning ----------------
class TestWarning(unittest.TestCase):
    def test_warning_goes_to_stderr_naming_the_kind(self):
        with _Run() as r:
            _, _, err = r.go(r.rest_argv("--replay"))
        self.assertIn("--replay is not supported", err)
        self.assertIn("rest", err)

    def test_warning_states_the_reason(self):
        with _Run() as r:
            _, _, err = r.go(r.rest_argv("--replay"))
        self.assertIn("chat-only", err)

    def test_stdout_is_unchanged_by_the_warning(self):
        """The warning is diagnostic; stdout must stay parseable."""
        with _Run() as r:
            _, with_, _ = r.go(r.rest_argv("--replay"))
        with _Run() as r:
            _, without, _ = r.go(r.rest_argv())
        self.assertNotIn("not supported", with_)
        self.assertEqual(len(with_.splitlines()), len(without.splitlines()))

    def test_no_warning_when_replay_not_requested(self):
        with _Run() as r:
            _, _, err = r.go(r.rest_argv())
        self.assertNotIn("--replay is not supported", err)


# ---------------- other exports unaffected ----------------
class TestOtherArtifactsUnaffected(unittest.TestCase):
    def test_sarif_is_still_written_on_a_rest_run(self):
        with _Run() as r:
            r.go(r.rest_argv("--replay", "--sarif"))
            self.assertTrue(os.path.exists(f"{r.out}.sarif"))

    def test_har_is_still_written_on_a_rest_run(self):
        with _Run() as r:
            r.go(r.rest_argv("--replay", "--har"))
            self.assertTrue(os.path.exists(f"{r.out}.har"))

    def test_report_is_still_written_on_a_rest_run(self):
        with _Run() as r:
            r.go(r.rest_argv("--replay"))
            for ext in (".md", ".html", ".json"):
                self.assertTrue(os.path.exists(f"{r.out}{ext}"), ext)


# ---------------- chat is frozen ----------------
class TestChatReplayIsUnchanged(unittest.TestCase):
    def _capture(self, mode):
        with _Run() as r:
            rc, _, err = r.go([mode, "--out", r.out, "--no-evidence", "--no-aakg",
                               "--replay"])
            with open(f"{r.out}.replay.json", encoding="utf-8") as fh:
                bundle = json.load(fh)
            with open(f"{r.out}_replay_runner.py", encoding="utf-8") as fh:
                runner = fh.read()
        return rc, bundle, runner, err

    def test_demo_bundle_and_runner_are_written(self):
        rc, bundle, runner, err = self._capture("--demo")
        self.assertEqual(rc, 0)
        self.assertEqual(bundle["glasscage_replay_version"], "1.0")
        self.assertTrue(bundle["steps"])
        self.assertNotIn("--replay is not supported", err)

    def test_harness_bundle_and_runner_are_written(self):
        rc, bundle, runner, _ = self._capture("--harness")
        self.assertEqual(rc, 0)
        self.assertTrue(bundle["steps"])

    def test_runner_is_byte_identical_to_baseline(self):
        for mode in ("--demo", "--harness"):
            with self.subTest(mode=mode):
                _, _, runner, _ = self._capture(mode)
                self.assertEqual(
                    hashlib.sha256(runner.encode()).hexdigest(), _RUNNER_SHA)

    def test_target_config_shape_is_unchanged(self):
        _, bundle, _, _ = self._capture("--demo")
        self.assertEqual(sorted(bundle["target_config"]),
                         ["body_template", "name", "response_path", "url"])


# ---------------- the guard keys on surface kind ----------------
class TestGuardKeysOnSurfaceKind(unittest.TestCase):
    def test_no_surface_resolves_to_chat(self):
        self.assertEqual(cli._driven_kinds(None), {SurfaceKind.CHAT})

    def test_a_chat_surface_resolves_to_chat(self):
        from glasscage.refagent import ReferenceAgent
        self.assertEqual(cli._driven_kinds(ChatSurface(ReferenceAgent())),
                         {SurfaceKind.CHAT})

    def test_a_rest_surface_resolves_to_rest(self):
        t = RestTarget("https://api.example/v1")
        t.scope = Scope(["api.example"])
        self.assertEqual(cli._driven_kinds(rest_surface_from_target(t, "GET", "/u")),
                         {SurfaceKind.REST})

    def test_a_mixed_application_reports_both_kinds(self):
        """The guard must fire on any non-CHAT kind present, not on the target's type."""
        from glasscage.refagent import ReferenceAgent
        agent = ReferenceAgent()
        t = RestTarget("https://api.example/v1")
        t.scope = Scope(["api.example"])
        app = ApplicationTarget(base_url=t.url)
        app.add_surface(ChatSurface(agent, surface_id="c"))
        for c in discover_openapi(_SPEC):
            app.add_surface(bind_candidate(c, t))
        self.assertEqual(cli._driven_kinds(app), {SurfaceKind.CHAT, SurfaceKind.REST})

    def test_a_kind_with_no_driver_is_still_refused_by_resolution(self):
        """`_driven_kinds` delegates to `drivable_surfaces_of`, so it inherits ADR 0009's
        refusal rather than inventing its own."""
        t = RestTarget("https://api.example/v1")
        bad = Surface(id="x", kind=SurfaceKind.GRAPHQL, locator=None,
                      driver=rest_surface_from_target(t, "GET", "/u").driver)
        with self.assertRaises(ConfigError):
            cli._driven_kinds(bad)


if __name__ == "__main__":
    unittest.main()
