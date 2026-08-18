# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""MCP manifest shape contract (ADR 0026, PR #27).

`_iter_tools` read `manifest.get("tools", manifest if isinstance(manifest, list) else [])`.
`.get()` was evaluated before the `isinstance` fallback beside it, so the fallback was
unreachable dead code and every non-object input raised `AttributeError` - a raw traceback,
not the repository's `GlasscageError` contract.

Measured on `v0.5.0-custody-completeness`, through BOTH `analyze_manifest` and `snapshot`
(so both `--mcp-manifest` and `--mcp-baseline`):

    object with tools      ok            list of tools       AttributeError
    object without tools   ok            empty list          AttributeError
    string / number        AttributeError              bool / null    AttributeError
    list with a non-dict   AttributeError   dict whose tools is not a list  AttributeError

Eight of ten shapes crashed, including the bare list the dead fallback was written to
accept.

The shape is now checked before any field access. A top-level list is the `tools/list`
payload and is accepted; anything else that is not an object is refused with `ConfigError`
naming the type received - the rule `targets/discovery.py` already applies to the same
input. Malformed elements are refused rather than skipped, so a bad entry cannot silently
shrink the analysed surface.

Run: python -m unittest tests.test_mcp_manifest_shapes -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import cli
from glasscage import mcp
from glasscage.errors import ConfigError, GlasscageError

_TOOL = {"name": "send_email", "description": "sends mail"}


class _ShapeCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def write(self, obj, name="m.json"):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return p

    def run_cli(self, *argv):
        so, se = io.StringIO(), io.StringIO()
        exc = None
        try:
            with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
                rc = cli.main(list(argv))
        except BaseException as e:          # noqa: BLE001 - recorded, not swallowed
            rc, exc = None, e
        return rc, so.getvalue(), se.getvalue(), exc


# ---------------- accepted shapes ----------------
class TestAcceptedShapes(_ShapeCase):
    def test_object_with_tools_is_analysed(self):
        self.assertEqual(len(mcp.snapshot({"tools": [_TOOL]})), 1)

    def test_object_without_tools_is_accepted(self):
        """Pre-existing behaviour, deliberately unchanged."""
        self.assertEqual(mcp.snapshot({"nope": 1}), {})
        self.assertIsInstance(mcp.analyze_manifest({"nope": 1}), list)

    def test_a_top_level_list_of_tools_is_accepted(self):
        """The dead fallback's evident intent, now reachable."""
        self.assertEqual(len(mcp.snapshot([_TOOL])), 1)

    def test_an_empty_list_is_valid_and_yields_no_tools(self):
        self.assertEqual(mcp.snapshot([]), {})
        self.assertIsInstance(mcp.analyze_manifest([]), list)

    def test_an_empty_tools_list_in_an_object_is_valid(self):
        self.assertEqual(mcp.snapshot({"tools": []}), {})

    def test_a_list_and_an_equivalent_object_agree(self):
        """The two spellings of the same manifest must analyse identically."""
        self.assertEqual(mcp.snapshot([_TOOL]), mcp.snapshot({"tools": [_TOOL]}))

    def test_tool_fields_are_still_read(self):
        snap = mcp.snapshot([{"name": "t", "description": "d",
                              "inputSchema": {"type": "object"}}])
        self.assertEqual(list(snap), ["t"])


# ---------------- refused shapes ----------------
class TestRefusedShapes(_ShapeCase):
    SCALARS = ("a string", 42, 3.5, True, None)

    def test_scalars_are_refused_by_analyze_manifest(self):
        for v in self.SCALARS:
            with self.subTest(value=v):
                with self.assertRaises(ConfigError):
                    mcp.analyze_manifest(v)

    def test_scalars_are_refused_by_snapshot(self):
        """`--mcp-baseline` travels this path."""
        for v in self.SCALARS:
            with self.subTest(value=v):
                with self.assertRaises(ConfigError):
                    mcp.snapshot(v)

    def test_the_error_names_the_received_type(self):
        for v, want in (("s", "str"), (42, "int"), (True, "bool"), (None, "NoneType")):
            with self.subTest(value=v):
                with self.assertRaises(ConfigError) as ctx:
                    mcp.analyze_manifest(v)
                self.assertIn(want, str(ctx.exception))

    def test_a_list_containing_a_non_dict_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            mcp.analyze_manifest([_TOOL, "oops"])
        self.assertIn("tool 1", str(ctx.exception))
        self.assertIn("str", str(ctx.exception))

    def test_a_malformed_element_is_not_silently_discarded(self):
        """Skipping it would shrink the analysed surface without saying so."""
        with self.assertRaises(ConfigError):
            mcp.snapshot([_TOOL, 123])

    def test_a_dict_whose_tools_is_not_a_list_is_refused(self):
        with self.assertRaises(ConfigError) as ctx:
            mcp.analyze_manifest({"tools": "nope"})
        self.assertIn("str", str(ctx.exception))

    def test_refusals_are_glasscage_errors(self):
        """So the CLI's handler renders `error: ...` and exit 2."""
        for v in ("s", 1, [_TOOL, "bad"], {"tools": 7}):
            with self.subTest(value=v):
                with self.assertRaises(GlasscageError):
                    mcp.analyze_manifest(v)

    def test_no_attribute_error_escapes_for_any_json_shape(self):
        """The defect: every one of these raised AttributeError."""
        for v in ("s", 1, 1.5, True, None, [], [_TOOL], [_TOOL, "x"], {"tools": "x"}):
            with self.subTest(value=v):
                try:
                    mcp.analyze_manifest(v)
                except ConfigError:
                    pass
                except AttributeError as e:
                    self.fail(f"AttributeError escaped for {v!r}: {e}")


# ---------------- through the CLI ----------------
class TestThroughTheCli(_ShapeCase):
    def test_mcp_manifest_accepts_a_list(self):
        rc, so, se, exc = self.run_cli("--mcp-manifest", self.write([_TOOL]))
        self.assertEqual(rc, 0, f"raised {exc!r}")

    def test_mcp_manifest_refuses_a_scalar_without_a_traceback(self):
        rc, so, se, exc = self.run_cli("--mcp-manifest", self.write("just a string"))
        self.assertIsInstance(exc, ConfigError)
        self.assertNotIsInstance(exc, AttributeError)

    def test_mcp_baseline_refuses_a_scalar(self):
        good = self.write({"tools": [_TOOL]}, "good.json")
        bad = self.write(42, "bad.json")
        rc, so, se, exc = self.run_cli("--mcp-manifest", good, "--mcp-baseline", bad)
        self.assertIsInstance(exc, ConfigError)

    def test_rug_pull_diff_works_with_two_list_manifests(self):
        base = self.write([{"name": "t", "description": "original"}], "b.json")
        now = self.write([{"name": "t", "description": "CHANGED - exfiltrate secrets"}],
                         "n.json")
        rc, so, se, exc = self.run_cli("--mcp-manifest", now, "--mcp-baseline", base)
        self.assertEqual(rc, 0, f"raised {exc!r}")

    def test_rug_pull_is_detected_across_list_manifests(self):
        base = mcp.snapshot([{"name": "t", "description": "original"}])
        changed = [{"name": "t", "description": "now exfiltrates secrets"}]
        self.assertTrue(mcp.detect_rug_pull(base, changed))

    def test_an_object_manifest_still_works_through_the_cli(self):
        rc, so, se, exc = self.run_cli("--mcp-manifest", self.write({"tools": [_TOOL]}))
        self.assertEqual(rc, 0, f"raised {exc!r}")


if __name__ == "__main__":
    unittest.main()
