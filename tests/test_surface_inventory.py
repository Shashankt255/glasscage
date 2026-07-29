# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface inventory tests (PR #3): discovery renderers and the --discover CLI mode.

Covers to_json/to_markdown shape, locator rendering per kind, ASCII-only output,
honest empty rendering, renderer purity, and the standalone CLI mode (no target, no
assessment, deterministic artifacts).
Run: python -m unittest tests.test_surface_inventory -v
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
from glasscage.errors import ConfigError
from glasscage.targets import discover_mcp, discover_openapi
from glasscage.targets.discovery import to_json, to_markdown

_SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
_MCP = os.path.join(_SAMPLES, "mcp_manifest.json")

_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/v1/chat": {"post": {"operationId": "createChat"},
                     "get": {"parameters": [{"name": "limit", "in": "query"}]}},
        "/v1/files/{id}": {"delete": {"operationId": "deleteFile"}},
    },
}


def _rest():
    return discover_openapi(_OPENAPI)


def _mcp():
    with open(_MCP, encoding="utf-8") as fh:
        return discover_mcp(json.load(fh))


def _write(tmp, name, payload):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


# ---------------- to_json ----------------
class TestToJson(unittest.TestCase):
    def test_field_set_and_order_match_the_candidate(self):
        rows = to_json(_rest())
        self.assertEqual(list(rows[0]), ["id", "kind", "locator", "io_schema", "source"])

    def test_kind_is_a_string_value_not_an_enum(self):
        for row in to_json(_rest()) + to_json(_mcp()):
            self.assertIsInstance(row["kind"], str)
            self.assertIn(row["kind"], ("rest", "mcp_tool"))

    def test_is_json_serializable_and_preserves_discovery_order(self):
        found = _rest()
        rows = json.loads(json.dumps(to_json(found)))
        self.assertEqual([r["id"] for r in rows], [c.id for c in found])


# ---------------- to_markdown ----------------
class TestToMarkdown(unittest.TestCase):
    def test_one_row_per_candidate(self):
        found = _rest()
        rows = [ln for ln in to_markdown(found).splitlines()
                if ln.startswith("| rest:")]
        self.assertEqual(len(rows), len(found))

    def test_rest_locator_renders_method_and_path(self):
        self.assertIn("| POST /v1/chat |", to_markdown(_rest()))
        self.assertIn("| DELETE /v1/files/{id} |", to_markdown(_rest()))

    def test_mcp_locator_renders_the_tool_name(self):
        md = to_markdown(_mcp())
        self.assertIn("| get_weather |", md)
        self.assertIn("mcp_tool", md)

    def test_output_is_ascii_only(self):
        for md in (to_markdown(_rest()), to_markdown(_mcp()), to_markdown([])):
            md.encode("ascii")          # raises UnicodeEncodeError if not ASCII


# ---------------- empty input and purity ----------------
class TestEmptyAndPurity(unittest.TestCase):
    def test_empty_inventory_is_stated_not_faked(self):
        md = to_markdown([])
        self.assertIn("No surfaces discovered.", md)
        self.assertNotIn("|---|", md)
        self.assertEqual(to_json([]), [])

    def test_renderers_do_not_mutate_their_input(self):
        found = _rest()
        before = [(c.id, c.kind, c.locator, c.source) for c in found]
        to_markdown(found)
        to_json(found)
        self.assertEqual([(c.id, c.kind, c.locator, c.source) for c in found], before)


# ---------------- CLI mode ----------------
class TestDiscoverCLI(unittest.TestCase):
    def test_runs_without_a_target_and_writes_both_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = _write(tmp, "openapi.json", _OPENAPI)
            out = os.path.join(tmp, "inv")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--discover", spec, "--out", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(f"{out}_surfaces.md"))
            self.assertTrue(os.path.exists(f"{out}_surfaces.json"))

    def test_prints_the_table_to_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = _write(tmp, "openapi.json", _OPENAPI)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.main(["--discover", spec, "--out", os.path.join(tmp, "inv")])
            text = buf.getvalue()
            self.assertIn("GLASSCAGE Surface Inventory", text)
            self.assertIn("| POST /v1/chat |", text)

    def test_json_artifact_is_byte_identical_across_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = _write(tmp, "openapi.json", _OPENAPI)
            first, second = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--discover", spec, "--out", first])
                cli.main(["--discover", spec, "--out", second])
            with open(f"{first}_surfaces.json", "rb") as fh:
                a = fh.read()
            with open(f"{second}_surfaces.json", "rb") as fh:
                b = fh.read()
            self.assertEqual(a, b)

    def test_runs_no_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = _write(tmp, "openapi.json", _OPENAPI)
            out = os.path.join(tmp, "inv")
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--discover", spec, "--out", out])
            for artifact in (f"{out}.md", f"{out}.html", f"{out}.json",
                             f"{out}_aakg.json", f"{out}_evidence"):
                self.assertFalse(os.path.exists(artifact), artifact)


# ---------------- refusal ----------------
class TestDiscoverRefusal(unittest.TestCase):
    def test_malformed_document_raises_config_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = _write(tmp, "bad.json", {"not": "a spec"})
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ConfigError):
                    cli.main(["--discover", bad, "--out", os.path.join(tmp, "x")])


if __name__ == "__main__":
    unittest.main()
