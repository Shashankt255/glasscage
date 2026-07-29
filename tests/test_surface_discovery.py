# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface discovery tests (ADR 0003).

Covers OpenAPI and MCP enumeration, deterministic ids, honest handling of empty and
malformed input, the ApplicationTarget candidate registry, the no-network / never-bound
guarantees, and non-regression of `schema.ingest`.
Run: python -m unittest tests.test_surface_discovery -v
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import schema
from glasscage.errors import ConfigError, GlasscageError
from glasscage.targets import (
    ApplicationTarget,
    SurfaceCandidate,
    SurfaceKind,
    discover,
    discover_mcp,
    discover_openapi,
)

_SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")

_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/v1/chat": {
            "post": {
                "operationId": "createChat",
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/x"}}}},
            },
            "get": {"parameters": [{"name": "limit", "in": "query"}]},
            "options": {"summary": "ignored: unsupported method"},
            "description": "not an operation",
        },
        "/v1/files/{id}": {"delete": {"operationId": "deleteFile"}},
        "/broken": "not-an-object",
    },
}

# Same document without the malformed path entry. `schema.from_openapi` raises
# AttributeError on a path whose value is not an object (pre-existing; schema.py is
# explicitly out of scope for this PR), so the non-regression comparison uses a
# well-formed document — which is what a regression baseline should use anyway.
_OPENAPI_CLEAN = {"openapi": "3.0.0",
                  "paths": {k: v for k, v in _OPENAPI["paths"].items() if k != "/broken"}}


def _load_sample(name):
    with open(os.path.join(_SAMPLES, name), encoding="utf-8") as fh:
        return json.load(fh)


# ---------------- OpenAPI parsing ----------------
class TestOpenAPIDiscovery(unittest.TestCase):
    def test_one_candidate_per_operation(self):
        found = discover_openapi(_OPENAPI)
        self.assertEqual([c.id for c in found],
                         ["rest:delete:/v1/files/{id}", "rest:get:/v1/chat",
                          "rest:post:/v1/chat"])
        self.assertTrue(all(c.kind is SurfaceKind.REST for c in found))
        self.assertTrue(all(c.source == "openapi" for c in found))

    def test_locator_carries_method_and_path(self):
        post = [c for c in discover_openapi(_OPENAPI) if c.id == "rest:post:/v1/chat"][0]
        self.assertEqual(post.locator, {"method": "POST", "path": "/v1/chat"})

    def test_io_schema_preserves_request_body_and_parameters(self):
        found = {c.id: c for c in discover_openapi(_OPENAPI)}
        self.assertIn("requestBody", found["rest:post:/v1/chat"].io_schema)
        self.assertEqual(found["rest:get:/v1/chat"].io_schema,
                         {"parameters": [{"name": "limit", "in": "query"}]})
        self.assertIsNone(found["rest:delete:/v1/files/{id}"].io_schema)

    def test_unsupported_methods_and_non_objects_are_skipped(self):
        ids = [c.id for c in discover_openapi(_OPENAPI)]
        self.assertNotIn("rest:options:/v1/chat", ids)
        self.assertFalse([i for i in ids if "/broken" in i])

    def test_ref_is_passed_through_not_resolved(self):
        post = [c for c in discover_openapi(_OPENAPI) if c.id == "rest:post:/v1/chat"][0]
        blob = json.dumps(post.io_schema)
        self.assertIn("$ref", blob)


# ---------------- MCP parsing ----------------
class TestMCPDiscovery(unittest.TestCase):
    def test_one_candidate_per_tool(self):
        found = discover_mcp(_load_sample("mcp_manifest.json"))
        self.assertEqual([c.id for c in found],
                         ["mcp_tool:fetch_url", "mcp_tool:get_weather",
                          "mcp_tool:metadata_probe", "mcp_tool:notes_helper"])
        self.assertTrue(all(c.kind is SurfaceKind.MCP_TOOL for c in found))
        self.assertTrue(all(c.source == "mcp" for c in found))

    def test_input_schema_preserved_and_locator_is_the_tool_name(self):
        found = {c.id: c for c in discover_mcp(_load_sample("mcp_manifest.json"))}
        weather = found["mcp_tool:get_weather"]
        self.assertEqual(weather.locator, "get_weather")
        self.assertEqual(weather.io_schema,
                         {"type": "object", "properties": {"city": {"type": "string"}}})

    def test_unnamed_tools_are_skipped_not_invented(self):
        found = discover_mcp({"tools": [{"description": "no name"}, {"name": ""},
                                        {"name": "ok"}]})
        self.assertEqual([c.id for c in found], ["mcp_tool:ok"])


# ---------------- auto-detect ----------------
class TestAutoDetect(unittest.TestCase):
    def test_dispatches_openapi_and_mcp(self):
        self.assertTrue(all(c.kind is SurfaceKind.REST for c in discover(_OPENAPI)))
        self.assertTrue(all(c.kind is SurfaceKind.MCP_TOOL
                            for c in discover(_load_sample("mcp_manifest.json"))))

    def test_unrecognized_shape_is_refused(self):
        with self.assertRaises(ConfigError):
            discover(_load_sample("function_schema.json"))
        with self.assertRaises(ConfigError):
            discover(["not", "a", "document"])


# ---------------- determinism ----------------
class TestDeterminism(unittest.TestCase):
    def test_repeated_runs_are_identical(self):
        a = [(c.id, c.kind, c.source) for c in discover_openapi(_OPENAPI)]
        b = [(c.id, c.kind, c.source) for c in discover_openapi(_OPENAPI)]
        self.assertEqual(a, b)

    def test_ids_are_unique_and_sorted(self):
        ids = [c.id for c in discover_openapi(_OPENAPI)]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))

    def test_duplicate_operations_collapse(self):
        spec = {"paths": {"/x": {"get": {}, "GET": {}}}}
        self.assertEqual([c.id for c in discover_openapi(spec)], ["rest:get:/x"])


# ---------------- honesty ----------------
class TestHonesty(unittest.TestCase):
    def test_empty_paths_yields_no_candidates(self):
        self.assertEqual(discover_openapi({"paths": {}}), [])
        self.assertEqual(discover_mcp({"tools": []}), [])

    def test_malformed_documents_raise_config_error(self):
        for bad in ({}, {"paths": None}, {"paths": []}, "string", None):
            with self.assertRaises(GlasscageError):
                discover_openapi(bad)
        for bad in ({}, {"tools": None}, {"tools": {}}, 7):
            with self.assertRaises(GlasscageError):
                discover_mcp(bad)

    def test_no_candidate_is_emitted_for_an_absent_operation(self):
        found = discover_openapi({"paths": {"/only": {"get": {}}}})
        self.assertEqual([c.locator["path"] for c in found], ["/only"])
        self.assertEqual([c.locator["method"] for c in found], ["GET"])


# ---------------- registry ----------------
class TestCandidateRegistry(unittest.TestCase):
    def test_add_candidate_is_idempotent_by_id(self):
        app = ApplicationTarget(base_url="https://x.example")
        for c in discover_openapi(_OPENAPI):
            app.add_candidate(c)
        again = discover_openapi(_OPENAPI)
        for c in again:
            app.add_candidate(c)
        self.assertEqual(len(app.candidates), 3)

    def test_candidates_of_filters_by_kind(self):
        app = ApplicationTarget()
        for c in discover_openapi(_OPENAPI):
            app.add_candidate(c)
        for c in discover_mcp(_load_sample("mcp_manifest.json")):
            app.add_candidate(c)
        self.assertEqual(len(app.candidates_of(SurfaceKind.REST)), 3)
        self.assertEqual(len(app.candidates_of(SurfaceKind.MCP_TOOL)), 4)
        self.assertEqual(app.candidates_of(SurfaceKind.CHAT), [])


# ---------------- safety ----------------
class TestSafety(unittest.TestCase):
    def test_discovery_performs_no_network_io(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("discovery must not use the network")):
            self.assertTrue(discover_openapi(_OPENAPI))
            self.assertTrue(discover_mcp(_load_sample("mcp_manifest.json")))

    def test_candidates_are_never_bound_to_a_driver(self):
        found = discover_openapi(_OPENAPI) + discover_mcp(_load_sample("mcp_manifest.json"))
        self.assertTrue(found)
        for c in found:
            self.assertIsInstance(c, SurfaceCandidate)
            self.assertFalse(hasattr(c, "driver"))
            self.assertFalse(hasattr(c, "drive"))


# ---------------- non-regression ----------------
class TestSchemaUnaffected(unittest.TestCase):
    def test_schema_ingest_output_is_unchanged(self):
        tools = schema.ingest(_OPENAPI_CLEAN)
        self.assertEqual(
            tools,
            [{"name": "createChat", "capability": "write", "side_effect": True,
              "provenance": "schema-confirmed"},
             {"name": "get /v1/chat", "capability": "data", "side_effect": False,
              "provenance": "schema-confirmed"},
             {"name": "deleteFile", "capability": "write", "side_effect": True,
              "provenance": "schema-confirmed"}])


if __name__ == "__main__":
    unittest.main()
