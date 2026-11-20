"""Tests for glasscage.integration_reference — CBH integration assets."""
import unittest

from glasscage import integration_reference as ir


class MCPToolsTests(unittest.TestCase):
    def test_mcp_tools_returns_list(self):
        tools = ir.mcp_tools()
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0)

    def test_all_tools_have_name_and_description(self):
        for t in ir.mcp_tools():
            self.assertIn("name", t)
            self.assertIn("description", t)

    def test_public_tools_present(self):
        names = {t["name"] for t in ir.mcp_tools()}
        for expected in ("search_disclosed_reports", "get_program",
                         "get_program_scope", "get_report"):
            self.assertIn(expected, names)

    def test_auth_tools_present(self):
        names = {t["name"] for t in ir.mcp_tools()}
        for expected in ("list_my_programs", "get_my_program", "list_my_reports"):
            self.assertIn(expected, names)

    def test_mcp_tool_for_found(self):
        t = ir.mcp_tool_for("get_report")
        self.assertIsNotNone(t)
        self.assertEqual(t["name"], "get_report")
        self.assertFalse(t["requires_auth"])

    def test_mcp_tool_for_not_found(self):
        self.assertIsNone(ir.mcp_tool_for("nonexistent_tool"))


class ReconManifestSchemaTests(unittest.TestCase):
    def test_schema_loads(self):
        s = ir.recon_manifest_schema()
        self.assertIsInstance(s, dict)
        self.assertIn("$schema", s)
        self.assertEqual(s["title"], "Recon → Hunt Manifest")

    def test_schema_has_required_fields(self):
        s = ir.recon_manifest_schema()
        self.assertIn("required", s)
        self.assertIn("target", s["required"])


class EngagementExampleTests(unittest.TestCase):
    def test_engagement_loads(self):
        e = ir.engagement_example()
        self.assertIsInstance(e, dict)
        self.assertIn("name", e)
        self.assertEqual(e["name"], "demo-local")

    def test_engagement_has_scope(self):
        e = ir.engagement_example()
        self.assertIn("in_scope", e)
        self.assertIn("out_of_scope", e)


class PluginManifestTests(unittest.TestCase):
    def test_plugin_loads(self):
        p = ir.plugin_manifest()
        self.assertIsInstance(p, dict)
        self.assertEqual(p["name"], "claude-bughunter")

    def test_plugin_has_version(self):
        p = ir.plugin_manifest()
        self.assertIn("version", p)
        self.assertEqual(p["version"], "2.1.0")


class DesignDocsTests(unittest.TestCase):
    def test_design_docs_returns_list(self):
        docs = ir.design_docs()
        self.assertIsInstance(docs, list)
        self.assertEqual(len(docs), 4)

    def test_all_docs_have_required_fields(self):
        for d in ir.design_docs():
            self.assertIn("name", d)
            self.assertIn("type", d)
            self.assertIn("title", d)
            self.assertIn("body", d)
            self.assertIn(d["type"], ("plan", "spec"))

    def test_design_doc_for_found(self):
        d = ir.design_doc_for("2026-08-09-autopilot-ledger")
        self.assertIsNotNone(d)
        self.assertEqual(d["type"], "plan")
        self.assertIn("Autopilot Ledger", d["title"])

    def test_design_doc_for_not_found(self):
        self.assertIsNone(ir.design_doc_for("nonexistent"))

    def test_plans_and_specs_paired(self):
        docs = ir.design_docs()
        plans = [d for d in docs if d["type"] == "plan"]
        specs = [d for d in docs if d["type"] == "spec"]
        self.assertEqual(len(plans), 2)
        self.assertEqual(len(specs), 2)


if __name__ == "__main__":
    unittest.main()
