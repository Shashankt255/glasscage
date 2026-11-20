"""CBH integration reference: MCP tools, schemas, engagement, plugin, design docs."""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data"


def _load(name: str):
    with open(_DATA / name) as f:
        return json.load(f)


def mcp_tools() -> list[dict]:
    return _load("cbh_mcp_tools.json")["tools"]


def recon_manifest_schema() -> dict:
    return _load("cbh_recon_manifest_schema.json")


def engagement_example() -> dict:
    return _load("cbh_engagement_example.json")


def plugin_manifest() -> dict:
    return _load("cbh_plugin_manifest.json")


def design_docs() -> list[dict]:
    return _load("cbh_design_docs.json")["docs"]


def mcp_tool_for(name: str) -> dict | None:
    return next((t for t in mcp_tools() if t["name"] == name), None)


def design_doc_for(name: str) -> dict | None:
    return next((d for d in design_docs() if d["name"] == name), None)
