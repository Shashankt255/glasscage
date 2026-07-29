# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Schema ingestion for schema-confirmed blast radius.

The review flagged that blast radius rested on the model's self-reported tool
names (an unreliable narrator) classified by keyword. This module ingests the
*real* interface definition - OpenAPI, function-calling schema, or an MCP
tools/list - and derives a schema-confirmed tool surface with capability and
side-effect classification. Findings then distinguish self-reported from
schema-confirmed provenance, and impact scoring only trusts the latter.
"""

from __future__ import annotations

import json

_WRITE_VERBS = ("post", "put", "patch", "delete", "create", "update", "send",
                "delete", "write", "pay", "transfer", "remove", "execute", "run")
_READ_VERBS = ("get", "list", "read", "search", "query", "fetch", "lookup")
_CAP_KEYWORDS = {
    "exec": ("exec", "run", "shell", "code", "eval", "command"),
    "cred": ("secret", "key", "token", "credential", "vault", "password"),
    "network": ("url", "uri", "http", "fetch", "webhook", "callback"),
    "write": _WRITE_VERBS,
    "data": _READ_VERBS + ("sql", "db", "database", "file"),
}


def _classify(name: str, method: str, blob: str) -> tuple[str, bool]:
    low = f"{name} {method} {blob}".lower()
    for cap in ("exec", "cred", "write", "network", "data"):
        if any(k in low for k in _CAP_KEYWORDS[cap]):
            side_effect = cap in ("exec", "write", "cred")
            return cap, side_effect
    return "unknown", False


def _tool(name, capability, side_effect):
    return {"name": name, "capability": capability, "side_effect": side_effect,
            "provenance": "schema-confirmed"}


def from_openapi(spec: dict) -> list[dict]:
    tools = []
    for path, methods in (spec.get("paths") or {}).items():
        for method, op in (methods or {}).items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            name = (op.get("operationId") if isinstance(op, dict) else None) or f"{method} {path}"
            blob = json.dumps(op) if isinstance(op, dict) else ""
            cap, se = _classify(name, method, blob)
            tools.append(_tool(name, cap, se))
    return tools


def from_function_schema(schema) -> list[dict]:
    """OpenAI-style function/tool list: [{name, description, parameters}]."""
    items = schema if isinstance(schema, list) else schema.get("functions", schema.get("tools", []))
    tools = []
    for it in items:
        fn = it.get("function", it)
        name = fn.get("name", "<unnamed>")
        blob = json.dumps(fn)
        cap, se = _classify(name, "", blob)
        tools.append(_tool(name, cap, se))
    return tools


def from_mcp(manifest: dict) -> list[dict]:
    tools = []
    for t in manifest.get("tools", []):
        name = t.get("name", "<unnamed>")
        blob = json.dumps(t)
        cap, se = _classify(name, "", blob)
        tools.append(_tool(name, cap, se))
    return tools


def ingest(data: dict) -> list[dict]:
    """Auto-detect schema type and return schema-confirmed tools."""
    if not isinstance(data, (dict, list)):
        return []
    if isinstance(data, dict) and "paths" in data:
        return from_openapi(data)
    if isinstance(data, dict) and "tools" in data and all(
            "inputSchema" in t or "input_schema" in t for t in data.get("tools", []) or [{}]):
        return from_mcp(data)
    return from_function_schema(data)
