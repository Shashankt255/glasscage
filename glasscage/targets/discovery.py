# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Surface discovery: enumerate drivable candidates from an interface definition.

Status: Experimental. Read-only.

Discovery answers "where can this application be driven?" and emits `SurfaceCandidate`
records carrying the locator, HTTP method and I/O schema of each operation. That is a
different question from the one `schema.py` answers — `schema.ingest` flattens every
operation into `{name, capability, side_effect, provenance}` for schema-confirmed blast
radius and deliberately discards path, method and parameters. Both are needed; neither
replaces the other, and this module does not change `schema.py` or its output.

**Candidates are never bound to a Driver here.** A bound surface must be bound to the
target supplied to the engine (ADR 0002), so binding a discovered endpoint cannot happen
until per-surface attribution exists. Discovery produces the input that work needs.

No network, no filesystem: callers pass already-parsed JSON, exactly as `schema.ingest`
expects it. Output is deduplicated by id and sorted, so the same document always yields
the same candidates in the same order.

Scope limits (deliberate, see ADR 0003): `$ref` is not resolved — unresolved refs pass
through into `io_schema` verbatim; webhooks, callbacks and server-variable expansion are
out of scope; only `paths` -> HTTP methods are enumerated.
"""

from __future__ import annotations

from typing import Any

from ..errors import ConfigError
from .surface import SurfaceCandidate, SurfaceKind

# Mirrors the method set `schema.from_openapi` accepts. Duplicated rather than imported:
# `targets/` may not import the analysis layer (layering rule, enforced by test).
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _finalize(candidates: list[SurfaceCandidate]) -> list[SurfaceCandidate]:
    """Deduplicate by id (first wins) and sort by id, so discovery is deterministic."""
    seen: dict[str, SurfaceCandidate] = {}
    for c in candidates:
        seen.setdefault(c.id, c)
    return sorted(seen.values(), key=lambda c: c.id)


def discover_openapi(spec: Any) -> list[SurfaceCandidate]:
    """Enumerate REST candidates from an OpenAPI document.

    One candidate per `paths` -> HTTP method operation. `locator` is
    `{"method": "GET", "path": "/x"}`; `io_schema` carries the operation's `parameters`
    and `requestBody` when present. Operations with an unsupported method, and entries
    that are not objects, are skipped rather than guessed at.
    """
    if not isinstance(spec, dict):
        raise ConfigError(f"OpenAPI document must be an object, got {type(spec).__name__}")
    paths = spec.get("paths")
    if paths is None:
        raise ConfigError("OpenAPI document has no 'paths' object")
    if not isinstance(paths, dict):
        raise ConfigError(f"OpenAPI 'paths' must be an object, got {type(paths).__name__}")

    found: list[SurfaceCandidate] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, op in operations.items():
            if not isinstance(method, str) or method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                continue
            io: dict[str, Any] = {}
            if "parameters" in op:
                io["parameters"] = op["parameters"]
            if "requestBody" in op:
                io["requestBody"] = op["requestBody"]
            found.append(SurfaceCandidate(
                id=f"rest:{method.lower()}:{path}",
                kind=SurfaceKind.REST,
                locator={"method": method.upper(), "path": path},
                io_schema=io or None,
                source="openapi",
            ))
    return _finalize(found)


def discover_mcp(manifest: Any) -> list[SurfaceCandidate]:
    """Enumerate MCP tool candidates from an MCP `tools/list` manifest.

    `locator` is the tool name; `io_schema` is the tool's declared input schema
    (`inputSchema` or `input_schema`). A tool with no usable name is skipped: there is
    nothing to drive, and inventing a name would fabricate a surface.
    """
    if not isinstance(manifest, dict):
        raise ConfigError(f"MCP manifest must be an object, got {type(manifest).__name__}")
    tools = manifest.get("tools")
    if tools is None:
        raise ConfigError("MCP manifest has no 'tools' list")
    if not isinstance(tools, list):
        raise ConfigError(f"MCP 'tools' must be a list, got {type(tools).__name__}")

    found: list[SurfaceCandidate] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        found.append(SurfaceCandidate(
            id=f"mcp_tool:{name}",
            kind=SurfaceKind.MCP_TOOL,
            locator=name,
            io_schema=tool.get("inputSchema") or tool.get("input_schema"),
            source="mcp",
        ))
    return _finalize(found)


def discover(data: Any) -> list[SurfaceCandidate]:
    """Auto-detect the document type and discover its surfaces.

    Dispatch mirrors `schema.ingest`: `paths` means OpenAPI, `tools` means MCP. Unlike
    `schema.ingest` there is no function-schema fallback — a function/tool list declares
    callables, not drivable locators — so an unrecognized document is refused rather than
    reported as an empty surface set.
    """
    if isinstance(data, dict):
        if "paths" in data:
            return discover_openapi(data)
        if "tools" in data:
            return discover_mcp(data)
    raise ConfigError(
        "unrecognized document: expected an OpenAPI document ('paths') or an MCP "
        f"manifest ('tools'), got {type(data).__name__}")


_NOTE = "_Experimental. Candidates are not bound to a driver and are not driven._"


def _render_locator(candidate: SurfaceCandidate) -> str:
    """Human-readable locator: 'POST /v1/chat' for REST, the tool name for MCP."""
    loc = candidate.locator
    if isinstance(loc, dict):
        return f"{loc.get('method', '')} {loc.get('path', '')}".strip()
    return str(loc)


def to_json(candidates: list[SurfaceCandidate]) -> list[dict]:
    """Serialize candidates to plain JSON-safe dicts, preserving discovery order."""
    return [{"id": c.id, "kind": c.kind.value, "locator": c.locator,
             "io_schema": c.io_schema, "source": c.source} for c in candidates]


def to_markdown(candidates: list[SurfaceCandidate]) -> str:
    """Render the surface inventory as a deterministic ASCII markdown table.

    An empty inventory says so explicitly rather than emitting an empty table: a
    document with no drivable operations is a result, not a rendering failure.
    """
    lines = ["# GLASSCAGE Surface Inventory", ""]
    if not candidates:
        lines += ["No surfaces discovered.", "", _NOTE]
        return "\n".join(lines)
    lines += ["| Surface | Kind | Locator | Source |", "|---|---|---|---|"]
    for c in candidates:
        lines.append(
            f"| {c.id} | {c.kind.value} | {_render_locator(c)} | {c.source} |")
    lines += ["", f"{len(candidates)} surface(s) discovered.", "", _NOTE]
    return "\n".join(lines)
