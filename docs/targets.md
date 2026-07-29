# `glasscage.targets` — multi-surface application model

Additive Phase 1 foundation. Defines the drivable-surface contract that discovery and
driver PRs build on. Not yet consumed by the run pipeline.

## Concepts
- **`SurfaceKind`** — `CHAT, REST, GRAPHQL, FUNCTION, MCP_TOOL, RAG, VECTOR_DB`. Only
  `CHAT` is exercised in this release.
- **`Surface`** — a drivable thing: `id`, `kind`, `locator`, optional `io_schema`, a
  bound `Driver`. `surface.drive(action)` delegates to the driver.
- **`Driver`** (Protocol) — exercises a surface: `drive(surface, action) -> Observation`.
- **`Observation`** — uniform interaction record; fields mirror `target.ChatResponse`
  (`text`, `ok`, `latency_ms`, `error`, `trace`) plus optional
  `request/response/status/custody_hash` for non-chat drivers.
- **`ApplicationTarget`** — container of surfaces sharing an `AuthContext` and optional
  `audit.Scope`. Pure data; performs no I/O.
- **`ChatSurface` / `ChatDriver`** — adapt an existing `HTTPChatTarget` to the model.

## Example
```python
from glasscage.targets import ApplicationTarget, ChatSurface, PromptAction
from glasscage.target import HTTPChatTarget

app = ApplicationTarget(base_url="https://bot.example")
app.add_surface(ChatSurface(HTTPChatTarget(cfg), surface_id="chat"))
obs = app.surfaces_of(app.surfaces[0].kind)[0].drive(PromptAction(prompt="hello"))
assert obs.ok  # Observation mirrors the underlying ChatResponse
```

## Layering rule
`targets/` may import `audit` and `tal` only. It must **not** import `engine`, `probes`,
or `aakg`; a test (`tests/test_targets_foundation.py`) enforces this at source level.
