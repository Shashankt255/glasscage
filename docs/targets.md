# `glasscage.targets` — multi-surface application model

Additive Phase 1 foundation. Defines the drivable-surface contract that discovery and
driver PRs build on. Since [ADR 0002](adr/0002-engine-surface-wiring.md) the run
pipeline can optionally drive a CHAT surface, and since
[ADR 0012](adr/0012-rest-surface-execution.md) a REST surface; the default path is
unchanged.

## Concepts
- **`SurfaceKind`** — `CHAT, REST, GRAPHQL, FUNCTION, MCP_TOOL, RAG, VECTOR_DB`. `CHAT` and
  `REST` are exercised in this release; every other kind has no driver and is refused
  loudly rather than silently assessed at the wrong surface.
- **`Surface`** — a drivable thing: `id`, `kind`, `locator`, optional `io_schema`, a
  bound `Driver`. `surface.drive(action)` delegates to the driver.
- **`Driver`** (Protocol) — exercises a surface: `drive(surface, action) -> Observation`.
- **`Action`** — base request descriptor. Subtypes carry kind-specific data:
  | Action | Fields | Serves | Status |
  |---|---|---|---|
  | `PromptAction` | `prompt` | `CHAT` | Implemented |
  | `HttpAction` | `method`, `path`, `query`, `headers`, `body` | `REST`, later `GRAPHQL` | Implemented — consumed by `RestDriver` (ADR 0012) |
  | `ToolCallAction` | `name`, `arguments` | `MCP_TOOL`, `FUNCTION` | Experimental — no driver yet |

  `HttpAction` mirrors what discovery emits for a REST candidate (`{"method", "path"}`
  locator plus `io_schema`), so both halves of the pipeline agree by construction. It
  expresses **one request** and nothing more — authentication belongs to `AuthContext`,
  which a REST target carries and `RestDriver` consumes at the transport boundary
  ([ADR 0013](adr/0013-request-material-at-the-transport-boundary.md)); it is never placed
  in an `HttpAction`, because that would put the credential into `canonical_request` and so
  into custody, Finding identity, reproduction, HAR and the report —
  timeouts, retries, redirects, pagination and content negotiation belong to the driver.
  See [ADR 0007](adr/0007-action-model-generalisation.md).
- **`Observation`** — uniform interaction record; fields mirror `target.ChatResponse`
  (`text`, `ok`, `latency_ms`, `error`, `trace`) plus optional
  `request/response/status/custody_hash` for non-chat drivers.

  **Chain of custody** ([ADR 0008](adr/0008-driver-side-custody.md)): a driven observation
  carries the `request` that produced it and a `custody_hash` of
  `audit.sha256(request, response)` — the same helper and argument order the engine uses
  for `Finding.evidence_hash`. The two coexist by design: the finding hash is computed at
  the engine layer before redaction, the observation hash at the transport boundary, and
  neither is derived from the other. A transport failure still carries custody — what was
  sent is evidence regardless of outcome — but `Observation.failure()` does not, because
  no request occurred. **The driver hashes; it does not record:** `exchanges` and the
  audit chain remain the target's responsibility, so nothing is double-counted.
- **`ApplicationTarget`** — container of surfaces (and of discovered, unbound
  `SurfaceCandidate`s) sharing an `AuthContext` and optional `audit.Scope`. Pure data;
  performs no I/O.
- **`ChatSurface` / `ChatDriver`** — adapt an existing `HTTPChatTarget` to the model.
- **`SurfaceTarget`** (`compat.py`) — presents a bound Surface through the `send(prompt)`
  contract the run pipeline expects, delegating every other attribute to the origin
  target. `chat_surfaces_of()` resolves a Surface or ApplicationTarget to the CHAT
  surfaces to drive; `chat_surface_of()` is the first of them.

### Resolution contract
See [ADR 0009](adr/0009-surface-resolution-contract.md).

- `chat_surfaces_of(source)` returns **every** drivable CHAT surface. Non-CHAT surfaces
  are excluded; anything else is refused with `ConfigError`.
- Order is **registration order** — the sequence the operator added surfaces in — and is
  deliberately **not** sorted. This differs from `discovery`, which sorts candidates by
  id because a document has no inherent order; a registration list does, and it is the
  operator's.
- Duplicate ids collapse **first-wins**, preserving order. Defensive: `add_surface` is
  already idempotent by id, so duplicates arise only from constructing
  `ApplicationTarget(surfaces=[...])` directly.
- `chat_surface_of(source)` is exactly `chat_surfaces_of(source)[0]` and holds no logic
  of its own — every `ConfigError` originates in the plural form, so the two cannot
  drift. An application with several CHAT surfaces yields the first; ambiguity is not
  refused, because multi-surface execution is a later change.
- **Resolution does not validate ownership.** Declared ownership and governance are
  checked per surface when a `SurfaceTarget` is constructed (ADR 0005); resolution raises
  `ConfigError` and never `TargetError`.

## Surface discovery
`discovery.py` enumerates drivable candidates from an interface definition. Status:
**Experimental**, read-only. See [ADR 0003](adr/0003-surface-discovery.md).

| Entry point | Input | Emits |
|---|---|---|
| `discover_openapi(spec)` | OpenAPI document | one `REST` candidate per `paths` → HTTP method, `locator={"method","path"}`, `io_schema` from `parameters`/`requestBody`, `source="openapi"` |
| `discover_mcp(manifest)` | MCP `tools/list` manifest | one `MCP_TOOL` candidate per tool, `locator=<tool name>`, `io_schema` from `inputSchema`, `source="mcp"` |
| `discover(data)` | either | auto-detects: `paths` → OpenAPI, `tools` → MCP |

From the CLI, `--discover SPEC` runs the same enumeration standalone — no target, no
assessment — printing a table and writing `<out>_surfaces.md` / `<out>_surfaces.json`.
`discovery.to_markdown()` and `discovery.to_json()` render the inventory and are the
same renderers the CLI uses. See [COMMAND_REFERENCE](COMMAND_REFERENCE.md).

`ApplicationTarget.add_candidate()` registers a candidate (idempotent by id) and
`candidates_of(kind)` filters them. Candidate ids are `rest:<method>:<path>` and
`mcp_tool:<name>`; output is deduplicated and sorted, so the same document always yields
the same candidates in the same order.

**Discovery itself never binds.** A candidate is a proposal carrying provenance, not a
surface: it holds no Driver and `--discover` drives nothing. Promotion to a bound Surface is
a separate, explicit step — see *Surface binding* below.

## Surface binding
`binding.py` promotes a candidate to a bound `Surface`. See
[ADR 0014](adr/0014-surface-binding.md).

```python
candidates = discover_openapi(spec)
target = RestTarget("https://api.example/v1")
target.scope = Scope(["api.example"])          # ADR 0012: required and non-empty
for c in candidates:
    app.add_surface(bind_candidate(c, target))
```

- **`bind_candidate(candidate, target, surface_id=None) -> Surface`.** The bound surface
  keeps the candidate's id, so a finding's `surface_id` traces back to the discovered
  operation. The candidate's `locator` and `io_schema` are carried through unchanged.
- **Pure resolution.** No I/O, no target construction, no mutation. The caller supplies the
  target, because a bound surface must be bound to the target supplied to the engine
  (ADR 0002) and an application's controls are verified, never propagated (ADR 0011).
- **Refusals are `ConfigError`, never `TargetError`.** Ownership, governance and the
  fail-closed scope check stay at `SurfaceTarget` construction (ADR 0005, ADR 0012), so a
  candidate bound to a scopeless target binds and is refused there.
- **REST is the only bindable kind today.** Discovery emits `REST` and `MCP_TOOL`
  candidates; `MCP_TOOL` has no driver and is refused by name. This set is not the drivable
  set — `CHAT` is drivable but discovery emits no CHAT candidate.
- Promotion is a free function rather than an `ApplicationTarget` method, matching
  `chat_surface_from_target` and `rest_surface_from_target`: the container stores surfaces,
  it does not construct them.

From the CLI, `--rest-spec SPEC --rest-config FILE` performs exactly the sequence above —
discover, bind, register, drive — and `--scope` is mandatory there because ADR 0012 R1 is
enforced downstream at `SurfaceTarget` construction. `--discover` is unaffected and still
drives nothing. See [ADR 0015](adr/0015-cli-surface-exposure.md) and
[COMMAND_REFERENCE](COMMAND_REFERENCE.md).

This complements `schema.ingest` rather than replacing it: `schema.py` flattens
operations into capability records for schema-confirmed blast radius and drops the path,
method and parameters; discovery keeps exactly those. `schema.py` is unchanged.

**Limitations (deliberate):** `$ref` is not resolved — unresolved refs pass through into
`io_schema` verbatim; webhooks, callbacks and server-variable expansion are out of scope;
only `paths` → HTTP methods are enumerated. Empty documents yield an empty list;
malformed documents raise `ConfigError`; nothing is ever invented.

## Multi-surface execution
`Engine(target, surface=<ApplicationTarget>)` drives **every** registered CHAT surface.
See [ADR 0011](adr/0011-multi-surface-execution.md).

- **Order** is exactly `chat_surfaces_of()`'s output — registration order, never sorted
  (INV-1). The engine does not re-decide ordering.
- **Validate-all-before-traffic:** every surface's ownership and governance is checked up
  front, so a refusal aborts the run before any surface is probed (ADR 0005 across N).
- **`ApplicationTarget.scope`**, when set, is verified against every driven target; a
  mismatch raises `TargetError` pre-traffic. Verified, never propagated.
- **Per-surface recon:** each surface gets its own `ReconResult`. Probes read
  `tool_surface` and `model_hints` while assessing, and three derive findings entirely
  from recon, so a merged fingerprint would let one endpoint drive another's verdicts.
  Run-level recon is an order-preserving union.
- **Per-surface attribution and reproduction:** each finding carries its producing
  surface's `surface_id` and cites that surface's target in its reproduction steps.
- **Report identity:** an application run names `base_url`; a bare `Surface` or direct run
  names the target (discharges ADR 0005's deferral).
- **Failure:** an unreachable surface is skipped and named in `notes`; its siblings
  continue. If none is reachable the run completes with `reachable` false and every
  surface named, so it is distinguishable from a clean assessment (INV-4).
- **Attacker budget is `PER_SURFACE`** (INV-3): N surfaces perform N × budget evaluations.
  The effective total is reported in `results["tier"]`.
- **Shared state:** surfaces bound to the same target share that target's state. That is a
  property of the target, not of the orchestration.

## Driving a surface from the engine
`Engine(target, surface=...)` routes probe, recon and attacker traffic through the bound
surface instead of calling the target directly. Status: **Implemented** (CHAT only).

- `surface=` accepts a `Surface` or an `ApplicationTarget` (its first CHAT surface is
  used). Omit it and the pipeline behaves exactly as before.
- The `target` argument is still required. Ownership is **declared and governed**
  ([ADR 0005](adr/0005-declared-and-governed-ownership.md)):
  - every driver declares the target it drives as `.target`; one that declares nothing is
    refused with `TargetError`, because attribution that cannot be verified is treated as
    failed attribution;
  - the **driven** target is authoritative for attribution — capability tier and
    reproduction steps follow it, not the supplied target;
  - a driven target *different* from the supplied one is allowed, which is what makes
    future non-chat drivers possible — **provided** it is governed by the supplied
    target's operational controls. Where the supplied target sets `scope`, `rate` or
    `audit`, the driven target must present the same objects, or the run is refused
    before any traffic. Probing a target that never received the scope allowlist would
    test a host the operator never authorised.
  - The report header still names the supplied target (the assessment subject);
    per-finding provenance comes from `surface_id` and the reproduction steps.
  - Chain of custody and `--har` remain scoped to the supplied target. Driver-side
    custody is a later change.
- Probes receive an `Observation` rather than a `ChatResponse`. This needs no probe
  change — the two agree on every field any caller reads (`ok`, `text`, `error`, `trace`,
  `latency_ms`), and `Observation.raw` is an additive alias for `response` so plugin
  probes written against `ChatResponse.raw` keep working. See ADR 0002.
- Resolution failures (a surface kind with no driver, no drivable surface registered, wrong
  type) raise `ConfigError`. A REST target additionally requires a non-empty `Scope` and is
  refused with `TargetError` before any socket opens (ADR 0012), and a driven REST target
  that does not carry the supplied target's `AuthContext` is refused the same way
  (ADR 0013). Everything raised here is a `GlasscageError`.

### Probe applicability
Probes declare which surface kinds they can drive via `Probe.surface_kinds`, defaulting
to `(SurfaceKind.CHAT,)`. See [ADR 0006](adr/0006-probe-surface-applicability.md).

- The engine resolves the driven kind from the driven surface, defaulting to `CHAT` when
  no surface is bound.
- A probe that does not declare the driven kind is **never invoked** and yields one
  `NOT ASSESSABLE` finding naming the driven kind and the kinds it does drive — the same
  outcome shape an unmet `min_tier` produces.
- Applicability is checked **before** capability tier: being unable to drive a surface at
  all is more fundamental than lacking a capability on it.
- Set membership, not an ordinal like `min_tier` — surface kinds have no ordering.
- Probes that declare nothing are read as chat-applicable, so existing plugins are
  unaffected.
- `rest-response-disclosure` is the first registered probe declaring a non-CHAT kind. It is
  part of the default battery, so a chat run emits one `NOT ASSESSABLE` finding for it
  rather than omitting it and reporting coverage it has not earned (ADR 0012).

### Finding attribution
Findings produced by target interaction on a surface-driven run carry
`Finding.surface_id`, the id of the driven `Surface`. See
[ADR 0004](adr/0004-attribution-before-binding.md).

- **Attributed:** probe-loop findings, tier-gated `NOT ASSESSABLE` findings, and
  `--adaptive` / `--genetic` attacker findings.
- **Never attributed:** MCP-manifest findings (configuration review) and architecture
  answers (questionnaire). They are not observations on a surface, so tagging them would
  fabricate provenance.
- On a run without `surface=`, every `surface_id` is `""` and nothing else changes.
- Chain of custody, HAR export and reproduction steps still read the supplied target, not
  the surface. Moving those is a later, separate change.
- No CLI flag yet; this is a Python-API capability until a discovery PR lands.

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
`targets/` may import `audit`, `tal` and `errors` only. It must **not** import `engine`,
`probes`, or `aakg`; a test (`tests/test_targets_foundation.py`) enforces this at source
level. (`errors` is a dependency-free leaf module; `compat.py` imports it so failures at
the engine boundary raise the project's typed hierarchy rather than bare built-ins.)
