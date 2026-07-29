# ADR 0003 — Read-only surface discovery

Status: Accepted · Phase 1 / Sprint 2 / PR #2

## Context
[ADR 0001](0001-surface-driver-foundation.md) defined `SurfaceCandidate` and stated that
"discovery modules (later Phase 1 PRs) emit these; the engine decides which to bind to a
Driver." [ADR 0002](0002-engine-surface-wiring.md) wired one bound CHAT surface into the
engine and listed discovery first among its follow-ups.

Two constraints shape what discovery can be today:

1. **ADR 0002's attribution guard.** A driven surface must be bound to the target
   supplied to the engine, or the run is refused — otherwise findings would cite a system
   that was never probed. Binding a *discovered* endpoint therefore cannot happen until
   per-surface attribution exists.
2. **Only `PromptAction` exists.** Every probe is prompt-shaped, so there is nothing that
   could drive a REST or MCP surface even if one were bound.

## Decision
Ship discovery as **read-only enumeration**. `targets/discovery.py` converts an OpenAPI
document or an MCP manifest into `SurfaceCandidate` records; `ApplicationTarget` gains a
candidate registry. Nothing is bound to a Driver, and no pipeline code consumes
candidates yet.

Output is deduplicated by id and sorted, so the same document always yields the same
candidates in the same order. Ids are `rest:<method>:<path>` and `mcp_tool:<name>` —
pinned by test, because anything that persists them later depends on the scheme.

## Why not extend `schema.py`
`schema.from_openapi` flattens every operation into
`{name, capability, side_effect, provenance}` and **discards the path, the HTTP method
and the parameter schema**. Those three fields are exactly what a driver needs and
exactly what `SurfaceCandidate` carries. The two modules answer different questions —
"what can this application do?" (capability, feeding schema-confirmed blast radius) versus
"where can it be driven?" (locator) — and merging them would force one answer to lose
information. `schema.py` is not modified and a test asserts its output is unchanged.

The method set (`get/post/put/patch/delete`) is duplicated rather than imported: the
layering rule keeps `targets/` from importing the analysis layer. The duplication is six
tokens and is noted at the definition site.

## Alternatives considered
1. **Bind discovered surfaces immediately.** Rejected: collides with ADR 0002's
   attribution guard, which is a closed decision.
2. **Add a REST driver in the same PR.** Rejected: requires a new `Action` kind on the
   frozen driver contract plus probe changes — a different, larger PR.
3. **Model candidates in the AAKG.** Rejected: the architecture is frozen against new
   node and edge types, and an unbound candidate is not evidence of anything.
4. **A function-schema fallback in `discover()`, mirroring `schema.ingest`.** Rejected: a
   function/tool list declares callables, not drivable locators. An unrecognized document
   is refused with `ConfigError` rather than reported as an empty surface set.

## Consequences
- **Positive:** the locator information `schema.py` destroys is now preserved; the driver
  and binding PRs have their input; zero risk to the run pipeline, which does not import
  this module.
- **Accepted:** candidates have no pipeline consumer until the binding PR. This is the
  second deliberately-unconsumed addition to `targets/`, and it is bounded — the guard in
  ADR 0002 makes consumption impossible today, not merely unimplemented. Marked
  **Experimental** until then.
- **Scope limits, deliberate:** `$ref` is not resolved (unresolved refs pass through into
  `io_schema` verbatim); webhooks, callbacks and server-variable expansion are out of
  scope; only `paths` → HTTP methods are enumerated.
- **Honesty:** empty documents yield an empty list; malformed documents raise
  `ConfigError`; an operation absent from the input is never emitted; a tool with no
  usable name is skipped rather than given an invented one.
- **Follow-up (not this PR):** per-surface attribution, then binding and non-chat drivers.

## Note for the next PR
`schema.from_openapi` raises `AttributeError` on a path whose value is not an object
(e.g. `{"paths": {"/x": "oops"}}`). Observed while writing the non-regression test.
Pre-existing, out of scope here, and worth its own issue — `discovery.py` skips such
entries.
