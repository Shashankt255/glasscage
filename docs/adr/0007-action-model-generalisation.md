# ADR 0007 — Action model generalisation

Status: Accepted · Phase 2 / Sprint 1 / PR #7

## Context
[ADR 0001](0001-surface-driver-foundation.md) defined `Action` as a "base request
descriptor handed to a driver; subtypes carry kind-specific data", and shipped exactly
one subtype: `PromptAction`, carrying a single `prompt: str`.

The same ADR designed `Observation` with `request`, `response`, `status` and
`custody_hash` so the **response** side would generalise beyond chat without rework. That
foresight held: no change to `Observation` has been needed across six PRs. Only the
**request** side was missing.

That gap is now the binding constraint. A REST driver cannot be written without a way to
express method, path and body; an MCP driver cannot be written without tool name and
arguments. The accepted Phase 1 Foundation Review ranked the action model third by
architectural value and called it "irreplaceable — no substitute exists"; with the
ownership guard ([ADR 0005](0005-declared-and-governed-ownership.md)) and probe
applicability ([ADR 0006](0006-probe-surface-applicability.md)) merged, it is the highest
remaining item.

## Decision
Add two additive `Action` subclasses:

- **`HttpAction`** — `method`, `path` required; `query`, `headers`, `body` optional. Serves
  `REST` and, later, `GRAPHQL` surfaces.
- **`ToolCallAction`** — `name` required, `arguments` optional. Serves `MCP_TOOL` and
  `FUNCTION` surfaces.

`Action`, `PromptAction`, `Observation` and the `Driver` protocol are unchanged. Both new
classes are pure data records: no validation, no driver logic, no I/O.

**Two kinds, not one envelope.** A tool call has no path or method; an HTTP request has no
tool name. A single generic record would make every field optional, which is the same as
carrying no contract at all — and it would push the "which fields apply here?" question
into every driver.

**The `HttpAction` shape is derived, not invented.** `discovery` already emits a REST
`SurfaceCandidate` whose locator is `{"method", "path"}` alongside an `io_schema` built
from `parameters` and `requestBody`. `HttpAction` describes exactly that data, so the two
halves of the pipeline agree by construction rather than by convention.

**Deliberately minimal.** `HttpAction` expresses *one request*. Explicitly excluded:
authentication (belongs to `AuthContext`), timeouts, retries, redirect policy, pagination,
content negotiation, and connection reuse — all of which belong to the driver that
performs the request, not to the description of the request.

**Per-instance mutable defaults.** `query`, `headers` and `arguments` use
`field(default_factory=dict)`; a shared class-level dict would leak state between actions.
Asserted by test.

## Alternatives considered
1. **One generic `RequestAction` with an untyped payload.** Rejected: every field becomes
   optional and meaningless, and type information the driver needs is lost.
2. **Deferring until the first driver is written.** Rejected: the driver PR would then
   carry both the request model and the transport, making it un-reviewable — the same
   coupling ADR 0001 rejected for `target.py`.
3. **Adding validation** (legal HTTP methods, path shape). Rejected: these are data
   records. A driver validates what it can actually perform; a record that rejects input
   would duplicate that judgement in the wrong layer.
4. **Modelling GraphQL separately.** Deferred: a GraphQL request is an HTTP POST with a
   structured body, which `HttpAction` already expresses. Revisit only if a GraphQL driver
   proves otherwise.

## Consequences
- **Positive:** the REST driver, the MCP driver, driver-side custody
  (`Observation.custody_hash` needs a request to hash) and non-chat reproduction are all
  now writable against a stable request shape.
- **No behaviour change.** Nothing constructs these actions. `ChatDriver` already returned
  `Observation.failure` for a non-`PromptAction`, so the only reachable effect on existing
  code is a failure path that already existed and was already tested.
- **Safe to add now because of ADR 0006.** The applicability gate means a prompt-shaped
  probe can never be handed a non-chat surface, so the new kinds cannot reach code that
  would misinterpret them. Adding them before that gate would have been a live hazard.
- **Accepted:** this is the fifth consecutive preparation layer in `targets/` and is stated
  plainly. Unlike binding, it is irreplaceable and blocks four downstream items. Marked
  **Experimental** until a driver consumes it.
- **Accepted:** the field shape becomes a de facto contract before any driver validates it.
  Mitigated by deriving it from what `discovery` emits, and by keeping it minimal enough
  that a driver is unlikely to need less.
- **Follow-up (not this PR):** driver-side custody, multi-surface iteration, then the REST
  and MCP drivers; binding last.
