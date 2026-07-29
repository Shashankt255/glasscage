# ADR 0008 — Driver-side chain of custody

Status: Accepted · Phase 2 / Sprint 1 / PR #8

## Context
[ADR 0001](0001-surface-driver-foundation.md) declared `Observation.custody_hash` so that
custody would generalise beyond chat. Seven PRs later nothing had ever populated it.

The accepted Phase 1 Foundation Review identified this as the **only remaining
evidence-integrity gap** and made closing it a condition of beginning driver work:
`HTTPChatTarget.send()` records into its own `exchanges` and writes the audit chain, so a
future REST or MCP driver — which has no `HTTPChatTarget` behind it — would produce
findings with no custody at all. In a tool whose central claim is evidence discipline,
that is not an acceptable state to ship a driver into.

## Decision
The driver attaches custody to every observation it produces.

`_to_observation` receives the request that produced the response and populates
`Observation.request` and `Observation.custody_hash`, the latter with
`audit.sha256(request, response_text)` — the **same helper and the same argument order**
the engine already uses for `Finding.evidence_hash`.

Three boundaries define the decision:

1. **The driver hashes; it does not record.** `HTTPChatTarget.send()` already appends to
   `exchanges` and calls `audit.record`. A driver doing either would double-count the
   audit chain and the HAR export — silent corruption of the very thing custody exists to
   protect. Recording stays with whoever owns the transport.
2. **Transport failures carry custody.** A `ChatResponse` with `ok=False` is the result of
   a request that really was sent; what was sent is evidence regardless of the outcome.
3. **`Observation.failure(...)` carries none.** No request occurred, so there is nothing
   to attest. Populating it would manufacture custody for an interaction that never
   happened.

## Two custody hashes, deliberately
`Finding.evidence_hash` and `Observation.custody_hash` now coexist. They are not
duplicates:

| | `Finding.evidence_hash` | `Observation.custody_hash` |
|---|---|---|
| Layer | engine, post-enrichment | driver, at the transport boundary |
| Input | `raw_request` / `raw_response` on the finding | the exact request and response text |
| Computed | before redaction, over one finding | per interaction, including ones that yield no finding |

Deriving one from the other was rejected: it would change `evidence_hash` values and break
the serialization stability every prior PR has preserved. The engine is untouched.

## Alternatives considered
1. **Have the driver call `audit.record`.** Rejected — double-counting (boundary 1).
2. **Have the engine consume `Observation.custody_hash` for `evidence_hash`.** Rejected —
   changes serialized values for no gain.
3. **Populate custody in `Observation.failure`.** Rejected — fabricates custody for an
   interaction that never occurred, and would break an existing test that correctly
   asserts the opposite.
4. **Wait for the first non-chat driver.** Rejected — the Review made closing the gap a
   precondition, and closing it now means the driver is written against a contract that
   already demands custody rather than retrofitting one.

## Consequences
- **Positive:** the last evidence-integrity gap identified in the Phase 1 Review is closed,
  while it is still unreachable in production. A field dead since ADR 0001 is retired.
  Every future driver inherits an explicit custody obligation.
- **No serialization, reporting, AAKG or CLI impact.** `Observation` is transient and is
  never persisted — verified: no reference in `report.py`, `sarif.py`, `aakg/*` or
  `evidence.py`. Reports, SARIF, replay bundles, HAR and the graph are byte-identical.
- **First use of the `targets → audit` import**, which the layering rule has permitted
  since ADR 0001 but which nothing had exercised.
- **Accepted risk:** `Observation.request` holds unredacted prompt text in a transient
  object. This is safe today because observations are never persisted, and the hash itself
  discloses nothing. **Any future PR that persists an `Observation` must apply `redaction`
  first.** Recorded here because that requirement is not enforceable by the type system.
- **Follow-up (not this PR):** multi-surface iteration, then the REST and MCP drivers;
  binding last.
