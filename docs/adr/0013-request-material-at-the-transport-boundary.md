# ADR 0013 — Request material at the transport boundary

Status: Accepted · Phase 2 / PR #13

Closes the second of the two fields [ADR 0001](0001-surface-driver-foundation.md) declared
on `ApplicationTarget` without a reader. [ADR 0011](0011-multi-surface-execution.md) closed
the first (`scope`); this closes `auth`. Supersedes nothing.

## Context
`ApplicationTarget.auth` held an `AuthContext` — scheme, headers, cookies — and no
production code read it. Three documents assign authentication to it:
[ADR 0007](0007-action-model-generalisation.md) excludes auth from `HttpAction` *because*
`AuthContext` owns it; `targets/driver.py` and `docs/targets.md` repeat the assignment. That
exclusion is only sound if something consumes `AuthContext`. Nothing did.

The consequence was worse than the `scope` gap ADR 0011 closed. A missing scope meant a
control silently unenforced. A missing auth meant the assessment silently did not happen: a
REST run against an authenticated API returns 401s, which the probe reports as
`Status.ERROR` — a transport error with no diagnostic naming the cause.

ADR 0011 established *"verified, never propagated"* for `ApplicationTarget.scope`. Whether
that discipline governed `auth` was genuinely undetermined by the repository: ADR 0001 says
the material is held *"for use by drivers"*, which implies consumption, while ADR 0011's
rule implies verification alone. The two readings imply different designs.

## Decision

### `AuthContext` is request material, not an operational control
ADR 0011's "verify, never propagate" governs **operational control objects** — `scope`,
`rate`, `audit`, the tuple `compat._CONTROLS` names. Each of those *enforces* something, and
enforcement stays inside the target that owns it. `AuthContext` is material that is *sent*.
The distinction is the load-bearing one in this ADR: it is why consumption here does not
contradict ADR 0011, and why `auth` is deliberately **not** added to `_CONTROLS`.

### Consumption happens at the REST transport boundary, and nowhere else
`RestDriver` merges the target's `AuthContext` headers into the outbound request at the one
point where `RestTarget.headers` is already merged. `canonical_request` is built from the
`Action` alone, so a credential supplied this way never reaches the canonical form.

That single placement discharges the whole prohibition list by construction, because custody,
Finding identity, reproduction, `exchanges`, HAR and the audit chain are all computed over
the canonical form. Credentials shall not appear in: `HttpAction` · `canonical_request` ·
`Observation.request` · custody · Finding identity · reports · replay · HAR · evidence ·
exception messages · audit logs · debug output.

### Precedence: auth is the floor
`{**auth, **target.headers, **action.headers}`. An explicit per-target or per-request header
always overrides application-level credentials.

### CHAT is not extended
`HTTPChatTarget` documents `headers` as the place to put auth tokens and already works. The
CHAT path is untouched, and a test asserts `HTTPChatTarget` has no `auth` attribute so the
boundary cannot erode silently.

### Parity verification, in addition and never instead
A driven target that does not carry the supplied target's `AuthContext` is refused with
`TargetError` before any traffic. This catches credentials attached to the supplied target
but not to the one actually driven. It is a separate function from `_verify_governance`,
because that guards enforcement objects and this guards material.

### Credential-bearing fields are excluded from `repr`
A dataclass renders every field, so `f"{app}"` emitted the bearer token in cleartext — see
the defect note below. `scheme` is retained because it names the mechanism without
disclosing material.

## Alternatives considered
1. **Verify-only, by parity with `scope`.** Rejected: a no-op here. `Scope.check()` is
   invoked inside `send()`; nothing would invoke `AuthContext`, so this asserts correct
   wiring while still authenticating nothing.
2. **Merge auth into `action.headers`.** Rejected, decisively: it places the credential in
   `canonical_request` and therefore in Finding identity, custody input, reports and HAR.
   `redaction` matches `SECRET_PATTERNS` — API-key and password shapes — which **does not
   match a bearer token**, so such a leak would be unrecoverable.
3. **Extend the `Driver` protocol with an auth parameter.** Rejected: ADR 0001 froze the
   contract and ADR 0007 treats the Action field sets as frozen.
4. **Declare `AuthContext` advisory and document it as unread.** Rejected: leaves the silent
   failure intact and contradicts three documents that assign auth ownership to it.
5. **Remove `AuthContext`.** Rejected: ADR 0007's `HttpAction` exclusion depends on it.

## Consequences
- **Positive:** a declared field gains its reader; a REST assessment against an authenticated
  API works; misattached credentials are refused loudly rather than producing 401s reported
  as transport errors; a cleartext credential leak through `repr` is closed.
- **Unchanged:** everything. The default path is byte-identical to `v0.3.1-rest-runtime` —
  benchmark, `runtime_coverage_ratio`, replay, SARIF, chat findings including
  `evidence_hash`, custody, graph identity and determinism, verified by tree comparison
  rather than assertion. No existing test required modification.
- **Accepted:** `RestTarget.headers` and `AuthContext.headers` are now two channels for the
  same thing. Precedence is defined and tested; the existing channel is not removed.
- **Deliberately out of scope:** `AuthContext.cookies` has no transport mapping in
  `RestDriver` and the repository states no intended one; `AuthContext.scheme` is declared
  with example values but no behaviour. Both are carried unread rather than given invented
  semantics. Extending `SECRET_PATTERNS` to cover bearer tokens would change a detector
  shared by `benchmark`, `redaction` and both disclosure probes, and belongs to its own PR.
- **Follow-up (not this ADR):** surface binding; CLI exposure; `diff.py` comparison-key
  alignment; MCP runtime, GraphQL and function drivers.

## Defect found on the baseline
`AuthContext` and `ApplicationTarget` are dataclasses with generated `repr`. On
`v0.3.1-rest-runtime`, `repr(ApplicationTarget(auth=AuthContext(headers={...})))` emitted
the bearer token and session cookie in cleartext, so any log line, f-string or exception
message embedding an application target disclosed live credentials. Pre-existing and
independent of this PR's feature work; fixed here because it is the mechanism by which auth
would reach exception messages and debug output. The regression test fails against the
baseline.
