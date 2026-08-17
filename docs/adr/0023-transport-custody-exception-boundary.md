# ADR 0023 — The transport exception boundary excludes custody

Status: Accepted · Phase 3 / PR #24

Applies [ADR 0008](0008-driver-side-custody.md) §1 to `HTTPChatTarget`. Supersedes nothing.
No control's semantics, no audit format, no hash and no dependency changes.

## Context
[ADR 0008](0008-driver-side-custody.md) §1 settled who records:

> **The driver hashes; it does not record.** … Recording stays with whoever owns the
> transport.

Four components own a transport. Three had already converged on the same shape — the
transport `try/except` decides *what was exchanged*, then custody is recorded once, after
it:

| Owner | Transport `try/except` | Custody sites |
|---|---|---|
| `RestDriver.drive` | ends before recording | 1, outside |
| `ReferenceAgent.send` ([ADR 0022](0022-harness-transport-custody.md)) | none | 1, single return path |
| `_MockTarget.send` | none | 1 |
| `HTTPChatTarget.send` | **encloses recording** | **3** |

`HTTPChatTarget.send()` called `_record()` from *inside* the `try` whose broad
`except Exception` also calls `_record()`. A failure raised by custody itself was therefore
caught as though it were a transport fault. The handler then fabricated an `ok=False`
`ChatResponse` from the audit error text and recorded a **second** exchange for one network
call.

`AuditLog.record` advances `self.prev` and appends to `self.entries` before its file write,
so a write failure is not benign: the chain is already advanced when the exception escapes.

Measured on `v0.4.7-harness-transport-custody`, one network call:

```
audit.record raises      -> 2 exchanges, 0 audit entries
audit file write fails   -> 2 exchanges, 2 audit entries, chain still VERIFIED
                            entry 1 = digest of "[Errno 28] No space left on device"
                            exchange 1 = status 0, that OS error text as the response body
```

The integrity control cannot detect this: the chain is *internally* consistent, so
`check()` reports `verified`. What is false is the content — a fabricated exchange that
never happened, attested as custody.

Over a full CLI run with the disk filling mid-assessment: **18 network calls, 32 HAR
entries, 4 audit entries on disk**, `Audit chain: verified (32 entries)`, **exit 0**.

The controls were never in doubt: connection-refused, non-JSON body, HTTP 500 and a
`response_path` failure each produced exactly one exchange and one entry, before and after.
The broad handler does its job; only its extent was wrong.

## Decision

### 1. The transport handler assigns the outcome; it does not record
Each branch of the `try/except` binds `resp_obj`, `status`, `body_text` and `latency` and
nothing more. The block ends. `_record(...)` is then called **once**, followed by a single
`return`.

### 2. Exactly one custody site in `send()`
Three call sites became one. "Exactly once per exchange" is now structural rather than a
property to be re-established at each site, and is pinned by test against the source.

### 3. A custody failure propagates
`_record()` raising now escapes `send()` rather than being re-interpreted as a transport
fault. This matches `ReferenceAgent` and `RestDriver`, neither of which shields custody.
No fabricated response is manufactured for a failure that produced no exchange.

### 4. `status` and `body_text` are deliberately not pre-initialised
A future branch that forgets to bind one must fail loudly rather than silently record
default metadata against a real exchange.

### 5. This is not a redesign
`RestDriver.drive` has always had this shape. The change makes the oldest transport owner
consistent with the three written after it. ADR 0008 is applied, not amended.

## Security analysis
- **What this fixes:** one network call now yields exactly one exchange and one audit entry.
  A failing custody backend can no longer inject a fabricated exchange into the chain, and
  HAR can no longer over-report the traffic actually sent.
- **What it does not change:** `audit.py` is untouched, and with it `sha256`, the entry
  format, canonical serialization, `ENTRY_VERSION`, `ChainStatus`/`ChainResult` and
  `AuditLog.verify()`. Scope, rate and authorization are untouched. `ReferenceAgent`, REST
  and demo counts are unchanged. No new dependency; no new network path.
- **Recorded values are unchanged** on every path that already worked: success records the
  decoded body with the response status; `HTTPError` records `e.reason` with `e.code`; any
  other transport fault records `str(e)` with status 0.

## Known limitation — not closed by this ADR
An audit-write failure still leaves the in-memory chain one entry ahead of the file, and
[engine.py](../../glasscage/engine.py) catches per-probe exceptions (`"probe … crashed"`,
run continues, exit 0). A failing custody backend therefore still yields an on-disk log
that is silently incomplete while the CLI reports the in-memory chain as verified. That has
a **separate root cause** — `AuditLog.record`'s in-memory-before-disk ordering and the
engine's exception isolation — and fixing it requires `audit.py` and/or `engine.py`, both
outside this PR's approved scope. Recorded as follow-up work; this ADR makes no claim to
have addressed it. What it does remove is the doubling and the fabricated entries.

## Rejected alternatives
1. **Narrow the exception boundary around each of the three `_record()` calls.** Rejected:
   same fix, three sites instead of one, and the handler would still fabricate an
   `ok=False` response from the custody error before recording it.
2. **Make `_record()` idempotent.** Rejected on merit, not convenience: it suppresses a
   symptom while the control-flow fault remains, requires a dedup identity no entry carries,
   changes `_record`'s contract, and risks silently discarding a genuine second exchange.
3. **Move recording into the engine or a wrapper.** Rejected against ADR 0008 §1, which
   names driver-side recording as "silent corruption of the very thing custody exists to
   protect".

## Consequences
- **Positive:** the chat transport satisfies the same exact-once custody principle as the
  other three transport owners.
- **Behavioural change, intended:** a custody failure now propagates instead of producing a
  second, fabricated exchange. Every previously-working path is byte-unchanged.
- **Unchanged:** `audit.py`, `cli.py`, `engine.py`, `targets/**`, `refagent.py`; the audit
  format and append/resume semantics; graph identity, SARIF, replay bundle and runner,
  provenance, `runtime_coverage_ratio`, discovery output, benchmark determinism and the
  zero-dependency boundary — all verified against `v0.4.7-harness-transport-custody`.
- **No migration.** No format, schema or API change.
