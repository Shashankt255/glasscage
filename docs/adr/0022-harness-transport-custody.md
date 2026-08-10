# ADR 0022 — The harness records its own custody

Status: Accepted · Phase 3 / PR #23

Applies [ADR 0008](0008-driver-side-custody.md) §1 to `ReferenceAgent`. Supersedes nothing;
no control's semantics, no format and no hash changes.

## Context
[ADR 0008](0008-driver-side-custody.md) §1 settled who records:

> **The driver hashes; it does not record.** … Recording stays with whoever owns the
> transport.

Three components own a transport and each records: `HTTPChatTarget.send()` →
`_record()` (`target.py`), `_MockTarget.send()` (`cli.py`), and `RestDriver.drive()`
(`targets/rest.py`) — for REST the driver *is* the transport, since `RestTarget` has no
send path of its own.

`ReferenceAgent` is the fourth. Its MRO is `[ReferenceAgent, object]`: it is not built on
`HTTPChatTarget`, so it inherits no `_record`, and ADR 0008 forbids `ChatDriver` from
recording on its behalf. It declared `scope`, `rate`, `audit` and `exchanges` and used
none of them.

The controls were wired correctly — [ADR 0021](0021-operational-controls-precede-traffic.md)
guarantees the CLI attaches them before any branch can drive the target. Measured on
`v0.4.6-controls-precede-traffic`, at the agent's first `send()`:

```
type(self.audit)  = AuditLog          <- a fully configured instance
agent.audit.path  = ...\audit.jsonl   <- the operator's path
AuditLog.record() = 0 calls, callers: NONE
```

25 exchanges were performed. The run wrote no log and no HAR, and reported:

```
Audit chain: verified (0 entries)     exit 0
```

`check_entries([])` returns `VERIFIED`, so an inert control and a genuinely silent run are
indistinguishable — the CLI asserted a positive integrity property over a chain that had
recorded nothing. ADR 0008's Context had already named this state: a component producing
"findings with no custody at all … is not an acceptable state to ship a driver into."

The gap predates every tag. `refagent.py` has one commit in its history (the initial
baseline) and `audit.record` appears in it at none of the 15 tags from `v0.1.0-phase1` to
`v0.4.6`. It is not a regression from PR #21 or PR #22.

**Findings are not a proxy for exchanges.** That same run produced 25 `send()` calls and 22
findings. Any accounting keyed on findings is wrong by construction.

## Decision

### 1. The agent records, because the agent owns the transport
`ReferenceAgent.send()` appends one entry to `self.exchanges` and, when `self.audit` is
set, calls `self.audit.record(self.url, prompt, text, ok)`. This is ADR 0008 §1 applied
unchanged, not a new rule.

### 2. Recording sits on the single return path
`send()` has one return. Placing the record immediately before it makes "exactly once per
exchange" structural rather than a property to be maintained by inspection, and lets the
recorded outcome be the response's own `ok` rather than a literal.

### 3. Custody is not manufactured
An exception raised before the response exists — a tool raising through `_ToolRouter.call`,
which does not catch — records nothing. There is no response to attest to
([ADR 0008](0008-driver-side-custody.md) §3). A record placed earlier would create custody
for an exchange that produced no result.

### 4. Nothing above the agent records
`ChatDriver` continues to hash only, so a surface-driven harness run reaches this line
exactly once, as a direct run does. This is what ADR 0008 §1 protects and it is why the fix
belongs here and not in a driver or orchestration layer: recording there would double-count
the audit chain and the HAR for **every** surface, which §1 calls "silent corruption of the
very thing custody exists to protect".

### 5. Scope and rate are deliberately left alone
`ReferenceAgent` is in-process with no network egress, exactly like `_MockTarget`, and
neither enforces `scope` or `rate`. That is consistent between the two in-process targets
and is out of scope here. Custody is not: `--demo` records and `--harness` did not, and
that inconsistency is what marks this one accidental.

## Security analysis
- **What this fixes:** a `--harness --audit-log` run now records one entry per exchange, the
  chain verifies, `--har` is written, and the CLI can no longer report `verified (0 entries)`
  for a run that performed 25 exchanges.
- **What it does not change:** every control's semantics, error types and exit codes; the
  entry format, canonical serialization and `audit.sha256`; and the counts produced by
  `--config`, `--demo` and `--rest-config`.
- **Severity, stated honestly:** medium. The harness is documented as a fixture whose output
  must not be treated "as evidence about a real system" (`COMMAND_REFERENCE.md`), and real
  engagement paths always recorded correctly. The defect is a false assurance on a
  non-evidentiary surface, not lost evidence on a real one.
- **Residual, unchanged:** a genuinely zero-exchange run still reports `verified (0 entries)`.
  Distinguishing "nothing was sent" from "custody was inactive" is a separate CLI output
  contract and is not decided here.

## Rejected alternatives
1. **Record in a common driver/orchestration layer.** Rejected on ADR 0008 §1's own
   reasoning: it double-counts the chain and the HAR for every surface, and would require
   removing recording from three working call sites at once.
2. **Leave the harness outside custody and make the CLI refuse to claim `verified`.**
   Rejected: leaves findings with no custody, which ADR 0008's Context calls unacceptable,
   fixes neither `--har` nor the missing log, and invents a new output contract.
3. **Make `ReferenceAgent` subclass `HTTPChatTarget` to inherit `_record`.** Rejected: it
   would inherit an HTTP transport it must override in full, coupling an in-process agent to
   a network adapter for one method.

## Consequences
- **Positive:** the documented promise — "one JSONL entry per request", "everything sent" —
  now holds on the harness surface, and `--har` works there.
- **Behavioural change, intended:** `--harness --audit-log` now writes entries where it
  previously wrote none, and `--harness --har` now writes a HAR. `--harness` without those
  flags is unchanged.
- **Made meaningful:** `tests/test_driver_custody.py::TestNoDoubleRecording` compared
  `0 == 0` and could not have detected double recording. Its subject is a `ReferenceAgent`,
  so it now compares real counts. The test itself is unmodified.
- **Unchanged:** `audit.sha256`, `evidence_hash`, `custody_hash`, `ENTRY_VERSION`, the
  canonical form, `ChainStatus`/`ChainResult`, `AuditLog.verify()`, `Finding` fields, graph
  identity, SARIF, the replay bundle and the byte-identical replay runner, provenance,
  `runtime_coverage_ratio`, discovery output, benchmark determinism, and the zero-dependency
  boundary — all verified against `v0.4.6-controls-precede-traffic`.
- **No migration.** No format, schema or API change; `audit.py` is untouched, and
  [ADR 0020](0020-audit-log-append-semantics.md)'s resume applies to harness logs
  automatically.
