# ADR 0025 — Custody completeness at run exit

Status: Accepted · Phase 3 / PR #26

Closes the limitation recorded by [ADR 0024](0024-durable-before-visible-audit-commit.md).
Extends [ADR 0022](0022-harness-transport-custody.md), [ADR 0023](0023-transport-custody-exception-boundary.md)
and [ADR 0024](0024-durable-before-visible-audit-commit.md); amends none of them.
[ADR 0008](0008-driver-side-custody.md) §1 is untouched — who records does not change, and
neither does when a record becomes durable.

## Context
Three PRs established the counters this ADR relies on:

- **ADR 0022/0023** — every transport owner appends exactly one `exchanges` record per
  exchange it actually performed.
- **ADR 0024** — `AuditLog.record` commits durably before it commits in memory, so
  `audit.entries` holds exactly what reached disk.

ADR 0024 recorded what it had not closed:

> "A failed write still only surfaces as a `"probe … crashed"` note via `engine.py`'s
> per-probe isolation, and the run still exits 0. … What this ADR removes is the false
> claim and the corruption, not the quietness."

Measured on `v0.4.9-durable-audit-commit`, with the audit backend failing from write 5:

```
network calls   18
exchanges       18
audit entries    4    (== on disk; chain `verified`)
exit code        0
only signal      14 "probe ... crashed" notes inside the report JSON
```

The `Audit chain: verified (4 entries)` line was true — ADR 0024 made it true — but nothing
told the operator that 14 of 18 exchanges were absent. A security tool reported a
successful assessment while knowing its evidence trail was 78% incomplete.

The path is `AuditLog.record` → transport `_record` → probe → `engine.py:149-150`, where the
`OSError` is caught as an ordinary probe crash and the loop continues. The loss becomes
invisible there.

**The signal already existed.** `len(exchanges) == len(audit.entries)` was measured to hold
on every surface when custody succeeds — `--config` 21/21, `--demo` 21/21, `--harness`
25/25, `--rest-config` 6/6 — and to break by exactly the number lost when it does not.
Nothing had to be counted that was not already counted.

## Decision

### 1. Reconcile at run exit
After every artifact is written, compare `len(target.exchanges)` against
`len(target.audit.entries)`. A positive difference is custody loss.

### 2. Custody loss is established by reconciliation, never inferred from failure
A refused connection, an HTTP 500, a non-JSON body and a `response_path` failure each
append **one exchange and one entry**, so all reconcile to zero. Failure of the target is
not failure of custody, and the two must not be conflated: an assessment of a broken target
is still a sound assessment.

### 3. Fail closed, with exit 3
Incomplete custody returns **3**. Exit 2 already means *refused* — `GlasscageError` and
`ap.error` both use it — and a run that completed with incomplete custody is a different
outcome that scripts must be able to tell apart. Complete custody still returns 0.

### 4. Exactly one diagnostic, on stderr, naming the shortfall
One deterministic line, to stderr only, carrying the count lost, the total attempted and
the number that survived. It states that the target *was* assessed and that what failed is
chain of custody, so the message cannot be misread as target failure.

### 5. Artifacts are still written
The report, HTML, JSON, SARIF, replay bundle and HAR are produced before the check. The
assessment is sound; only its evidence trail is incomplete, and withholding the findings
would destroy work that is valid.

### 6. The engine is not touched
Execution is not aborted at the first custody failure, and `engine.py`'s per-probe
isolation is unchanged. Aborting mid-run would need `engine.py` and would kill a long
assessment over a transient blip. Reporting the truth at exit achieves fail-closed
semantics without touching the exception architecture.

## Security analysis
- **What this fixes:** a run that loses custody can no longer present as successful. The
  operator learns how much was lost, in one deterministic line, and the exit status carries
  it into any script or pipeline.
- **What it does not change:** ADR 0024's durable-before-visible ordering, memory/disk
  agreement, chain verification, ADR 0020 append/resume, exactly-once transport custody on
  all four surfaces, ADR 0021's control ordering, and the report/SARIF/replay/HAR outputs.
- **Accepted limitation — recon-time asymmetry.** A custody failure during recon runs
  outside `engine.py`'s per-probe handler and still propagates as an uncaught `OSError`
  (exit ≠ 0, no report). That is pre-existing behaviour, deliberately preserved and now
  pinned by test so it cannot drift. Making the two paths symmetric would require
  `engine.py`.
- **Accepted limitation — granularity.** Reconciliation reports *how many* exchanges were
  lost, not *which*. The lost exchanges left no durable record, so identifying them is not
  possible from the chain.
- **Accepted limitation — `fsync` / power-loss durability is out of scope.** As in
  [ADR 0024](0024-durable-before-visible-audit-commit.md), `fsync` is deliberately not
  introduced. Reconciliation compares what the process recorded against what it wrote; it
  makes no claim about the operating system losing a buffered write. That is a different
  failure model and remains a separate decision.
- **Accepted limitation — partial-line corruption is unchanged.** A write exhausting the
  disk mid-line can still leave a malformed line, exactly as
  [ADR 0024](0024-durable-before-visible-audit-commit.md) records. Such a line is reported
  as `TAMPERED` under [ADR 0019](0019-audit-chain-integrity.md), so it is detectable rather
  than silent. PR #26 neither prevents nor re-classifies it; the completeness check counts
  entries and does not alter how a malformed line is judged.

## Consequences
- **Positive:** incomplete custody is observable and machine-detectable at exit.
- **Behavioural change, intended:** a run with incomplete custody now exits 3 where it
  previously exited 0. This is a CLI contract change and is why the release carries a minor
  version bump.
- **Unchanged:** `audit.py`, `engine.py`, `target.py`, `refagent.py`, `targets/**`; the
  audit format, hashes and canonical form; every frozen invariant; and all four surface
  entry counts.
- **No migration.** No format, schema or API change.

## Rejected alternatives
1. **Abort at the first custody failure.** Rejected: needs `engine.py`, and a transient
   fault would destroy a long assessment that is otherwise valid.
2. **Fix it in `audit.py`.** Rejected: `AuditLog` cannot reach the operator. The only
   mechanism would be raising a non-`Exception` `BaseException` to evade the engine's
   handler — a trick, producing a traceback rather than a clean diagnostic.
3. **Fix it in `engine.py` by distinguishing custody exceptions.** Rejected: couples the
   engine to audit exception types, changes behaviour for every probe crash, and the engine
   owns neither the exit status nor the operator-facing summary.
4. **Warn without changing the exit status.** Rejected: a warning on stderr is invisible to
   the CI and scripting cases that most need it. Fail-closed means the status changes.
5. **Reuse exit 2.** Rejected: conflates *refused* with *completed but uncertified*.
