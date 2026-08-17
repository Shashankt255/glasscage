# ADR 0024 — Durable before visible: the audit commit order

Status: Accepted · Phase 3 / PR #25

Constrains `AuditLog.record`'s commit order. Extends [ADR 0019](0019-audit-chain-integrity.md)
and [ADR 0020](0020-audit-log-append-semantics.md); amends neither. No format, no hash and
no dependency change. [ADR 0008](0008-driver-side-custody.md) §1 is untouched: who records
does not change, only when the record becomes visible.

## Context
`AuditLog.record` performed a non-atomic state transition:

```
entry["entry_hash"] = sha256(canonical_entry(entry))
self.prev = entry["entry_hash"]        # in-memory commit
self.entries.append(entry)             # in-memory commit
if self.path:
    with open(self.path, "a", ...) as fh:
        fh.write(json.dumps(entry) + "\n")   # durable commit, may fail
```

The in-memory chain committed **before** the durable write. A failed write therefore left
`prev` pointing at an entry that was never persisted. The next successful record chained
from that unpersisted hash and wrote a **gap** into the file.

Measured on `v0.4.8-transport-custody-exception`:

```
unit    : one failed write        -> in-memory 2, on-disk 1, prev != disk head
unit    : failure then success    -> on-disk chain `tampered`
                                     "entry 1 does not link to its predecessor"
CLI     : intermittent write fault -> 21 exchanges, 19 entries on disk,
                                      ON-DISK CHAIN `tampered`,
                                      CLI reported `verified (21 entries)`, exit 0
```

Two distinct outcomes followed from one cause. An **intermittent** fault produced a
corrupted chain; a **sustained** fault produced a silently truncated one. Both were
reported to the operator as `verified (N)`, because `cli.py` prints
`target.audit.check()` — the in-memory chain — and nothing reconciled it against the file.

The corrupted case is the serious one. ADR 0019's control correctly reported `tampered`
on a file that **the tool itself had gapped**, and [ADR 0020](0020-audit-log-append-semantics.md)
then refused to append to it, so the engagement's custody path became permanently
unusable. This is the same class of harm PR #21 corrected — the integrity control
accusing a correctly-used custody log — reintroduced through a different mechanism.

## Decision

### 1. Durable before visible
The append happens **before** `self.prev` and `self.entries` advance. Ordering only; the
entry, its `prev` linkage, the canonical form, the digests and the return value are
unchanged.

### 2. INV-25
> For a path-backed `AuditLog`, the in-memory chain never advances past what is durably on
> disk. After any `record()` — successful or failed — `len(self.entries)` equals the number
> of entries in the file and `self.prev` equals the file's head.

Corollary: `AuditLog.check()` and `verify_file(path)` agree, so the CLI's claim is true by
construction rather than by coincidence.

### 3. A failed write commits nothing
The `OSError` propagates unchanged. `prev` does not advance, `entries` does not grow, and
no in-memory-only custody entry exists. The exchange is simply absent from custody — the
file remains a **verifiable prefix**, never a gapped chain, and a later successful record
chains from the last persisted entry.

### 4. `path=None` is bit-identical
An in-memory-only log performs no write, so the reorder is unobservable there.

### 5. This is not a durability guarantee against power loss
`fsync` is deliberately **not** introduced. The defect is the process claiming more than it
wrote, not the operating system losing a buffered write. Adding `fsync` changes performance
characteristics and is a separate decision.

## Security analysis
- **What this fixes:** an audit-write failure can no longer corrupt the on-disk chain, and
  can no longer leave the process reporting a durable custody state that is not present on
  disk. A custody path that suffers a transient fault stays appendable under ADR 0020
  instead of becoming permanently unusable.
- **What it does not change:** `audit.sha256`, `evidence_hash`, `custody_hash`,
  `ENTRY_VERSION`, the canonical serialization, `ChainStatus`/`ChainResult`,
  `AuditLog.verify()`, ADR 0020 resume, and who records (ADR 0008 §1).
- **Accepted limitation — partial line.** A write exhausting the disk mid-line can still
  leave a malformed line. ADR 0019 already reports a malformed line as `TAMPERED` (PR #21),
  so it is detectable rather than silent. This ADR makes no claim to prevent it.
- **Accepted limitation — silence.** A failed write still only surfaces as a
  `"probe … crashed"` note via `engine.py`'s per-probe isolation, and the run still exits 0.
  Whether a custody failure should be fatal is a **policy** question about
  `engine.py`/`cli.py`, deliberately not decided here. What this ADR removes is the
  false claim and the corruption, not the quietness.

## Consequences
- **Positive:** custody on disk is always a chain that verifies; the in-memory count can no
  longer exceed it.
- **Behavioural change, intended:** after a failed write there is now **no** in-memory
  entry for that exchange, where previously there was one. Three assertions in
  `tests/test_chat_transport_custody.py` (PR #24) encoded the old count and were amended to
  match INV-25. Their transport-exchange assertions were left untouched: one network call
  is still one exchange, which is PR #24's contract and is unaffected.
- **Unchanged:** `cli.py`, `engine.py`, `target.py`, `refagent.py`, `targets/**`; the audit
  format and append/resume semantics; graph identity, SARIF, replay bundle and runner,
  provenance, `runtime_coverage_ratio`, discovery output, benchmark determinism and the
  zero-dependency boundary.
- **No migration.** Existing logs are read and continued exactly as before.

## Rejected alternatives
1. **Fix it in `engine.py` by not swallowing the exception.** Rejected: the corruption
   happens inside `record()` before the engine sees anything, so this fixes nothing. It
   would also couple the engine to audit exception types and change behaviour for every
   probe crash.
2. **Roll back `prev`/`entries` in an exception handler.** Rejected: same observable result
   as ordering, with a mutable-state window and a handler that must stay correct as the
   method evolves. Ordering makes the property structural.
3. **Buffer entries and flush at end of run.** Rejected: widens the loss window from one
   entry to the whole run and breaks ADR 0020's incremental append.
4. **Add `fsync` to make the write durable against power loss.** Rejected for this ADR: a
   different failure model, with performance consequences; see Decision §5.
