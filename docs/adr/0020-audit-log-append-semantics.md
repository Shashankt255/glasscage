# ADR 0020 — Audit-log append semantics

Status: Accepted · Phase 3 / PR #21

Extends [ADR 0019](0019-audit-chain-integrity.md). Supersedes nothing; every guarantee and
every accepted limitation recorded there is unchanged.

## Context
`--audit-log` is documented as *"path to **append-only**, hash-chained JSONL audit log"*
(`cli.py`), and `AuditLog`'s own docstring says *"Append-only, hash-chained JSONL audit
trail"*. Appending across runs is the stated design.

`AuditLog.__init__` did not implement it. It set `self.prev = "0" * 64` unconditionally and
never read the file, so a second run wrote a **second chain** into the same file, beginning
again at genesis. Measured on `v0.4.4-audit-integrity`, two `--demo` runs to one log:

```
audit lines = 42  ->  verify_file: tampered
detail: entry 21 does not link to its predecessor
```

The integrity control was **accusing a correctly-used custody log of tampering**. That is a
worse failure than silence: an operator maintaining one custody file across an engagement —
exactly what "append-only" invites — is told their evidence was altered, which devalues
every true positive the control will ever report.

This was not introduced by ADR 0019. The broken on-disk linkage had existed since the flag
shipped; nothing read the file back until ADR 0019 added `verify_file`, which made it
visible. The verifier was working correctly.

## Decision

### 1. A log file is one append-only chain
Opening an existing file resumes that chain rather than starting another. Segmentation,
rotation, migration and recovery are all explicitly **not** introduced.

### 2. The existing chain is verified before it is trusted
The head is adopted only after every prior entry has been recomputed under ADR 0019's v2
rules. Resuming from an unverified head would let a single altered entry silently anchor
everything appended afterwards.

### 3. State transitions
| Existing file | Behaviour |
|---|---|
| no path, or file absent | start at genesis |
| present but empty, or blank lines only | start at genesis |
| verifies as v2 | **resume**: load the verified entries, seed `prev` from the verified head |
| tampered | **refuse** — `ConfigError`, nothing written |
| legacy v1 / unverifiable | **refuse** — `ConfigError`, nothing written |

### 4. Refusal is loud, and offers nothing else
`errors.ConfigError` is an existing `GlasscageError`, so `cli.py`'s existing handler turns
it into `error: …` and exit 2 — the same refusal path `discovery`, `schema` and `compat`
already use. No new error type is added.

A refused open **writes nothing**: no partial entry, no sibling file, no backup. The message
names the path and tells the operator to write this run elsewhere and keep the existing file
for investigation. **The consequence is accepted deliberately: a tampered or legacy log path
becomes unusable.** Every softer option — rotate, migrate, repair, start a segment — is a
mechanism this repository does not have, and inventing one to smooth over a failed integrity
check would defeat the control.

### 5. Prior entries are loaded into memory
`self.entries` holds the verified prior entries plus this run's. This keeps
`check_entries`'s contract untouched: it verifies a whole chain from genesis, and it would
report `TAMPERED` for an in-memory list whose first entry carried a non-genesis `prev`. The
alternative — seeding `prev` alone — would have required changing that contract.

The one observable effect is that the CLI's entry count reports the whole file rather than
the current run. For a log documented as append-only that is the correct reading, and
`cli.py` needs no change to produce it.

### 6. A JSONL line that is valid JSON but not an object is tampering
`check_entries` guards this before touching any field. `verify_file` already promised *"a
malformed line is reported as tampering rather than skipped"*; a bare array, string or
number reached a field access and raised `AttributeError` instead. The guard sits in
`check_entries` so both callers inherit one rule.

## Security analysis
- **What resuming proves:** the pre-existing chain is internally consistent under ADR 0019
  v2 — every entry's digest matches its own canonical form and every link matches its
  predecessor. An attacker who altered any recorded field is detected and the run refuses
  before writing.
- **What it does not prove:** that nothing was **removed**. [ADR 0019](0019-audit-chain-integrity.md)
  §8 already accepts this — a forward chain can be recomputed end to end by whoever can
  write the file, so a truncated-then-recomputed file is indistinguishable from an intact
  one. Resuming inherits that boundary exactly: it neither widens nor narrows it, and this
  ADR makes no truncation claim.
- **Net effect:** a strict improvement. Previously a tampered log was silently appended to,
  compounding the damage; now the run stops before writing.

## Rejected alternatives
1. **Segmented chains** — each run its own chain with a boundary marker. Rejected: a segment
   boundary is indistinguishable from a truncation point without an external anchor, so it
   would blur the very limitation ADR 0019 §8 was careful to state.
2. **Refuse to append to any non-empty file.** Rejected: contradicts the documented
   append-only design and would make the flag useless across runs.
3. **Resume without verifying.** Rejected: anchors everything appended afterwards to a head
   nobody checked.
4. **Migrate or repair a legacy/tampered log.** Rejected: recomputing v1 entries needs raw
   payloads that were never stored, and "repairing" a failed integrity check is a
   contradiction in terms.
5. **Seed `prev` without loading entries.** Rejected: would require changing
   `check_entries`'s from-genesis contract.

## Consequences
- **Positive:** the documented append-only behaviour is now the actual behaviour; a
  multi-run custody log verifies; a tampered or legacy log is refused before it can be
  extended.
- **Unchanged:** `audit.sha256` and with it `evidence_hash` and `custody_hash`;
  `AuditLog.verify()`'s signature and `bool` return; `ChainStatus`/`ChainResult`;
  `ENTRY_VERSION` and the canonical serialization; no raw payload persisted; zero
  dependencies; graph identity, SARIF, replay, provenance, discovery output, benchmark and
  determinism — all verified by tree comparison. No existing test required modification.
- **No format change and no migration.** `ENTRY_VERSION` stays 2; existing v2 logs are read
  and continued; v1 logs are untouched on disk.
- **Accepted:** a tampered or legacy log path cannot be appended to, and the operator must
  choose another path.
- **Follow-up (not this ADR):** an external anchor for truncation resistance, and a CLI verb
  for verifying a JSONL log — both still open from ADR 0019.
