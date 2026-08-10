# ADR 0019 — Audit chain integrity

Status: Accepted · Phase 3 / PR #20

Supersedes nothing. Corrects a guarantee asserted by `audit.py`'s own docstring and by nine
documentation sites.

## Context
`AuditLog` was described as *"append-only JSONL of every payload sent… chained (each entry
hashes the previous) **so tampering is evident**"*, and `THREAT_MODEL.md` listed *Tampering
with evidence* as mitigated by it, status **Implemented**. `cli.py` printed the verdict to
the operator.

Measured on `v0.4.3-replay-applicability`, the guarantee did not hold:

```
url altered            verify() -> True     response_sha256 altered  -> True
ts altered             verify() -> True     ok flag flipped          -> True
prompt_sha256 altered  verify() -> True     tail truncated           -> True
```

Only a deleted middle entry was caught, and only because it broke a `prev` link.

**The cause is structural.** `record()` computed `sha256(prev, ts, url, prompt, response)`
over the **raw** payloads, but the entry persisted `prompt_sha256`/`response_sha256` —
digests, not the raw values. `verify()` therefore could not recompute anything and only
walked the links. Two further gaps surfaced while establishing this: `ok` was stored but was
never a hash input, so it was unprotected in principle; and nothing anywhere read the
`--audit-log` file back, so the on-disk artifact had no verification path at all.

One property decided the design: **the log has never held a raw payload.** `redaction` does
not touch it because there is nothing to redact. That was incidental; this ADR makes it a
contract.

## Decision

### 1. The hash covers the fields the entry retains
`entry_hash = sha256(canonical_entry(entry))` over `v`, `prev`, `ts`, `url`,
`prompt_sha256`, `response_sha256`, `ok`. Every input is stored, so any entry is
independently recomputable from itself. `ok` becomes covered for the first time.

### 2. Raw prompt and response are never persisted
Digests only, now stated rather than assumed. The audit log remains the one artifact that
cannot leak a payload, which is what justifies `redaction`'s exemption of it.

### 3. The stored digests are the integrity source
The chain attests that *a payload with this digest was sent at this time to this URL*. It
does not attest the payload's content, because the content is deliberately not retained.
Anyone holding the original can confirm the match; nobody can reconstruct it from the log.

### 4. Canonical serialization — frozen, specified once
For each field, in exactly this order — `v`, `prev`, `ts`, `url`, `prompt_sha256`,
`response_sha256`, `ok` — emit

```
<utf8-byte-length> ":" <value>
```

concatenated with no separator between fields. Booleans encode as `true`/`false`, never
Python's `str(True)`. The result is passed to `sha256` as a **single** argument.

Length-prefixing is required because `audit.sha256` concatenates its parts without a
separator: `sha256("ab", "c") == sha256("a", "bc")`. Passing one pre-delimited string
removes the ambiguity **without altering `sha256`**, whose output is frozen by
`evidence_hash` (`engine.py`) and `custody_hash` (`chat.py`, `rest.py`).

### 5. Entries carry a format version
Each entry gains `"v": 2`. Additive; readers ignoring unknown keys are unaffected.

### 6. Legacy chains are unverifiable, never tampered
A chain containing an entry without `v` returns `LEGACY_UNVERIFIABLE` with a reason. It is
detected **before** any digest comparison, because a v1 digest can never match the v2
formula and reporting that as tampering would accuse the operator of something that did not
happen. A v1 chain cannot be upgraded: recomputing it needs raw payloads that were never
stored.

### 7. `verify()` is a compatibility API only
`AuditLog.verify()` keeps its signature and `bool` return for callers written against the
old contract, and returns `True` only for a fully verified chain — `False` for both
tampered and legacy, because `bool` cannot express three states. **No new code calls it.**
`AuditLog.check()` returns the three-state `ChainResult`, and `verify_file(path)` applies
the same rule to a JSONL log — the first reader that artifact has ever had. `cli.py` uses
`check()` so the operator sees the distinction.

### 8. Truncation detection is out of scope
A forward-linked chain can always be recomputed end to end by whoever can write the file,
and tail truncation leaves a self-consistent prefix. Detection requires an anchor held
outside the log. Not decided here, because the repository offers no location the writer does
not also control — the report is written by the same process to the same directory.
`ChainResult.head` exposes the final digest so an operator can record it externally, and the
documentation no longer claims truncation resistance. A test pins the limitation so it
cannot be quietly assumed away.

## Rejected alternatives
1. **Persist raw prompt and response so the existing hash recomputes.** Rejected: writes
   unredacted payloads to the one artifact that has never held them, contradicting
   redaction-by-default. Buys content attestation by making the audit log a breach vector.
2. **Keep the hash and pass raw values into `verify()`.** Rejected: impracticable —
   `verify()` runs after the assessment and has no payloads to supply.
3. **Sign entries with a MAC.** Rejected: needs key management the repository has no
   evidence of, and a keyed primitive under a zero-dependency constraint.
4. **Recompute v1 entries with the new formula.** Rejected: would report every legacy entry
   as tampered.
5. **Change `sha256` to insert a separator.** Rejected: `evidence_hash` and `custody_hash`
   are frozen invariants computed with it.
6. **Leave the code and withdraw the claim.** Rejected: a control listed *Implemented* in
   the threat model should be implemented, and the fix is contained.

## Consequences
- **Positive:** altering any recorded field is now detected; `ok` gains protection it never
  had; the on-disk log gains a reader; and the payload-free property becomes a stated
  contract rather than an accident.
- **Unchanged:** `audit.sha256` byte-for-byte, and with it `evidence_hash` and
  `custody_hash`; `verify()`'s signature and return type; `Scope`; `RateLimiter`;
  `har_export`; and every artifact other than the audit log. Verified by tree comparison
  against `v0.4.3-replay-applicability`.
- **Format change:** entries gain `"v": 2`. No in-repository consumer reads the JSONL, so
  the internal blast radius is zero.
- **No migration is possible.** v1 logs remain readable and report as legacy-unverifiable.
- **Accepted:** no content attestation without the original payload, and no truncation
  resistance without an external anchor. Both stated rather than implied.
- **Follow-up (not this ADR):** an external anchor for truncation resistance; a CLI verb for
  verifying a JSONL log.
