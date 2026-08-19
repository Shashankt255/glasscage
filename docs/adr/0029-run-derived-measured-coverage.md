# ADR 0029 — Run-derived measured coverage

Status: Accepted · Phase 3 / PR #30

Adds a second, run-derived coverage figure beside the existing registry-derived one. Amends
no existing ADR. The meaning and the value of `runtime_coverage_ratio` are unchanged. No
score, no new machine-readable output contract, no dependency change.

## Context

[ADR 0027](0027-coverage-reporting-states-its-provenance.md) and
[ADR 0028](0028-exported-coverage-claims-state-their-provenance.md) stopped the report and
the HTML export calling a provenance-mixed count "tested", and promoted
`runtime_coverage_ratio` — 7/13 (0.54) — as the honest figure to quote.

Preparing the C1 real-target validation programme surfaced what that figure actually is.
`coverage_provenance.summarize()` **takes no run argument**. It iterates the probe
`REGISTRY` and classifies each probe by `inspect.getsource(probe.run)`, looking for
`target.send` or `target.drive`. It is a static property of the installed probe set:

> 7/13 means *seven categories have a probe that would send a payload*.

It does not mean *seven categories sent one*. The same 7/13 is reported whether the target
answered every request, refused every connection, rate-limited the run, or was out of
scope. Against the bundled mock target the two readings coincide, which is why this went
unnoticed; against a real target — the entire point of C1 — they can diverge arbitrarily,
and the figure would still read 7/13.

This is a capability/measurement conflation, not an arithmetic error. C1 cannot report
"what was exercised against this target" from a number that never consulted the target.

## Decision

### 1. A separate field, not a redefinition
`runtime_coverage_ratio` and `coverage_provenance` keep their exact current semantics and
values. A distinct block is added:

```
run_measured_coverage = {
    universe, measured_categories, measured_count, run_coverage_ratio, custody_complete
}
```
plus a flat `run_coverage_ratio` mirroring the block's ratio for quotability. Naming
deliberately avoids `runtime_*`, which would silently redefine the existing field.

### 2. "Payload delivered" is defined by the transport's own record
A category is measured **iff at least one exchange recorded during one of its probes shows
a response came back from the target**. All three transports —
`target.HTTPChatTarget._record`, `targets/rest.py`, `refagent` — append a record carrying
`status`, and every one of them writes `0` when the payload never reached the target
(refused connection, timeout, DNS failure). So:

- `status > 0` → delivered. This includes 4xx/5xx: the target received the payload and
  rejected it. The category *was* exercised.
- `status == 0` → not delivered (transport refusal).
- **scope refusal** → `scope.check` raises inside `send` before any record is written, so
  it cannot appear at all.
- **probe crashes before sending** → no record appended, not counted.
- **probe delivers then crashes** → counted; the payload was delivered and the crash is
  after the fact.

### 3. Findings are explicitly not the source
A delivered payload that produced **no finding** still counts. Coverage is what was
exercised, not what was found — deriving it from findings would make a clean run look like
an unexecuted one, which is the failure mode this series exists to remove. Nor is probe
existence a source: a registered probe that never sends is not coverage.

### 4. A category counts once
`measured_categories` is a set. LLM01 carries nine probes; nine deliveries are one measured
category.

### 5. The denominator is the canonical taxonomy
`len(CANONICAL)` = 13, the same denominator the capability figure uses, so the two are
directly comparable. Off-taxonomy ids (a plugin probe's own id) are filtered out and cannot
inflate the count.

### 6. Custody relationship — flagged, never silently trusted
PR #26 exits 3 when a run finishes with exchanges the audit chain does not hold. The
measurement mirrors that condition into `custody_complete`, computed exactly as PR #26
computes it (an audit exists and its entry count is below the exchange count). The
categories are still reported — they were delivered, that is an operational fact — but the
statement renders **NOT VOUCHED**, so a measurement standing on exchanges that cannot be
attested is never quoted as though it could. PR #26's exit codes are untouched.

### 7. Measured at the engine, computed in `coverage`
Attribution is only possible where a probe and its exchanges are both in scope: the engine's
probe loop. The exchange records carry no category, and all three recording sites are in
files this PR must not touch, so the engine brackets each probe with the transport's own
log and reads the slice. The arithmetic lives in `coverage.py` as two pure functions.
The block is attached **after** posture is computed, so it cannot reach the score.

## Security analysis
- **What this fixes:** a capability figure was the only "runtime" number available, and C1
  would have quoted it as a measurement of a real target.
- **What it does not change:** `posture_score` 42.7 / `risk_index` 57.3; the capability
  figure and its value; `coverage_ratio` semantics; the ADR 0027 markdown section; JSON,
  SARIF, replay bundle and runner, the AAKG export and all five audience views — verified
  unchanged; PR #23–26 custody and exit codes; every frozen probe; determinism.
- **Behavioural change, intended:** the HTML `Coverage:` line and the legacy `--no-aakg`
  markdown statement gain the measured sentence.
- **Accepted limitation — the AAKG markdown section is unchanged.** The ADR 0027 renderer
  is a separate path; surfacing the measurement there needs a production file beyond this
  PR's minimum. Recorded, not done here.
- **Accepted limitation — no machine-readable contract.** The block is not exported to JSON
  or SARIF; that was not approved for this PR. C1 tooling reads it from the coverage dict
  or the HTML `DATA` block.
- **Accepted limitation — delivery is not comprehension.** A 200 response proves the payload
  arrived, not that the model engaged with it. This measures exercise, not efficacy.

## C1 relationship
C1 requires, per run and without consulting GLASSCAGE's findings as an oracle:

```
capability coverage        = 7/13   (registry-derived, coverage_provenance)
measured runtime coverage  = Y/13   (this ADR, delivery-derived)
measured categories        = [...]
```

The measured figure is derived from transport records only — not findings, not posture, not
severity — so it satisfies the C1 anti-circularity rule that coverage evidence must not come
from the scoring path it is meant to qualify.

**This PR does not validate a real model.** It makes the measurement exist and proves it
tracks delivery. Whether GLASSCAGE detects anything against a real target is C1's question,
not this one's.

## Rejected alternatives
1. **Redefine `runtime_coverage_ratio` in place.** Rejected: it is quoted externally and in
   two shipped ADRs; silently changing a published figure's meaning is the defect this
   series removes, not a fix.
2. **Derive coverage from findings.** Rejected: a delivered payload that found nothing is
   still coverage; findings-derived coverage under-reports exactly on clean targets.
3. **Record the category on the exchange itself.** Rejected: all three recording sites are
   in files outside this PR's approved scope, and it would put a reporting concern inside
   the transports (ADR 0008 §1).
4. **Count `status == 0` as delivered.** Rejected: that is the transport saying the payload
   never arrived.
5. **Suppress measured categories when custody is incomplete.** Rejected: the delivery
   happened; hiding it would substitute one inaccuracy for another. Flagged instead.
