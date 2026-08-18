# ADR 0028 — Exported coverage claims state their provenance

Status: Accepted · Phase 3 / PR #29

Completes [ADR 0027](0027-coverage-reporting-states-its-provenance.md) for the shared
`coverage.statement()` string, which the HTML export renders. Amends no existing ADR. No
score, no format, no machine-readable output contract, no dependency change.
`coverage_ratio`'s meaning is unchanged.

## Context
[ADR 0027](0027-coverage-reporting-states-its-provenance.md) corrected the AAKG markdown
renderer. It explicitly recorded what it had not closed:

> **Accepted limitation — HTML is unchanged.** … Correcting the HTML view would require a
> production file beyond the renderer; recorded, not done here.

That limitation is this ADR. The HTML export does not use the markdown renderer: it embeds
`coverage.statement(cov)` as `DATA.coverage`, which the page shows as its `Coverage:` line.
On `v0.5.2-coverage-honesty` that statement read:

```
Tested 19 techniques across 10/13 taxonomy categories (LLM01, LLM02, LLM03, ...).
NOT tested this run: ...
```

`10/13` counts every category carrying a mapped finding, including categories reached only
by questionnaire or configuration review. Runtime coverage on the same run is **7/13
(0.54)**. The word **"Tested"** was attached to the larger, mixed-provenance count, with no
runtime figure and no caveat — precisely the overstatement ADR 0027 removed from markdown,
still being exported.

`statement()` has three consumers, all traced before the change:

| Caller | Path |
|---|---|
| `report.py:213` | HTML `DATA.coverage` — the operator-facing claim |
| `report.py:100` | legacy markdown (`--no-aakg`) |
| `tests/test_stage_e5.py:80` | asserts the return is a `str` |

Two dict shapes reach it, confirmed by instrumenting both runs: the AAKG dict carries
`coverage_provenance`, `runtime_coverage_ratio` and `coverage_ratio_caveat`; the legacy
`--no-aakg` dict carries none of them.

## Decision

### 1. The runtime figure leads, when the dict carries it
`statement()` opens with `Runtime-tested coverage: N/U (ratio)` and names the categories
where a payload was actually sent, followed by the configuration-review-only,
questionnaire-only and not-tested buckets.

### 2. The graph-derived count is contextual and is not called "tested"
It is retained — it carries real taxonomy information — but rendered as
`Graph-derived coverage (contextual, mixed provenance): N/13 taxonomy categories with a
mapped finding`. The defect was the label, not the data.

### 3. Values are read, never recomputed or hard-coded
Everything comes from the coverage dict as supplied by `coverage_provenance`. The ratio is
derived from the provenance buckets only when `runtime_coverage_ratio` is absent, and that
derivation is guarded so a zero universe yields `0.0` rather than raising.

### 4. A legacy dict omits the runtime sentence rather than guessing
`--no-aakg` supplies no provenance keys. The runtime claim is then simply not made — the
statement is not padded with an invented figure — and the graph-derived count is still not
called "tested".

### 5. The disclaimer is retained verbatim
*"'Passed' means the target resisted the specific inputs tried in this run - it is NOT a
proof of robustness against adaptive attackers."*

### 6. Only `statement()` changes
No other function in `glasscage/coverage.py` is touched; `compute()` and its counts are
unchanged, as are `aakg/**`, `posture.py`, `scoring.py`, `coverage_provenance.py`,
`engine.py` and `cli.py`.

## Security analysis
- **What this fixes:** the HTML export no longer presents a provenance-mixed count as
  "tested", and now carries the runtime figure, the provenance breakdown and the caveat.
- **What it does not change:** `posture_score` 42.7 and `risk_index` 57.3; `coverage_ratio`
  semantics; the runtime coverage itself (still 7/13); JSON, SARIF, the audience views and
  the ADR 0027 markdown section, all verified byte-identical.
- **Accepted limitation — `posture.coverage_ratio` still carries the mixed value** in the
  HTML `DATA` block as a reported field. It is unused by the score and is not part of the
  narrative claim; changing it would require a production file beyond `coverage.py`.
- **Accepted limitation — the underlying ratio is unchanged.** As in ADR 0027, this governs
  presentation only.

## Consequences
- **Positive:** every operator-facing surface — markdown (ADR 0027) and HTML (this ADR) —
  now distinguishes what a payload established from what was inferred.
- **Behavioural change, intended:** the exported statement gains the runtime sentence,
  provenance buckets and caveat, and stops using "Tested" for the mixed count. The legacy
  markdown consumer receives the same corrected wording.
- **Unchanged:** every frozen probe, all four surface entry counts, append/resume, PR #26
  exit codes, replay bundle and runner, provenance data, dependency set, determinism.
- **No migration.**

## Rejected alternatives
1. **Change `compute()`'s counts.** Rejected: that is a semantic change to
   `coverage_ratio`, out of scope and not required to stop the overstatement.
2. **Emit the runtime figure only when it differs from the graph-derived count.** Rejected:
   the claim should be legible always, not only when the two disagree.
3. **Invent a runtime figure for legacy dicts.** Rejected: it would manufacture a
   measurement the run cannot support — the exact failure this series has been closing.
4. **Correct `posture.coverage_ratio` in the HTML `DATA` block too.** Rejected: needs a
   production file beyond `coverage.py`; recorded above as an accepted limitation.
