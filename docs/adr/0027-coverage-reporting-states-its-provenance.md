# ADR 0027 — Coverage reporting states its provenance

Status: Accepted · Phase 3 / PR #28

Concerns only how coverage is **rendered**. Amends no existing ADR. No score, no format, no
machine-readable output contract, no dependency change. `coverage_ratio`'s meaning is
unchanged — this ADR makes it legible, not different.

## Context
`aakg/coverage.py` already computed three honest figures and labelled them as such:

- `runtime_coverage_ratio` — categories where a payload was actually sent;
- `coverage_provenance` — the runtime / configuration-review / questionnaire / not-tested
  breakdown;
- `coverage_ratio_caveat` — *"coverage_ratio counts questionnaire and configuration-review
  findings as tested; use runtime_coverage_ratio for runtime-tested categories only."*

**None of them reached any artifact.** An audit of every output of a `--demo` run — markdown,
HTML, JSON, SARIF, all five audience views and CLI stdout — found `runtime_coverage_ratio`,
`coverage_provenance` and `coverage_ratio_caveat` in **none** of them.

What the operator read instead, in the primary markdown report:

```
## Coverage (graph-derived)  [Measured]
- **OWASP**: 10/13 tested (demonstrated 2, hypothesized 8, not-assessable 0)
```

`10/13` counts every category carrying a mapped finding, including categories reached only
by questionnaire or configuration review. **7/13** had a payload sent. The larger figure was
presented as a measurement, with no caveat.

The project's own guidance already said the opposite — `ASSESSMENT_WORKFLOW.md`: *"Quote
**runtime coverage (7/13)**, not `coverage_ratio`, externally."* The tool did not follow it.

### What this ADR does **not** claim
An earlier hypothesis held that the inflated ratio inflates `posture_score`. **That is
false and was disproved by substitution before any code was written:**

```
coverage_ratio 0.77 (inflated) -> posture_score 42.7  risk_index 57.3
coverage_ratio 0.54 (runtime)  -> posture_score 42.7  risk_index 57.3
```

`risk_index` is computed at `aakg/posture.py:47`; `cov_ratio` is read at line 53 and only
placed in the output dict. It is never an input to the score. This is therefore a reporting
defect, and the scores are asserted unchanged.

## Decision

### 1. The runtime-tested figure is the measured claim
The coverage section leads with `OWASP runtime-tested: 7/13 (0.54)`, tagged `Measured`. That
is the only coverage number in the report backed by a payload actually sent.

### 2. Provenance is shown, not summarised away
The four buckets are listed by category name — runtime-tested, configuration-review only,
questionnaire only, not tested — so an operator can see exactly which categories rest on
which kind of evidence.

### 3. The graph-derived counts are contextual, not a measurement
They remain, under `### Coverage (graph-derived) — contextual, mixed provenance`, tagged
`Observed` rather than `Measured`, and worded as "categories with a mapped finding" rather
than bare "tested". Removing them would lose real information; presenting them as a
measurement was the defect.

### 4. The caveat travels with the figure it qualifies
`coverage_ratio_caveat` is rendered inside the graph-derived block, where the number it
warns about appears.

### 5. Nothing is recomputed
All three values are read from the coverage dict the renderer already receives. No upstream
module changes; `aakg/coverage.py` and `coverage_provenance.py` are untouched.

### 6. No new machine-readable contract
JSON, SARIF and the audience views are deliberately unchanged. Adding coverage to them is a
new output contract and a separate decision.

## Security analysis
- **What this fixes:** the operator is no longer shown a provenance-mixed coverage figure
  labelled as a measurement, with the honest figure computed and discarded.
- **What it does not change:** `posture_score`, `risk_index`, `coverage_ratio`'s definition,
  the OWASP runtime coverage itself (still 7/13), and every machine-readable artifact.
- **Accepted limitation — the underlying ratio is unchanged.** `coverage_ratio` still counts
  mixed provenance wherever it is consumed internally; this ADR governs presentation only.
- **Accepted limitation — `posture.coverage_ratio` still carries the inflated value** as a
  reported field. It is unused by the score, so it is left alone rather than widening scope.
- **Accepted limitation — HTML is unchanged.** It embeds `posture.coverage_ratio` in its
  `DATA` block. Correcting the HTML view would require a production file beyond the
  renderer; recorded, not done here.

## Consequences
- **Positive:** the report distinguishes what was tested by sending a payload from what was
  inferred, and says so in the evidence label.
- **Behavioural change, intended:** the markdown coverage section gains the runtime figure,
  the provenance breakdown and the caveat, and the graph-derived block is retagged from
  `Measured` to `Observed`.
- **Unchanged:** `posture_score` 42.7 and `risk_index` 57.3 on `--demo`; JSON, SARIF, the
  five audience views, replay bundle and runner, provenance data, dependency set, and every
  frozen probe.
- **No migration.**

## Rejected alternatives
1. **Change what `coverage_ratio` counts.** Rejected: it is consumed by `posture.py`,
   `scoring.py` and the legacy coverage module; redefining it is a semantic change well
   beyond a reporting fix, and it does not affect any score anyway.
2. **Drop the graph-derived counts.** Rejected: they carry real taxonomy information across
   five families. The defect was the label, not the data.
3. **Add the honest figures to JSON/SARIF.** Rejected here: a new machine-readable contract
   deserving its own decision.
4. **Correct the HTML `DATA` block as well.** Rejected: needs scope beyond the renderer.
