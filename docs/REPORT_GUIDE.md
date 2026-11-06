# GLASSCAGE Report Interpretation Guide — 1.0.0rc3

How to read GLASSCAGE output correctly — and, just as importantly, **what you may not
conclude from it**.


## 1. The one rule

**Every GLASSCAGE finding is a hypothesis until a human confirms it.** GLASSCAGE has
not been validated against real language models. Its value is prioritization and
evidence linkage, not adjudication.


## 2. Read the evidence class first, the number second

Every section carries exactly one class. The tool enforces in code that a claim never
exceeds its evidence.

| Class | What you may conclude | What you may not |
|---|---|---|
| **Verified** | a cryptographic/ground-truth check passed (e.g. custody hash) | that the finding is exploitable |
| **Measured** | a number was computed by a stated method | that it generalises beyond that data |
| **Demonstrated** | it happened on this target, impact confirmed | that it happens every time, or elsewhere |
| **Observed** | a signal appeared in a response | that impact followed |
| **Experimental** | indicative from a small/experimental component | anything load-bearing |
| **Estimated** | an uncalibrated heuristic produced it | that it is a risk measurement |
| **Hypothesized** | architecturally reachable | that it was ever shown to work |
| **Pending External Validation** | the machinery exists; **no result is claimed** | **nothing at all** |


## 3. Executive Summary

```
Indicative Risk Index 74.2/100 (band high) — uncalibrated heuristic [Estimated]
Findings: 3 demonstrated, 11 hypothesized, 7 not assessable
Most consequential scenario: end-user → Secrets in 4 steps — hypothesized [Hypothesized]
```

- **Indicative Risk Index** — relative prioritization **on this target only**. It is
  **not** calibrated, **not** statistical, **not** comparable across targets. Do not
  report it as "our AI risk is 74".
- **demonstrated / hypothesized / not assessable** — the only counts that carry
  evidential weight is the first.
- **not assessable** means *unmeasured*, **not** *safe*. It is a gap in the
  assessment, not a clean bill of health.


## 4. Indicative Risk Index — contribution breakdown

Every point is attributed:

```
exploitability: value 0.80, weight 0.18 -> 14.4 pts (evidence: Finding:LLM01:...)
privileges:     value 0.90, weight 0.10 ->  9.0 pts (evidence: User→LLM crosses edge)
mitigation_offset: value 2, offset      -> -7.4 pts (evidence: Mitigation:tenant_isolation)
```

**What this proves:** the arithmetic is transparent and traceable to graph objects.
**What it does not prove:** that the weights are right. They are asserted, not
calibrated. `privileges` is hardcoded at 0.9. Read the breakdown to understand *why*
one finding outranks another — never to justify an absolute risk statement.

> **Mitigation offsets come from `--architecture` answers, which GLASSCAGE trusts
> without verification.** If you declared a control you do not actually have, this
> number is falsely low.


## 5. Attack Paths & Narratives

```
[Hypothesized] end-user → Secrets (likelihood 0.5, 1/4 demonstrated hops)
1. end-user crosses the trust boundary into model
   - nodes `User:end-user` -> `LLM:model` · edge `User:end-user-[crosses]->LLM:model`
     · evidence no evidence id (structural edge) · confidence n/a · [Demonstrated]
2. model invokes planner — hypothesized, not shown on-target
   - ... · [Hypothesized]
```

**Rules for reading:**
- **A path's state is its weakest hop.** `1/4 demonstrated hops` with an overall
  `Hypothesized` is the honest result — not a bug.
- **"no evidence id (structural edge)"** means the relationship is architectural, not
  observed. Finding-level evidence lives in the Evidence Ledger.
- **"Not demonstrated."** under a strategy means no graph path matched. GLASSCAGE
  refused to invent one. That refusal is a feature.
- Narratives **never** exceed `Demonstrated`; `Measured`/`Verified` require other
  evidence types.


## 6. Coverage — **read this before quoting any coverage number**

**Known defect in 1.0.0rc3:** `coverage_ratio` counts a category as tested if any
finding carries its id, regardless of how the finding was obtained.

| Method | Categories | Counted as "tested"? |
|---|---|---|
| **Runtime tested** (payload sent) | LLM01, LLM02, LLM05, LLM06, LLM07, LLM09, LLM10 — **7** | yes (correct) |
| **Questionnaire only** (no contact) | LLM03, LLM08 — 2 | yes (**incorrect**) |
| **Configuration review** (manifest parsed) | MCP03, MCP07 — 2 | yes (**incorrect**) |
| **Not tested** | LLM04, MULTIMODAL — 2 | no (correct) |

**True runtime coverage: 7/13 = 0.54.** The tool may report **0.85**.

**Do not quote `coverage_ratio` to a customer or reviewer.** Quote 0.54 and the
breakdown. Fix tracked as a P0 blocker.


## 7. Trust Boundary & Blast Radius

- **Privilege transitions** — edges into a higher trust zone. Real graph observations.
- **Excessive privilege** — a semi-trusted component reaching >1 trusted asset.
- **Violations** — suppressed when a mitigation is declared. **Declared, not verified.**
- **Blast radius** `basis` is `demonstrated` / `hypothesized` / `unconfirmed`. The
  `multiplier` is a **heuristic**, not a measurement.


## 8. Assessment Story — the honest sections

- **Business Impact [Estimated]** — deliberately qualitative. GLASSCAGE has no
  asset-criticality input and will not invent valuations. Rate the named asset classes
  against your own crown-jewel inventory.
- **Residual Risk [Estimated]** — explicitly refuses to compute a post-remediation
  number ("not computed as a number: GLASSCAGE has no calibration data"). Re-run after
  fixes and compare.
- **Root Cause** — limited to findings carrying an `enables` edge; says "Not
  demonstrated." rather than speculate.
- **Verification Checklist [Verified]** — the section to act on first.


## 9. Audience views

| View | Use it for | Do not use it for |
|---|---|---|
| `executive` | direction, the one consequential scenario | board-level risk assertion |
| `security` | full kill chain with citations | — |
| `developer` | root cause, affected components, verification | assuming hypothesized hops are defects |
| `incident_response` | timeline, blast radius, containment order | IOCs — **GLASSCAGE produces none** and says so |
| `compliance` | control gaps, five-framework matrix | recording unassessed areas as compliant |


## 10. What GLASSCAGE output can never tell you

1. That your system is secure. Absence of a finding ≠ absence of a vulnerability —
   especially where an objective has **one** technique (prompt leak, data exfiltration).
2. Your calibrated risk. The index is uncalibrated.
3. That a hypothesized path works. It has not been shown.
4. That a NOT ASSESSABLE area is fine. It is **unmeasured**.
5. That a declared control exists. GLASSCAGE trusted your answer.
6. That MCP findings mean your MCP server was tested. **The manifest was parsed; the
   server was never contacted.**
7. That external frameworks ran. **Zero genuine tool outputs have ever been ingested.**
8. That results generalise to other models or frameworks.
