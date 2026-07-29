# Evidence Confidence Classification

Every report section and quantitative claim in GLASSCAGE carries exactly one evidence
class so no output implies stronger evidence than exists. The single authority is
`glasscage/evidence_confidence.py`; reporting/validation import from it.

## Classes (weakest → strongest)
1. **Pending External Validation** — framework implemented but not run against real
   external output/tools; no result claimed.
2. **Hypothesized** — architecturally reachable, not shown on-target; confirm manually.
3. **Estimated** — heuristic from an uncalibrated model (e.g. the Indicative Risk Index).
4. **Experimental** — from an Experimental component or small dataset; indicative only.
5. **Observed** — seen in a response, not impact-confirmed (steerability signal).
6. **Demonstrated** — observed on-target: impact-confirmed finding or fully-demonstrated path.
7. **Measured** — quantified with a stated method (detector precision/recall on the corpus).
8. **Verified** — confirmed against ground truth or a cryptographic check (custody hash).

## Where each is applied
- Indicative Risk Index + contribution breakdown → **Estimated** (never Measured).
- Attack paths → per path: **Demonstrated / Hypothesized / Pending External Validation**
  (mapped from the path's weakest-edge state).
- Trust boundary crossings → **Demonstrated** (graph-observed).
- Blast radius → **Demonstrated / Hypothesized** per basis; else **Estimated**.
- Coverage → **Measured** (counts) with per-category demonstrated/hypothesized split.
- Detector benchmark → **Measured** on an **Experimental** corpus (both stated).
- External-tool validation → **Experimental** (fixture) or **Pending External Validation**;
  **Measured** only when genuine tool output is supplied.
- Evidence ledger (chain-of-custody hashes) → **Verified**.

## Enforcement
`EvidenceClass.at_most(ceiling)` clamps any claim to its evidence ceiling. Reports use
`from_state()` to map graph states and `tag()`/`legend()` to render labels + a legend.
