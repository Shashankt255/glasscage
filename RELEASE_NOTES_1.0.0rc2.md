# Release Notes — GLASSCAGE 1.0.0rc2

Security & credibility hardening. Implements the five Priority-0 GA blockers from the
independent review. **No new attack capabilities, graph node types, or reporting
redesign.** Backward compatible. 145 tests pass.

## 1. Secure evidence handling
- Secret redaction ON BY DEFAULT across all artifacts; raw only via `--store-raw`.
- Optional at-rest encryption (`--encrypt-evidence`, `crypto` extra; honest refusal
  without it — no homemade cipher).
- Chain of custody preserved (hash computed pre-redaction).
- Tests prove secrets never appear in default artifacts.

## 2. Evidence Confidence Classification (honesty control)
- Eight-level vocabulary (Verified → Pending External Validation); every report section
  is tagged; a clamp prevents any claim exceeding its evidence. Legend included in reports.

## 3. Indicative Risk Index (was "Posture Score")
- Removed the pseudo confidence interval (it was heuristic, not statistical).
- Relabeled as the uncalibrated **Indicative Risk Index [Estimated]**; value unchanged;
  `risk_interval` retained as `None` for compatibility.

## 4. Plugin security
- `--plugins` requires `--allow-plugins`; loud trust warning; version-gated. No sandbox
  (documented). Tested.

## 5. Adapter validation framework (honest)
- `--validate-adapters` validates parsers; genuine tool output → Measured; shipped
  fixtures → Experimental; otherwise **Pending External Validation**. Never fabricated.
- In THIS environment (no network / tools not installed): all five frameworks are
  **Pending External Validation**. Supply real output via `--genuine-output tool=path`.

## Governance & supply chain
- LICENSE (Apache-2.0), SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, VERSIONING.md,
  GLASSCAGE-specific THREAT_MODEL, SBOM generator (0 runtime deps, 55 modules).

## Still outstanding for GA (unchanged, honest)
- Real-target efficacy validation (C1) and genuine external-tool runs (C2/P0-5 completion).
- These require environments not available here and remain GA gates.
