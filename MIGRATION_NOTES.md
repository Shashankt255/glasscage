# Migration Notes — 1.0.0rc1 → 1.0.0rc2 (P0 GA-blocker hardening)

Backward compatible. No architectural changes. Actions you may need to take:

## Behavior changes (safe defaults)
- **Evidence is now REDACTED by default.** Secret-shaped content (API keys, AWS keys,
  passwords, PEM) is masked in all written artifacts (reports, JSON, HAR, evidence).
  Redacted values become stable `[REDACTED:<8hex>]` tokens. To retain raw evidence for a
  consenting engagement, pass `--store-raw` (writes live secrets to disk — use only in a
  sandboxed host). Chain of custody is preserved (evidence hashes are computed on the
  original before redaction).
- **Optional at-rest encryption:** `--encrypt-evidence --evidence-password ...` encrypts
  the evidence directory; requires `pip install glasscage[crypto]`. No homemade cipher.
- **Plugins now require explicit consent:** `--plugins DIR` also needs `--allow-plugins`
  (plugins run as arbitrary code with your privileges; there is no sandbox). Scripts that
  relied on `--plugins` alone must add `--allow-plugins`.

## API / field changes (compatible)
- `posture["risk_interval"]` is now **`None`** (the previous value was a pseudo-CI, not a
  statistical interval, and was removed). The key remains for compatibility. New keys:
  `posture["label"] = "Indicative Risk Index"`, `posture["evidence_class"] = "Estimated"`.
  The score is unchanged in value; only its labeling/interval changed.
- Reports now tag every section with an Evidence Class and include a legend. The score is
  presented as the **Indicative Risk Index** (uncalibrated), never as a statistical measure.

## Removed
- Dead modules `validation_report.py`, `build_corpus.py`; dead `--paper` branch (rc1).

## New (opt-in, additive)
- `--validate-adapters [--genuine-output tool=path]` — honest parser validation; frameworks
  without genuine output are marked **Pending External Validation** (never fabricated).
- `glasscage/redaction.py`, `evidence_confidence.py`, `adapter_validation.py`.
- Governance: LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, VERSIONING.md,
  docs/THREAT_MODEL.md, tools/gen_sbom.py.

## Test-suite deltas
- 138 → 145 tests. The obsolete `test_interval` now asserts the pseudo-CI is removed.
