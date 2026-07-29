# Assessment Workflow

A complete engagement from planning to archiving. Every step uses only implemented
functionality.

## 1. Planning

- Confirm **written authorization** to test the target. GLASSCAGE requires
  `--authorized`; that flag is your assertion, not a substitute for permission.
- Define scope: which hostnames (`--scope`), which environment (prefer staging), what
  rate is acceptable (`--rate`).
- Decide evidence handling: default (redacted) vs `--store-raw` (sandboxed host only).
- Set expectations: GLASSCAGE produces **hypotheses**, not verdicts. Budget time to
  confirm findings manually.

## 2. Target selection & characterization

- Determine the target's **capability tier**:
  - L0 = text in/out; L1 = + memory/session; L2 = + planner/tool traces.
  - Most black-box endpoints are L0/L1; agentic probes will return `NOT ASSESSABLE`
    there — an honest result, not a failure.
- Write the target config (`target.json`). Validate `response_path` against a manual
  curl before running.
- If the target is agentic, obtain a **tool schema** (`--schema`) — it materially
  improves blast-radius accuracy.

## 3. Capture architecture (optional, careful)

```bash
python -m glasscage --arch-template > arch.json
```

Answer **only what you know to be true**. Declared controls are trusted, not verified:
a wrong "yes" suppresses violations and lowers the risk index. When unsure, leave it
unknown.

## 4. Running the assessment

```bash
python -m glasscage --config target.json --authorized \
  --schema tools.json --architecture arch.json \
  --trials 5 --seed 1 --rate 2 \
  --views all --sarif --replay --audit-log custody.log \
  --out engagement-01
```

- `--trials 5` → Wilson intervals; single trials on a nondeterministic target are noise.
- `--seed 1` → reproducible stochastic engines.
- `--rate 2` → be polite; GLASSCAGE does not back off automatically.

## 5. Evidence collection

- Default: secrets are redacted in all artifacts; the custody hash is computed on the
  **original** before redaction, so integrity survives sanitisation.
- `--audit-log` writes a hash-chained record of what was sent/received.
- For engagements that must retain live secrets, use `--store-raw --encrypt-evidence`
  on a sandboxed host (requires `cryptography`; see [INSTALL.md](INSTALL.md)).

## 6. Narratives & story

- The Assessment Story (13 sections) and Attack Narratives (8 strategies) are generated
  automatically into the markdown/HTML/JSON.
- Read them as **prioritized hypotheses with citations**, not conclusions. See
  [NARRATIVES.md](NARRATIVES.md).

## 7. Report review

- Start with the **Verification Checklist** section of the Assessment Story.
- Read the **evidence class** on every section before the number
  ([REPORT_GUIDE.md](REPORT_GUIDE.md)).
- Note `NOT ASSESSABLE` items as **unmeasured**, never as passing.
- Quote **runtime coverage (7/13)**, not `coverage_ratio`, externally.

## 8. Validation (confirm findings)

- Reproduce every `demonstrated` finding by hand using its evidence / reproduction steps.
- Manually test every `hypothesized` path before reporting it.
- For cross-tool comparison, see [VALIDATION.md](VALIDATION.md).

## 9. Replay

- `--replay` writes a reproducible bundle (auth headers stripped) so a colleague can
  re-execute the assessment.
- Store the bundle with the engagement record; it is your reproducibility evidence.

## 10. Archiving

- Treat default artifacts as **Confidential**; `--store-raw` artifacts as **Secret**.
- Do **not** commit `*_evidence/`, `*.har`, or `*.json` outputs to a repository.
- Retain: the report, the replay bundle, the audit log, and the target/arch configs.
- Record the GLASSCAGE version (`python -c "import glasscage;print(glasscage.__version__)"`)
  with the engagement for reproducibility.

## Workflow at a glance

```
Plan → Characterize tier → (Arch, careful) → Run (--trials/--seed/--rate)
   → Collect evidence (redacted/custody) → Read story & narratives
   → Review report (evidence class first) → Confirm findings manually
   → Replay bundle → Archive (classify, record version)
```
