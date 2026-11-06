# GLASSCAGE — Cross-Agent Consolidated Findings

**Date:** 2026-11-05
**Validated by:** Lead Agent (cross-agent correlation of Agents 1–5)


## Cross-Agent Validation Notes

**Duplicate/overlap check:** No duplicate findings across agents. Each agent tested distinct dimensions with no conflicting conclusions. Agent 2's PermissionError finding (A07) and Agent 3's path traversal finding (S06) both touch `cli.py` output paths but address different failure modes (crash vs. write location).

**Conflict check:** Agent 4 P03 notes 1 evidence_hash mismatch for `sensitive-info-disclosure` due to post-hash redaction — this is consistent with Agent 2's audit chain validation (which also noted hash integrity is correct) and Agent 3's S20 (store-raw gating confirmed correct). No conflicting conclusions.


## Consolidated Defect List

### CRITICAL — None


### HIGH

| ID | Source | Finding | Component | Impact |
|---|---|---|---|---|
| S11 | Agent 3 | No SSRF protection in URL validation | `config.py:30-31`, `target.py:132` | Cloud metadata credential theft via internal IP targets (169.254.169.254, 127.0.0.1, RFC1918) |

**Remediation:** Add private IP blocklist to `validate_target_config()`. Block 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7, fe80::/10, 0.0.0.0. Resolve DNS before check.

**Release gate:** CONDITIONAL — acceptable for CLI-only 1.0.0 GA where user controls their own config. Must fix before any API/service deployment mode.


### MEDIUM

| ID | Source | Finding | Component | Impact |
|---|---|---|---|---|
| S18 | Agent 3 | Incomplete secret redaction patterns | `probes.py:260-265` | Anthropic keys (sk-ant-*), GitHub PATs, JWTs, Slack tokens unredacted in reports |
| S02 | Agent 3 | CRLF injection in header values | `config.py:33-38` | HTTP header injection (mitigated by Python 3 http.client) |
| S12 | Agent 3 | Unrestricted HTTP redirect following | `target.py:137-138` | SSRF via redirect chain (amplifies S11) |
| A07 | Agent 2 | PermissionError crash on non-writable output dir | `evidence.py:129`, `cli.py:488` | Unhandled traceback instead of clean ConfigError |


### LOW

| ID | Source | Finding | Component | Impact |
|---|---|---|---|---|
| S03 | Agent 3 | No length limits on config values | `config.py:22-42` | Self-DoS with 1MB URLs/headers |
| S04 | Agent 3 | Null bytes in config strings | `config.py:22-42` | Potential string truncation in C libraries |
| S06 | Agent 3 | Path traversal in --out parameter | `cli.py:488-561` | Write reports to unintended locations |
| S14 | Agent 3 | No maximum timeout enforced | `config.py:39-41` | Process hang on extreme timeout values |


### INFORMATIONAL / OBSERVATIONS

| ID | Source | Finding | Component | Notes |
|---|---|---|---|---|
| S05 | Agent 3 | Unicode edge cases not normalized | `config.py` | Visual spoofing in logs/reports |
| S07 | Agent 3 | Symlink following in evidence dir | `evidence.py:128-136` | Requires TOCTOU race + local access |
| S08 | Agent 3 | No validation of --out against device files | `cli.py:113` | Minimal impact with extensions appended |
| S10 | Agent 3 | Plugin system lacks sandboxing | `plugins.py:43-82` | By design — consent-gated |
| S16 | Agent 3 | HTML report raw innerHTML for SVG | `report.py:431` | Upstream escaping mitigates; fragile pattern |
| S23 | Agent 3 | Plugin informed consent adequate | `plugins.py`, `cli.py:281-291` | Design review — acceptable |
| A08 | Agent 2 | Stale test counts (21/25 vs 34/32) | `test_custody_completeness.py` | Expected — caused by uncommitted feature additions |


## Pre-GA Remediation Priority

### Must Fix (before 1.0.0 GA)
1. **S18** — Expand `SECRET_PATTERNS`: change `sk-[A-Za-z0-9]{16,}` to `sk-[A-Za-z0-9_-]{16,}` and add patterns for ghp_, github_pat_, JWT, xox[baprs]-, Bearer tokens
2. **A07** — Wrap PermissionError in evidence.py and cli.py with ConfigError for clean error handling
3. **A08** — Update hardcoded test counts to match current probe count (impact chaining adds entries)

### Should Fix (before 1.0.0 GA, acceptable as known limitations if documented)
4. **S02** — Reject CRLF in header values during config validation
5. **S04** — Reject null bytes in config string values
6. **S11** — Add SSRF private IP blocklist (critical for any future service mode; acceptable for CLI-only with documentation)
7. **S12** — Custom redirect handler with scope re-validation

### Fix Post-GA
8. **S03** — Length limits on config values
9. **S06** — Path canonicalization for --out
10. **S14** — Maximum timeout cap


## Defect Density Summary

| Severity | Count | Rate (per KLOC) |
|---|---|---|
| Critical | 0 | 0.0 |
| High | 1 | ~0.1 |
| Medium | 4 | ~0.4 |
| Low | 4 | ~0.4 |
| Info | 7 | ~0.7 |
| **Total actionable** | **9** | **~0.9** |

Codebase: ~10K lines Python (glasscage/ package + cli.py)

This defect density is well within industry norms for a security tool at RC stage. The high-severity finding (S11/SSRF) is mitigated by the CLI-only deployment model where the user controls their own config.
