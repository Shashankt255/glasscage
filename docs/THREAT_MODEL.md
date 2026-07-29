# GLASSCAGE Threat Model

This describes the security properties of the **GLASSCAGE tool itself** (not of the
systems it assesses). It states what GLASSCAGE actually guarantees, what it does not,
its maturity, and supported deployment models. It is deliberately specific.

## What GLASSCAGE is
A single-assessment, offline-by-default CLI/library that sends probe prompts to an
authorized target, records responses, builds an AI Attack Knowledge Graph, and emits
reports. Core is standard-library only; no telemetry; no outbound calls except to the
target the operator configures (and web/LLM features only if explicitly enabled).

## Assets to protect
1. **Target credentials** — API keys/tokens in the target config and request headers.
2. **Elicited secrets** — the disclosure probe intentionally causes the target to reveal
   secrets; these appear in responses.
3. **Assessment artifacts** — reports, JSON, HAR, evidence SVGs, replay bundles.
4. **Audit/chain-of-custody log** — hash-chained record of what was sent/received.

## Trust boundaries (of the tool)
- Operator ↔ CLI (trusted operator, authorized use enforced by `--authorized`).
- CLI ↔ target (untrusted target; responses are attacker-influenced data).
- CLI ↔ plugins (plugins are FULLY TRUSTED code; see below).
- Artifacts ↔ downstream readers/storage (may be less trusted than the operator).

## Threats and current mitigations
| Threat | Mitigation | Status |
|---|---|---|
| Elicited secrets persisted in cleartext | Default redaction of secret-shaped content in all artifacts; raw only via `--store-raw`; optional at-rest encryption (`--encrypt-evidence`, `crypto` extra) | **Implemented** |
| Target auth leaking into shareable artifacts | Replay bundles strip headers; config not embedded in reports | Implemented |
| Tampering with evidence | Hash-chained audit log; per-finding evidence hash computed on the ORIGINAL before redaction | Implemented (integrity, not secrecy) |
| Malicious/compromised plugin | Plugins load only with `--allow-plugins` + a printed trust warning; version-gated | Implemented (NO sandbox — plugins run as the operator) |
| Malicious target response causing report XSS | All model-derived text is HTML-escaped before embedding; SVG content escaped | Implemented; URL-scheme allowlist for links is **Roadmap** |
| Supply-chain compromise of the tool | Zero runtime deps; SBOM generation (`tools/gen_sbom.py`); pinned CI tools | Implemented (SBOM); **release signing is Roadmap** |
| SSRF / unauthorized targeting | `--authorized` gate; operator-supplied URL only | Implemented (operator responsibility) |
| Transport interception | HTTPS with stdlib certificate verification (defaults on) | Implemented |

## Explicit non-guarantees / limitations
- **No plugin sandbox.** Plugins execute arbitrary Python with the operator's privileges.
- **At-rest encryption is opt-in** and requires the `crypto` extra; default artifacts are
  redacted plaintext (human- and machine-readable), NOT encrypted.
- **Redaction is pattern-based** (API-key/AWS/password/PEM shapes). Novel secret formats
  may evade it. It reduces, not eliminates, exposure. Review artifacts before sharing.
- **No release signing / provenance attestation yet** (Roadmap).
- **Efficacy is not independently validated** (see `docs/reports/*`, Evidence classes).
  Findings are hypotheses until confirmed; the Indicative Risk Index is uncalibrated.

## Maturity
Release Candidate (1.0.0rc1). Security-relevant handling (redaction, plugin consent,
audit) is Implemented and tested. Live external-tool validation and release signing are
outstanding GA gates.

## Supported deployment models
- **Analyst workstation / CI runner (recommended):** offline core, redacted artifacts,
  authorized targets only.
- **Sandboxed engagement host:** for `--store-raw` engagements handling live secrets,
  with `--encrypt-evidence` and restricted artifact access.
- **NOT supported:** unattended fleet/multi-tenant service, or running untrusted plugins.
