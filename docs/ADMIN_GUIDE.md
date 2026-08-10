# GLASSCAGE Administrator Guide — 1.0.0rc3

For those deploying, securing, and governing GLASSCAGE. See `docs/THREAT_MODEL.md`
for the full threat model of the tool itself.

---

## 1. Supported deployment models

| Model | Status | Notes |
|---|---|---|
| **Analyst workstation** | **Supported** | default posture: offline core, redacted artifacts, authorized targets only |
| **CI runner** | **Supported** | pin the version; treat artifacts as sensitive; `--log-json` for pipeline logs |
| **Sandboxed engagement host** | **Supported** | required for `--store-raw`; pair with `--encrypt-evidence` and restricted artifact access |
| **Unattended fleet / multi-tenant service** | **NOT SUPPORTED** | no persistence, no async, no tenancy model. Do not attempt. |

---

## 2. Security posture of the tool

**Zero runtime dependencies** (stdlib only). No telemetry. No outbound connections
except to the target you configure — and to an LLM provider only if you explicitly
enable `--judge`.

| Control | Status |
|---|---|
| Secret redaction in all artifacts | **Implemented — default on** |
| Raw evidence only on explicit consent (`--store-raw`) | **Implemented** |
| Encrypted evidence at rest (`crypto` extra, real Fernet) | **Implemented — optional** |
| Chain of custody (hash computed pre-redaction) | **Implemented** |
| Hash-chained audit log | **Implemented** — detects alteration of any recorded field; stores digests, not payloads; tail truncation needs an external anchor (ADR 0019) |
| Replay bundles strip auth headers | **Implemented** |
| Config validation with typed errors | **Implemented** |
| TLS certificate verification (stdlib defaults) | **Implemented** |
| Plugin consent gate (`--allow-plugins`) | **Implemented** |
| HTML report escapes all model-derived text | **Implemented** |
| SBOM generation (`tools/gen_sbom.py`) | **Implemented** |
| **Plugin sandbox** | **NOT PROVIDED** — documented design position |
| **Release signing / provenance** | **Roadmap** — supply-chain gap |
| **URL-scheme allowlist in report links** | **Roadmap** — `javascript:`/`data:` hrefs not blocked |

---

## 3. Handling assessment artifacts as sensitive data

Assessment output can contain target credentials and, if `--store-raw` is used, **live
secrets elicited from the target**.

**Policy recommendations:**
1. Default (redacted) artifacts: treat as **Confidential**.
2. `--store-raw` artifacts: treat as **Secret**. Sandboxed host, encrypted at rest,
   short retention, documented destruction.
3. Never commit `*_evidence/`, `*.har`, or `*.json` outputs to a repository.
4. Review before sharing — redaction is pattern-based and may miss novel formats.

```bash
# Encrypted evidence, password from environment
export GLASSCAGE_EVIDENCE_PASSWORD='...'
python -m glasscage --config t.json --authorized --encrypt-evidence --out engagement
```

---

## 4. Plugin governance

Plugins execute **arbitrary Python with the operator's privileges. There is no
sandbox.** GLASSCAGE requires explicit consent and prints a warning:

```bash
python -m glasscage --demo --plugins ./myprobes --allow-plugins --out r
# WARNING: loading plugins from './myprobes'. Plugins run as arbitrary code
# with your privileges (no sandbox). Only load trusted plugins.
```

Without `--allow-plugins` the run is refused (exit 2).

**Recommended policy:** allowlist plugin directories; review plugin source; pin
`GLASSCAGE_PLUGIN_API` major version; do not load third-party plugins on hosts with
production credentials.

---

## 5. Supply chain

```bash
python tools/gen_sbom.py > sbom.json   # CycloneDX; 0 runtime deps, 56 hashed modules
```

- **Zero runtime dependencies** — the smallest possible dependency attack surface.
- **Extras are opt-in**: `crypto` (cryptography), `llm` (anthropic), `yaml`, `rich`.
- **Release signing is not yet implemented** (Roadmap). Until then, verify provenance
  out-of-band and pin versions in CI.

---

## 6. Logging & monitoring

```bash
python -m glasscage --config t.json --authorized --log-json --log-level INFO --out r
```

Emits one JSON object per record (stdlib formatter) suitable for SIEM ingestion.
Library modules never configure handlers; only the CLI/application does.

> **Limitation:** 16 broad exception handlers remain. A probe can fail and be recorded
> as a note rather than surfaced loudly — a failure can therefore become a silent
> coverage gap. Run with `--log-level DEBUG` when results look thin.

---

## 7. Versioning & upgrades

Semantic versioning; see `VERSIONING.md`. **Stable within a major:** `Engine.run()`
result keys, `Finding`/`Status`/`Severity` fields, `Probe` contract, `tal.Tier`,
`aakg.PropertyGraph` public methods, adapter base class, plugin SDK, `errors.*`,
documented CLI flags.

**Deprecated:** `--no-aakg` and the legacy `posture`/`coverage`/`chain`/`trust`
modules — removal planned in the next major.

---

## 8. Vulnerability reporting

See `SECURITY.md`. **Note for maintainers: the security contact in `SECURITY.md` is
currently a placeholder and MUST be replaced before public release.** A disclosure
policy with a non-working address is worse than none.
