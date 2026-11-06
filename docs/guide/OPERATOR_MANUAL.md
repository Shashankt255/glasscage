# GLASSCAGE Operator Manual — 1.0.0rc3

For the person running assessments. Assumes you have read the
[User Guide](USER_GUIDE.md) core concepts.


## 1. Authorization — non-negotiable

GLASSCAGE is an offensive tool. Live targets require `--authorized`, which is your
assertion that you own the system or hold **written** permission to test it.

```bash
--authorized                       # required for any --config target
--scope api.example.com staging.example.com   # hostname allowlist (defence in depth)
--rate 2                           # max requests/second — be polite
```

`--demo` and `--harness` need no authorization: they never leave the process.


## 2. Modes of operation — all **Implemented**

| Mode | Command | Use |
|---|---|---|
| Mock | `--demo` | smoke-test the tool itself |
| Reference harness (L2) | `--harness` | see agentic analysis work end-to-end |
| Live target | `--config t.json --authorized` | a real assessment |
| MCP manifest | `--mcp-manifest m.json` | **configuration review** of an MCP manifest |
| MCP rug-pull diff | `--mcp-manifest new.json --mcp-baseline old.json` | detect tool-definition drift |
| Benchmark | `--benchmark benchmark/corpus.json` | detector precision/recall (**Experimental** corpus) |
| Adapter run | `--orchestrate garak pyrit` | **Pending External Validation** |
| Adapter validation | `--validate-adapters` | honest parser status |
| Report diff | `--diff old.json new.json` | compare two runs |


## 3. Full flag reference

### Target & scope
| Flag | Maturity | Notes |
|---|---|---|
| `--config PATH` | Implemented | JSON target config; validated on load |
| `--demo` | Implemented | built-in mock (L0) |
| `--harness` | Implemented | built-in L2 reference agent |
| `--authorized` | Implemented | **required** for live targets |
| `--scope HOST...` | Implemented | hostname allowlist |
| `--rate N` | Implemented | requests/second cap |
| `--schema PATH` | Implemented | OpenAPI/function/MCP schema → schema-confirmed tools |
| `--architecture PATH` | Implemented | declared controls (**trusted, not verified** — §6.4 User Guide) |
| `--arch-template` | Implemented | print a blank architecture questionnaire |

### Attack engines
| Flag | Maturity | Notes |
|---|---|---|
| *(default)* | Implemented | 21 probes; 18 active, 3 questionnaire-only |
| `--adaptive` | Implemented | mutation loop over a single payload |
| `--genetic` | Implemented | evolutionary payload search (seeded) |
| `--judge` | **Experimental** | LLM-as-judge; requires `llm` extra + API key |
| `--trials N` | Implemented | repeat each probe N times → Wilson CIs |
| `--seed N` | Implemented | deterministic replay |

### Evidence & safety
| Flag | Maturity | Notes |
|---|---|---|
| *(default)* | Implemented | **secrets redacted in every artifact** |
| `--store-raw` | Implemented | **CONSENT: writes live secrets to disk.** Sandboxed hosts only |
| `--encrypt-evidence` | Implemented | encrypt evidence dir; needs `crypto` extra |
| `--evidence-password PW` | Implemented | or `GLASSCAGE_EVIDENCE_PASSWORD` |
| `--no-evidence` | Implemented | skip SVG evidence cards (faster) |
| `--har` | Implemented | HTTP archive (redacted unless `--store-raw`) |
| `--audit-log PATH` | Implemented | hash-chained custody log; records payload digests, not payloads. Detects an altered entry, not a truncated tail (ADR 0019) |

### Output
| Flag | Maturity | Notes |
|---|---|---|
| `--out BASE` | Implemented | basename for all artifacts |
| `--views AUDIENCE...` | Implemented | `executive security developer incident_response compliance` or `all` |
| `--sarif` | Implemented | SARIF 2.1.0 for code-scanning platforms |
| `--replay` | Implemented | reproducible replay bundle (auth stripped) |
| `--no-aakg` | Implemented (deprecated) | legacy engines; **removal planned next major** |

### Plugins & logging
| Flag | Maturity | Notes |
|---|---|---|
| `--plugins DIR` | Implemented | **requires `--allow-plugins`** |
| `--allow-plugins` | Implemented | **CONSENT: arbitrary code, no sandbox** |
| `--log-level LEVEL` | Implemented | DEBUG/INFO/WARNING/ERROR |
| `--log-json` | Implemented | structured JSON logs for SIEM |


## 4. Evidence handling — read before a client engagement

**Default is safe.** Secret-shaped content is masked in every written artifact
(reports, JSON, HAR, evidence cards) as stable `[REDACTED:<8hex>]` tokens — identical
secrets produce identical tokens, so you can correlate without exposure.

**Chain of custody is preserved:** the evidence hash is computed on the **original**
response *before* redaction. Integrity survives sanitisation.

```bash
# Default — safe to share internally
python -m glasscage --config t.json --authorized --out report

# Consent: retain live secrets (sandboxed host only)
python -m glasscage --config t.json --authorized --store-raw --out report

# Encrypt evidence at rest
pip install glasscage[crypto]
python -m glasscage --config t.json --authorized \
  --encrypt-evidence --evidence-password "$PW" --out report
```

> **Limitation:** redaction is pattern-based. Novel secret formats may pass through.
> **Review artifacts before sharing.** Encryption refuses honestly if the `crypto`
> extra is absent — GLASSCAGE ships no homemade cipher.


## 5. Reading exit codes

| Code | Meaning |
|---|---|
| 0 | run completed |
| 2 | refused: missing `--authorized`, missing `--allow-plugins`, bad config, unknown view |


## 6. Operational limits — plan around these

- **Serial execution.** No async, no 429 backoff, no resume. A large engagement takes
  hours and cannot resume on failure. (Roadmap.)
- **Tier reality.** Against a real black-box endpoint (L0/L1), planner/memory/tool
  probes return **NOT ASSESSABLE**. To exercise them you need an instrumented L2 target.
- **Rate limits.** Use `--rate`. GLASSCAGE will not adaptively back off for you.
- **Path enumeration** is bounded at depth 6 with no count cap; very dense agentic
  graphs may be slow.


## 7. Recommended engagement flow

```bash
# 1. Baseline the tool itself
python -m glasscage --harness --out /tmp/sanity

# 2. Capture architecture (only answer what you KNOW — answers are trusted)
python -m glasscage --arch-template > arch.json

# 3. Ingest the tool schema if the target is agentic
#    (schema-confirmed tools materially improve blast-radius accuracy)

# 4. Run, with statistics
python -m glasscage --config t.json --authorized \
  --schema tools.json --architecture arch.json \
  --trials 5 --seed 1 --rate 2 \
  --views all --sarif --replay --out engagement-01

# 5. Confirm every finding manually before reporting it.
```

**Step 5 is not optional.** GLASSCAGE has not been validated against real targets;
its output is a prioritized set of hypotheses for a human to verify.
