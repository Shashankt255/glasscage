# GLASSCAGE — Project State Baseline

**Generated:** 2026-11-06
**Commit:** `cca3f0d1e6f0c4f30c2729446459e661e6026059`
**Branch:** `main`
**Version:** `1.0.0rc4` (pyproject.toml) / `1.0.0rc3` (__version__ attribute)
**Tag:** `v1.0.0rc4` (6 commits ahead: `v1.0.0rc4-6-gcca3f0d`)

## Architecture

GLASSCAGE uses a graph-native architecture centered on the **AI Attack Knowledge Graph (AAKG)**:

```
Target → Probes → Findings + Evidence → AAKG Build
                                          │
    ┌──────────┬──────────┬───────────┬───┴──────┬────────────┐
    ▼          ▼          ▼           ▼          ▼            ▼
Attack Paths  Trust    Blast Radius  Coverage  Posture   Remediation
    └──────────┴──────────┴───────────┴──────────┴────────────┘
                                │
                    Narratives · Story · Views
                                │
                  Markdown · HTML · JSON · SARIF · Replay
```

**Layers:**
- **Substrate:** `aakg/types.py`, `aakg/engine.py` (PropertyGraph), `aakg/build.py`
- **Analysis:** `aakg/paths.py`, `trust_graph.py`, `blast.py`, `posture.py`, `coverage.py`, `remediation.py`
- **Reporting:** `aakg/report.py`, `narrative.py`, `story.py`, `views.py`, `report.py`, `sarif.py`
- **Acquisition:** `probes.py`, `agent_probes.py`, `target.py`, `refagent.py`, `recon.py`, `mcp.py`
- **Targets:** `targets/` subpackage — `application.py`, `binding.py`, `chat.py`, `compat.py`, `discovery.py`, `driver.py`, `rest.py`, `surface.py`
- **Cross-cutting:** `evidence_confidence.py`, `redaction.py`, `stats.py`, `taxonomy.py`, `errors.py`, `config.py`, `plugins.py`
- **Experimental:** `benchmark.py`, `validation.py`, `genetic.py`, `mutation.py`, `orchestrator.py`

## Implemented Capabilities

| Capability | Status | Notes |
|---|---|---|
| Chat target assessment (L0) | Implemented | HTTPChatTarget, OpenAI-compatible |
| REST surface assessment | Implemented | OpenAPI discovery, binding, driver |
| MCP manifest analysis | Implemented | Static analysis only (no runtime) |
| Probe suite (OWASP LLM01-10) | Implemented | 13+ probes, canary-based detection |
| Agent probes (L1/L2) | Implemented | Planner, memory, goal, tool, loop, context |
| Bypass probes | Implemented | Base64, payload-splitting, jailbreak, multilingual |
| Multi-turn erosion | Implemented | Refusal-aware (ADR 0032) |
| Impact chaining | Implemented | Auto follow-up on canary success (NEW) |
| Adaptive mutation attacker | Implemented | `--adaptive` flag |
| Genetic attack engine | Implemented | `--genetic` flag |
| AAKG graph construction | Implemented | 24 node types, 12 edge types |
| Attack path derivation | Implemented | Graph-native |
| Trust boundary model | Implemented | Privilege transitions, violations |
| Blast radius analysis | Implemented | Asset reachability |
| CVSS-style scoring | Implemented | GLSSCG vector format |
| Posture scoring | Implemented | Risk Index 0-100 |
| Evidence chain-of-custody | Implemented | SHA256, append-only JSONL, hash-chained |
| Secret redaction | Implemented | Pattern-based, before persistence |
| SARIF export | Implemented | `--sarif` flag |
| Replay bundles | Implemented | `--replay` flag |
| Report diffing | Implemented | `--diff OLD NEW` |
| HTML interactive report | Implemented | Dashboard, search, tabs, evidence SVGs |
| Markdown report | Implemented | Pentest-style deliverable |
| JSON report | Implemented | Machine-readable |
| HAR export | Implemented | `--har` flag |
| Architecture assessment | Implemented | Defense-in-depth questionnaire |
| Model card review | Implemented | `--model-card` flag |
| System prompt review | Implemented | `--system-prompt` static analysis |
| Audience views | Implemented | Executive, security, developer, IR, compliance |
| Narrative engine | Implemented | 8 strategic readings of graph |
| Story engine | Implemented | 13-section assessment narrative |
| Proxy support | Implemented | Burp Suite interception |
| Plugin system | Implemented | `--plugins` with `--allow-plugins` consent |
| Benchmark corpus | Implemented | Detector P/R measurement |
| Adapter validation | Implemented | Cross-framework honesty |
| Orchestration | Implemented | Multi-tool coordination |
| Rate limiting | Implemented | `--rate` flag |
| Adaptive backoff | Implemented | `--max-retries`, `--backoff` (NEW) |
| Free target | Implemented | `--free` flag with Pollinations AI (NEW) |
| Retry errors | Implemented | `--retry-errors` flag (NEW) |
| Scope enforcement | Implemented | `--scope` hostname allowlist |
| Audit logging | Implemented | `--audit-log` hash-chained JSONL |

## Unsupported Capabilities

| Capability | Status | Notes |
|---|---|---|
| MCP runtime transport | Not implemented | Manifest analysis only, no session lifecycle |
| GraphQL driver | Not implemented | Deferred per architecture doc |
| Function driver | Not implemented | Deferred per architecture doc |
| LLM-as-judge (without API key) | Not implemented | Requires `anthropic` package + key |
| Multimodal probes | Not implemented | Listed as "not tested" in coverage |
| Real-time streaming | Not implemented | Batch assessment only |

## Existing Tests

- **Test files:** 51
- **Test cases:** 1064 collected
- **Test framework:** pytest

### Key test categories:
- Audit integrity and custody (6 files)
- Surface/target architecture (10 files)
- Coverage honesty and provenance (4 files)
- Security hardening (2 files)
- Fuzz testing (1 file)
- CLI safety (2 files)
- Stage-based validation (4 files)
- Probe applicability (1 file)
- Property-based testing (1 file)
- Narrative/story (1 file)

## Test Execution Commands

```bash
# Full suite
python -m pytest -q

# Verbose with tracebacks
python -m pytest -v --tb=short

# Single file
python -m pytest tests/test_glasscage.py -v

# Demo assessment
python cli.py --demo --out demo_report

# Harness assessment
python cli.py --harness --out harness_report

# Live target
python cli.py --config target.json --authorized --out live_report
```

## Dependencies

**Core:** Zero dependencies (Python standard library only)

**Optional:**
- `anthropic>=0.30` — LLM judge / mutation
- `pyyaml>=6` — YAML config support
- `rich>=13` — Pretty CLI output

**Dev:**
- `pytest>=8`
- `ruff>=0.5`
- `mypy>=1.10`
- `build>=1.2`

**Runtime:** Python 3.10+

## Known Limitations

1. MCP is manifest-analysis only — no runtime transport/session.
2. Risk Index is uncalibrated — "Estimated" evidence class, not statistical.
3. No multimodal probe support.
4. Agent probes (L1/L2) require instrumented targets.
5. Genetic/adaptive attackers require LLM judge for full mutation.

## Baseline Test Results

```
1060 passed, 4 failed, 89 subtests passed
Duration: 25.13s
```

**4 failures** (all from uncommitted changes in working tree):
1. `test_custody_completeness::test_demo_surface_is_unchanged` — count mismatch (34 vs 21)
2. `test_custody_completeness::test_harness_surface_is_unchanged` — count mismatch (32 vs 25)
3. `test_harness_custody::test_demo_entry_count_still_equals_its_sends` — count mismatch (34 vs 21)
4. `test_surface_wiring::test_surface_parameter_is_keyword_defaulted_last` — new `impact_chain` parameter

All 4 are attributable to uncommitted feature additions (impact chaining, adaptive backoff) that add probes and Engine parameters. At the tagged `v1.0.0rc4` commit, all 1064 tests passed.

## ADRs

32 Architecture Decision Records in `docs/adr/`, covering:
- Surface/driver foundation (ADR 0001-0009)
- Finding/graph identity (ADR 0010-0011)
- REST execution (ADR 0012-0015)
- Provenance and custody (ADR 0016-0025)
- MCP manifest contract (ADR 0026)
- Coverage honesty (ADR 0027-0029)
- Detection methodology (ADR 0030-0032)

## Working Tree Status

8 modified files and 10 untracked files from current development session:
- Modified: `cli.py`, `config.py`, `engine.py`, `target.py`, `report.py`, `aakg/report.py`, `aakg/story.py`, `README.md`
- New: `impact_chain.py`, `samples/free_targets.json`, test configs, scan reports
