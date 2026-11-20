# GLASSCAGE — Handover Brief

*Updated 20 Nov 2026. Verified against the live repo, full test run, and GitHub release.*

## 1. What the project is
GLASSCAGE is an open-source Python AI security assessment platform built around a graph-native substrate, the **AAKG** (AI Attack Knowledge Graph). It probes AI targets (chat, REST, and MCP surfaces), records findings with evidence and chain of custody, and produces reports in JSON, Markdown, HTML, and SARIF, plus replay bundles.

## 2. Access and setup
- **Repo:** `github.com/Shashankt255/glasscage` (public).
- **Release:** `v1.0.0` — https://github.com/Shashankt255/glasscage/releases/tag/v1.0.0
- **Version:** `1.0.0` (`pyproject.toml`). Requires Python >= 3.10.
- **Entry point:** `glasscage = cli:main` or `python cli.py`.
- **Setup:**
  ```bash
  pip install glasscage
  # or from source:
  git clone https://github.com/Shashankt255/glasscage.git
  cd glasscage && pip install -e .
  pytest -q          # 1132 passed, 89 subtests in ~27s
  ```

## 3. Release history

### v1.0.0 GA — 20 Nov 2026
All GA blockers resolved. First stable release.

**What was done (Nov 20 session):**
- **Real-target validation:** Ran against Ollama llama3.2 (3.2B, local). Result: Grade D, risk score 47.5, 25 findings (7 vulnerable, 5 medium, 2 low), 42 probes, target reachable. All output formats generated (JSON/MD/HTML/SARIF/HAR/replay/audit log). Previous attempt (Nov 5) failed — target was unreachable.
- **Dual-path documentation:** VERSIONING.md already corrected in a prior session — `coverage.py` correctly documented as active on the default AAKG path, not deprecated.
- **Lint cleanup:** Fixed last ruff I001 error (unsorted import in `engine.py`). 175 → 0 ruff errors.
- **Fresh-clone smoke test:** Cloned from GitHub, `pip install -e .`, 1081 tests passed, `--demo` produced full report with all output formats.
- **Version bump:** `1.0.0rc4` → `1.0.0` in pyproject.toml, CITATION.cff, CHANGELOG.md.
- **Tag + release:** `v1.0.0` tagged, pushed, GitHub release created with sdist + wheel.

**CBH full extraction (Nov 20):**
Extracted complete knowledge base from Claude-BugHunter (elementalsouls, CC BY 4.0 + MIT):

| Data File | Size | Contents |
|---|---|---|
| Data File | Size | Contents |
|---|---|---|
| `glasscage/data/cbh_attack_chains.json` | 71K | 10 vuln classes, 56 patterns, 183 disclosed reports |
| `glasscage/data/cbh_severity_reference.json` | 20K | 94 calibrated finding→severity mappings |
| `glasscage/data/cbh_fp_corpus.json` | 4.7K | 10 AI-reframed FP test cases (7 safe, 3 vulnerable) |
| `glasscage/data/cbh_hunt_strategies.json` | 1.8M | 83 hunt skills, 2092 sections, 1122 report refs |
| `glasscage/data/cbh_eval_corpus.json` | 9.8K | 9 PS labs + 6 hard + 3 Juice Shop + 10 FP cases |
| `glasscage/data/cbh_cve_index.json` | 7.1K | 30 KEV CVE gaps, 91 indexed, 1592 total |
| `glasscage/data/cbh_engine_reference.json` | 16K | 47 class weights, 47 skill maps, 47 probes, scope rules, ROE template, recon patterns, 12 secret detectors |
| `glasscage/data/cbh_workflows.json` | 75K | 15 command workflows (autopilot, chain, hunt, intel, recon, report, scope, surface, validate, etc.) |
| `glasscage/data/cbh_disclosed_reports.json` | 327K | 36 vuln-class pattern libraries with cited examples and test patterns |

| Loader Module | Functions |
|---|---|
| `chain_reference.py` | `chains_for()`, `severity_reference()`, `severity_for_finding()` |
| `hunt_strategies.py` | `strategies()`, `strategy_for()`, `strategies_for_class()` |
| `eval_corpus.py` | `portswigger_labs()`, `juice_shop_challenges()`, `fp_cases()`, `cve_gaps()`, `cve_gap_for()` |
| `engine_reference.py` | `class_weights()`, `class_skill_map()`, `weight_for()`, `phases()`, `recon_patterns()`, `workflows()`, `workflow_for()` |
| `disclosed_reports.py` | `reports()`, `report_for()`, `cited_examples_for()`, `patterns_for()` |

**Integration:** `kb.py` enrichment attaches `web_attack_chains` to findings, showing how AI-layer vulns chain to web-layer impact (e.g., LLM01 Prompt Injection → SSRF via tool-use, RCE via code-exec).

**CBH Tier 2 extraction (Nov 20, same session):**

| Data File | Contents |
|---|---|
| `cbh_verification_labs.json` | 13 verification writeups (Apache, Jenkins, Spring, Juice Shop, JWT, SSTI, SAML, Smuggling, LLM, Cloud, Playwright, HackerOne VDP) |
| `cbh_lab_apps.json` + `cbh_labs/` | 7 runnable lab apps (Flask + Docker) |
| `cbh_mcp_tools.json` + `cbh_hackerone_mcp.py` | HackerOne MCP server (7 tools, 468 lines) |
| `cbh_recon_manifest_schema.json` | Recon→hunt JSON Schema |
| `cbh_engagement_example.json` | Engagement config example |
| `cbh_plugin_manifest.json` | Claude Code plugin v2.1.0 |
| `cbh_design_docs.json` | 4 design docs (autopilot ledger + H1 report body fetch) |

| Loader Module | Functions |
|---|---|
| `integration_reference.py` | `mcp_tools()`, `mcp_tool_for()`, `recon_manifest_schema()`, `engagement_example()`, `plugin_manifest()`, `design_docs()`, `design_doc_for()` |
| `verification_labs.py` | `labs()`, `lab_for()`, `labs_for_class()`, `lab_apps()` |

**CBH source:** `/home/kali/extraction-workspace/Claude-BugHunter/` (clone of elementalsouls/Claude-BugHunter)
**CBH extraction status: COMPLETE** — All Tier 1 + Tier 2 assets extracted, tested, and pushed.

### v1.0.0rc4 — 5 Nov 2026
- P0 coverage credibility: VERIFIED FIXED
- Dependabot PRs: #1 merged, #2-4 closed (subsumed by PR34)
- CI bumps: GitHub Actions to latest majors
- Release prep: version bump, OWNER/REPO sentinels fixed, CHANGELOG tagged

### Legacy/Graph Dual-Path Audit (reference)
| Module | Runs on default path? | Reaches user? | Status |
|---|---|---|---|
| `graph.py:build_graph()` | Yes | Yes — HTML Mermaid diagram | Active |
| `graph.py:summary_line()` | Yes | Yes — recon.notes | Active |
| `coverage.py:build()` | Yes | Partially — feeds `scoring.score()` | Active |
| `coverage.py:statement()` | Yes | Yes — HTML coverage text | Active |
| `coverage.py:is_delivered()` | Yes | Indirectly | Active |
| `coverage.py:run_measured()` | Yes | Yes — both paths | Active |
| `trust.py:build()` | No | No | Legacy (--no-aakg) |
| `chain.py:build()` | No | No | Legacy (--no-aakg) |
| `posture.py:compute()` | No | No | Legacy (--no-aakg) |

## 4. Real-target validation results
- **Target:** Ollama llama3.2 (3.2B, Q4_K_M, CPU-only, local)
- **Config:** `my_target.json` (http://127.0.0.1:11434/api/chat)
- **Grade:** D | **Risk Score:** 47.5 | **Posture:** Impact demonstrated
- **Findings:** 25 total — 7 vulnerable (5 medium, 2 low), 4 inconclusive, 6 passed, 4 error, 4 not_assessable
- **Probes:** 42 (adaptive mode)
- **Key vulns found:** prompt injection, indirect injection, agent goal hijack, long-context injection, adaptive guardrail bypass, secret disclosure, system prompt extraction
- **Output files:** `ollama_validation.*` (json/md/html/sarif/har/replay) + `audit_validation.jsonl`

## 5. What's next (priority order)
1. **Make repo public** — user decision pending
2. **PyPI publish** — optional (`twine upload dist/*`)
3. **Multi-target validation campaign** — run against different LLMs (GPT, Claude, Gemini endpoints) for broader coverage
4. **Independent validation** — efficacy not independently validated (stated in CITATION.cff)
5. **Fresh-clone smoke on Windows/macOS** — Linux verified, other OS pending

## 6. Engineering rules (unchanged)
1. Never redesign approved architecture (ADRs 0001-0032 are binding)
2. No unnecessary abstractions
3. Backward compatibility always
4. One small PR at a time with tests, docs, ADR, CHANGELOG
5. Inspect repo before proposing code
6. Never fabricate test results
