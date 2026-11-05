# GLASSCAGE — Handover Brief

*Prepared 5 Nov 2026. Checked against the live repo and verified with a full test run.*

## 1. What the project is
GLASSCAGE is an open-source Python AI security assessment platform built around a graph-native substrate, the **AAKG** (AI Attack Knowledge Graph). It probes AI targets (chat, REST, and MCP surfaces), records findings with evidence and chain of custody, and produces reports in JSON, Markdown, HTML, and SARIF, plus replay bundles.

## 2. Access and setup
- **Repo:** `github.com/Shashankt255/glasscage` (private).
- **HEAD:** latest on `main`. Last tagged release: none (rc4 prepared, not yet tagged).
- **Version:** `1.0.0rc4` (`pyproject.toml`). Requires Python >= 3.10.
- **Entry point:** `glasscage = cli:main` or `python cli.py`.
- **Setup:**
  ```bash
  python3 -m venv venv && source venv/bin/activate
  pip install -e .
  pytest -q          # 997 passed, 89 subtests in ~18s
  ```

## 3. What was done this session

### P0 Coverage Credibility: VERIFIED FIXED
- Ran `glasscage --demo` end-to-end, inspected JSON/MD/HTML output
- `runtime_coverage_ratio` (7/13, 0.54) correctly appears in both MD and HTML reports
- `EC.MEASURED` is applied only to the honest runtime figure
- Graph-derived coverage tagged `[Observed]` (contextual, mixed provenance)
- `aakg/posture.py` reads `coverage_ratio` (0.77) for internal scoring — **by design**, not a defect (posture computed before `run_measured_coverage` is attached)
- Coverage caveat present in all outputs
- **P0 is formally closed.**

### Dependabot PRs
- PR #1 merged via `gh pr merge` (actions/checkout v4→v7)
- PRs #2-#4 applied locally as PR34 commit: setup-python v5→v7, upload-artifact v4→v7, action-gh-release v2→v3
- **Blocked on push:** OAuth token lacks `workflow` scope. Run `gh auth login --scopes workflow` to push.
- PRs #2-#4 should be closed after push with comment "Subsumed by PR34 commit on main."

### Release Prep (rc4)
- Version bumped: `1.0.0rc3` → `1.0.0rc4` in pyproject.toml, CITATION.cff
- `OWNER/REPO` sentinel replaced with `Shashankt255/glasscage` in: pyproject.toml, README.md, CITATION.cff, .github/ISSUE_TEMPLATE/config.yml
- README test count updated: 192 → 997
- CHANGELOG `[Unreleased]` → `[1.0.0rc4]`
- RELEASE_CHECKLIST.md updated with completed items
- Build verified: `glasscage-1.0.0rc4.tar.gz` + wheel built successfully
- **Not yet tagged or released** — pending push and user decision

### Legacy/Graph Dual-Path Audit
Findings:
| Module | Runs on default path? | Reaches user? | Status |
|---|---|---|---|
| `graph.py:build_graph()` | Yes | Yes — HTML Mermaid diagram | Active, not legacy |
| `graph.py:summary_line()` | Yes | Yes — recon.notes | Active, not legacy |
| `coverage.py:build()` | Yes | Partially — feeds `scoring.score()` | Active, one field |
| `coverage.py:statement()` | Yes | Yes — HTML coverage text | Active, user-facing |
| `coverage.py:is_delivered()` | Yes | Indirectly | Utility function |
| `coverage.py:run_measured()` | Yes | Yes — both paths | Utility function |
| `trust.py:build()` | No | No | Legacy only (--no-aakg) |
| `chain.py:build()` | No | No | Legacy only (--no-aakg) |
| `posture.py:compute()` | No | No | Legacy only (--no-aakg) |

**Key finding:** VERSIONING.md says "`coverage` is deprecated" but `coverage.py:statement()` and `coverage.py:build()` are actively used on the default path. Removing `coverage.py` in a future major would break the default path.

## 4. Pending commits (not pushed)
Two commits staged on local `main`:
1. `ci: bump remaining GitHub Actions to latest majors (PR34)` — workflow file changes
2. Release prep: version bump, OWNER/REPO fix, README update, CHANGELOG, RELEASE_CHECKLIST

To push: `gh auth login --scopes workflow` then `git push origin main`.

## 5. What's next (priority order)
1. **Push pending commits** — needs `workflow` scope on GitHub token
2. **Close Dependabot PRs #2-#4** — comment "Subsumed by PR34"
3. **Tag rc4** — `git tag v1.0.0rc4 && git push origin v1.0.0rc4`
4. **Real-target validation** — run against an actual LLM (blocks GA)
5. **Document the dual-path** — update VERSIONING.md to clarify that `coverage.py` functions remain active
6. **Lint cleanup** — 175 ruff errors (advisory, not blocking)
7. **Fresh-clone smoke test** — on Windows/Linux/macOS (release checklist)
8. **GA release (1.0.0)** — after real-target validation campaign

## 6. Engineering rules (unchanged)
1. Never redesign approved architecture (ADRs 0001-0032 are binding)
2. No unnecessary abstractions
3. Backward compatibility always
4. One small PR at a time with tests, docs, ADR, CHANGELOG
5. Inspect repo before proposing code
6. Never fabricate test results
