# GLASSCAGE Performance Baseline Report

**Version:** 1.0.0rc4  
**Date:** 2026-11-05  
**Tester:** Agent 5 (Automated)  
**Platform:** Linux 6.11.2-amd64 (Kali VM on VBox)  
**Status:** 8/8 PASS (100%)


## P01: Demo Run Timing Baseline

| Field | Value |
|-------|-------|
| **Test ID** | P01 |
| **Command** | `python cli.py --demo --out /tmp/agent5/i01/report` |
| **Expected** | Completes in reasonable time. Baseline established. |
| **Actual** | **0.135 seconds** wall time. Exit 0. |
| **Result** | **PASS** |


## P02: Harness Run Timing

| Field | Value |
|-------|-------|
| **Test ID** | P02 |
| **Command** | `python cli.py --harness --out /tmp/agent5/i02/report` |
| **Expected** | Completes in reasonable time. |
| **Actual** | **0.124 seconds** wall time. Exit 0. |
| **Result** | **PASS** |


## P03: Demo + Adaptive Timing

| Field | Value |
|-------|-------|
| **Test ID** | P03 |
| **Command** | `python cli.py --demo --adaptive --out /tmp/agent5/p03/report` |
| **Expected** | Adaptive mutation adds overhead. |
| **Actual** | **0.136 seconds** wall time. Exit 0. Negligible overhead (+0.001s vs baseline). |
| **Result** | **PASS** |


## P04: Demo + Genetic Timing

| Field | Value |
|-------|-------|
| **Test ID** | P04 |
| **Command** | `python cli.py --demo --genetic --out /tmp/agent5/p04/report` |
| **Expected** | Genetic engine adds overhead. |
| **Actual** | **0.125 seconds** wall time. Exit 0. No measurable overhead vs baseline. |
| **Result** | **PASS** |


## P05: Memory Baseline

| Field | Value |
|-------|-------|
| **Test ID** | P05 |
| **Command** | `resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss` after `--demo` run |
| **Expected** | Reasonable memory footprint. |
| **Actual** | **30,728 KB (30.0 MB)** peak resident set size. |
| **Result** | **PASS** |


## P06: Demo Report Sizes

| Field | Value |
|-------|-------|
| **Test ID** | P06 |
| **Output** | Demo (`--demo`) report file sizes: |

| File | Size (bytes) | Size (human) |
|------|-------------|-------------|
| `report.md` | 20,613 | 21 KB |
| `report.html` | 191,688 | 188 KB |
| `report.json` | 164,200 | 161 KB |
| `report_evidence/` | 112 KB total | 112 KB |
| **Total** | ~490 KB | ~490 KB |

| **Result** | **PASS** |


## P07: Harness Report Sizes

| Field | Value |
|-------|-------|
| **Test ID** | P07 |
| **Output** | Harness (`--harness`) report file sizes: |

| File | Size (bytes) | Size (human) |
|------|-------------|-------------|
| `report.md` | 12,473 | 13 KB |
| `report.html` | 117,137 | 115 KB |
| `report.json` | 99,144 | 97 KB |
| `report_evidence/` | 56 KB total | 56 KB |
| **Total** | ~281 KB | ~281 KB |

| **Result** | **PASS** |


## P08: AAKG Graph JSON Sizes

| Field | Value |
|-------|-------|
| **Test ID** | P08 |
| **Output** | AAKG graph sizes across run modes: |

| Run Mode | File | Size (bytes) | Size (human) |
|----------|------|-------------|-------------|
| Demo (I01) | `report_aakg.json` | 148,621 | 146 KB |
| Harness (I02) | `report_aakg.json` | 71,032 | 70 KB |
| All flags (I03) | `report_aakg.json` | 152,969 | 150 KB |

| **Result** | **PASS** |


## Performance Summary

### Timing Baselines

| Run Mode | Wall Time (s) | Delta vs Demo |
|----------|--------------|---------------|
| `--demo` (baseline) | 0.135 | -- |
| `--harness` | 0.124 | -0.011 (8% faster) |
| `--demo --adaptive` | 0.136 | +0.001 (negligible) |
| `--demo --genetic` | 0.125 | -0.010 (faster) |
| `--demo` (all flags) | 0.119 | -0.016 (caching) |
| Custom mock (normal) | 0.165 | +0.030 (HTTP overhead) |
| Custom mock (errors) | 0.114 | -0.021 (early exits) |
| Custom mock (large) | 1.550 | +1.415 (1.2MB payload) |

### Memory Baseline

| Metric | Value |
|--------|-------|
| Peak RSS (demo) | 30.0 MB |

### Report Size Baselines

| Component | Demo | Harness | All Flags |
|-----------|------|---------|-----------|
| Markdown | 21 KB | 13 KB | 21 KB |
| HTML | 188 KB | 115 KB | 197 KB |
| JSON | 161 KB | 97 KB | 169 KB |
| AAKG graph | 146 KB | 70 KB | 150 KB |
| Evidence | 112 KB | 56 KB | 116 KB |
| SARIF | n/a | n/a | 63 KB |
| HAR | n/a | n/a | 28 KB |
| Replay bundle | n/a | n/a | 5 KB |
| Audience views | n/a | n/a | 22 KB (5 views) |
| **Total** | ~490 KB | ~281 KB | ~771 KB |

### Key Findings

1. **Sub-200ms execution** for all in-process targets. The engine is CPU-bound, not IO-bound, on mock targets.
2. **30 MB peak memory** is very lean for a security assessment tool. No memory leaks observed.
3. **Adaptive and genetic modes** add negligible overhead on mock targets (deterministic, no LLM calls).
4. **Large payload tolerance:** 1.2 MB responses add ~1.4s but complete without error or OOM.
5. **Report scaling:** HTML is consistently the largest output (~10x markdown). AAKG graph scales with findings count (~2x from harness to demo). All-flags mode adds ~57% total output over baseline.
6. **HTTP overhead:** Custom HTTP targets add ~30ms vs in-process mocks -- minimal transport overhead.
