# Performance Report — 1.0.0rc1

Method: `tools/benchmark_perf.py`, in-process (no network), reference agent target.

## Engine run time by tool count (graph path, default)
| Tools | Mean | SD |
|---|---|---|
| 0 | ~2.7 ms | 0.7 |
| 2 | ~2.7 ms | 0.3 |
| 5 | ~2.8 ms | 0.3 |
| 10 | ~3.1 ms | 0.8 |
| 20 | ~4.1 ms | 1.0 |

Roughly linear in graph size; sub-5 ms through 20 tools.

## Legacy vs graph (5 tools)
Legacy `--no-aakg` ~1.2 ms · graph ~2.7 ms · overhead ~1.5 ms for substantially more
analysis (paths, 5-taxonomy coverage, prioritized remediation, blast).

## Graph stage timings (10 tools)
build ~0.51 ms · paths ~0.16 ms · trust ~0.18 ms · blast ~0.06 ms.

## Caching
Repeated analysis calls (posture/remediation/report reusing paths/trust/blast) drop
from ~0.07 ms to ~0.001 ms — **~56x** — via the mutation-invalidated graph cache.

## Memory
Peak ~831 KiB over 50 runs; no growth across runs.

## Note
Real-world latency is dominated by target network round-trips (probe `send` calls),
not GLASSCAGE compute. The numbers above isolate framework overhead.
