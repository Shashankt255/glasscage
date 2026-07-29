# Profiling Report — 1.0.0rc1

Method: `tools/profile_run.py` (cProfile + tracemalloc, stdlib), 50 engine runs against
the L2 reference agent with 2 schema tools.

## Runtime hotspots (cumulative)
| Function | Share | Note |
|---|---|---|
| `aakg/build.build_graph` | ~28% | dominant; node/edge construction per run |
| `evidence.render_svg` (via `capture_all`) | ~13% | SVG evidence cards; disable with `--no-evidence` |
| `stats.TrialRunner.run` | ~12% | probe execution wrapper |
| `refagent.send` | ~9% | in-process harness (test only; real targets are network-bound) |
| `aakg` analyses via `cached` | ~9% | memoized after first call |

## Memory
Peak **831 KiB** across 50 runs (tracemalloc). Graph for the reference target: ~80
nodes / ~110 edges. Memory scales linearly with graph size; no leaks observed across
repeated runs (peak stable).

## Bottleneck analysis
Graph construction is the single largest cost and grows with tool/finding count. Path
enumeration is bounded (`max_depth=6`) and cached. For large agentic targets, path
enumeration would become dominant — first optimization target is memoized sub-path
reuse / depth pruning (Roadmap).

## Actions taken
- Added analysis cache (paths/trust/blast computed once per graph; ~56x on repeat calls).
- `--no-evidence` removes the SVG rendering cost when not needed.
