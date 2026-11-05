#!/usr/bin/env python3
"""Performance benchmarks across graph sizes (stdlib only).

Usage: python tools/benchmark_perf.py [--json]
Measures engine run time and per-stage graph analysis across increasing tool counts.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from glasscage import schema
from glasscage.aakg import blast, paths, trust_graph
from glasscage.aakg import build as B
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent


def _tools(n):
    return schema.ingest({"functions": [
        {"name": f"tool_{i}", "description": ["vault secret", "database", "exec"][i % 3],
         "parameters": {}} for i in range(n)]})


def bench_engine(n_tools, runs=20, use_aakg=True):
    t = _tools(n_tools)
    xs = []
    for _ in range(runs):
        s = time.perf_counter()
        Engine(ReferenceAgent(), schema_tools=t, use_aakg=use_aakg).run()
        xs.append((time.perf_counter() - s) * 1000)
    return round(statistics.mean(xs), 2), round(statistics.pstdev(xs), 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = {"engine_ms": {}, "legacy_vs_graph": {}, "graph_stages_ms": {}}
    for n in (0, 2, 5, 10, 20):
        mean, sd = bench_engine(n)
        report["engine_ms"][f"{n}_tools"] = {"mean": mean, "sd": sd}
    lg, _ = bench_engine(5, use_aakg=False)
    gg, _ = bench_engine(5, use_aakg=True)
    report["legacy_vs_graph"] = {"legacy_ms": lg, "graph_ms": gg,
                                 "overhead_ms": round(gg - lg, 2)}
    res = Engine(ReferenceAgent(), schema_tools=_tools(10)).run()
    g = B.build_graph(res["recon"], res["findings"], None, None, "L2", "x")
    for name, fn in (("build", lambda: B.build_graph(res["recon"], res["findings"], None, None, "L2", "x")),
                     ("paths", lambda: paths._build_paths(g)),
                     ("trust", lambda: trust_graph._analyze(g)),
                     ("blast", lambda: blast._summary(g))):
        xs = []
        for _ in range(50):
            s = time.perf_counter(); fn(); xs.append((time.perf_counter() - s) * 1000)
        report["graph_stages_ms"][name] = round(statistics.mean(xs), 3)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Engine run time by tool count:")
        for k, v in report["engine_ms"].items():
            print(f"  {k:10} {v['mean']:.2f} ms (sd {v['sd']})")
        print(f"legacy vs graph (5 tools): {report['legacy_vs_graph']}")
        print("graph stage timings (10 tools):", report["graph_stages_ms"])
    return report


if __name__ == "__main__":
    main()
