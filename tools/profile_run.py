#!/usr/bin/env python3
"""Profile a GLASSCAGE run (cProfile + tracemalloc, stdlib only).

Usage: python tools/profile_run.py [--top N]
Prints the hottest functions and peak memory for an end-to-end graph run.
"""
import argparse, cProfile, io, pstats, sys, tracemalloc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage import schema

TOOLS = schema.ingest({"functions": [
    {"name": "get_secret", "description": "vault", "parameters": {}},
    {"name": "run_sql", "description": "db", "parameters": {}}]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()
    tracemalloc.start()
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(50):
        Engine(ReferenceAgent(), schema_tools=TOOLS).run()
    pr.disable()
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    s = io.StringIO()
    pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(args.top)
    print(s.getvalue())
    print(f"peak memory over 50 runs: {peak/1024:.1f} KiB")


if __name__ == "__main__":
    main()
