# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Statistical evaluation framework (GLASSCAGE Stage B).

Status: Implemented.

Rationale
---------
LLM targets are non-deterministic; a single probe run is a point estimate with
unknown variance. This module runs each probe over N trials and reports a success
rate with a Wilson score confidence interval, the outcome variance, and a
reproducibility metric (modal-outcome agreement). Deterministic replay is
supported via a seed passed to seed-aware targets (e.g. the reference harness and
the genetic engine), so results are reproducible where the target permits.

Wilson score interval is used instead of the normal approximation because it is
well-behaved at small N and extreme proportions - the common case here.
"""

from __future__ import annotations

import math
from collections import Counter

from .models import Finding, Status


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """Return (point, low, high) for a binomial proportion. z=1.96 -> 95%."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom
    return round(p, 4), round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def aggregate(findings: list[Finding]) -> Finding:
    """Collapse N single-trial findings for the same probe into one aggregate."""
    assert findings, "aggregate requires at least one finding"
    n = len(findings)
    statuses = [f.status for f in findings]
    dist = Counter(s.value for s in statuses)
    successes = sum(1 for s in statuses if s is Status.VULNERABLE)
    point, lo, hi = wilson(successes, n)
    modal = dist.most_common(1)[0]
    reproducibility = round(modal[1] / n, 4)

    # representative finding: prefer a VULNERABLE exemplar, else the modal status
    exemplar = next((f for f in findings if f.status is Status.VULNERABLE), None)
    if exemplar is None:
        modal_status = modal[0]
        exemplar = next(f for f in findings if f.status.value == modal_status)

    # aggregate status: if any trial was vulnerable -> vulnerable (with rate);
    # if all not_assessable -> not_assessable; else modal.
    if successes > 0:
        agg_status = Status.VULNERABLE
    elif all(s is Status.NOT_ASSESSABLE for s in statuses):
        agg_status = Status.NOT_ASSESSABLE
    else:
        agg_status = Status(modal[0])

    exemplar.status = agg_status
    exemplar.trials_run = n
    exemplar.success_rate = point
    exemplar.ci_low = lo
    exemplar.ci_high = hi
    exemplar.reproducibility = reproducibility
    exemplar.status_distribution = dict(dist)
    # confidence reflects the interval width (tighter = more confident)
    exemplar.confidence = round(max(0.1, 1.0 - (hi - lo)), 2) if n > 1 else exemplar.confidence
    return exemplar


class TrialRunner:
    """Runs a probe N times and returns aggregated findings with statistics."""

    def __init__(self, trials: int = 5, seed: int | None = None):
        self.trials = max(1, trials)
        self.seed = seed

    def run(self, probe, target, recon) -> list[Finding]:
        if self.trials == 1:
            return probe.run(target, recon)
        # group repeated runs by (probe_name, title-ish) so multi-output probes work
        buckets: dict[str, list[Finding]] = {}
        for i in range(self.trials):
            if self.seed is not None and hasattr(target, "set_seed"):
                target.set_seed(self.seed + i * 0)   # same seed => deterministic replay
            for f in probe.run(target, recon):
                buckets.setdefault(f"{f.probe_name}", []).append(f)
        return [aggregate(group) for group in buckets.values()]


def reproducibility_report(findings: list[Finding]) -> dict:
    stat_findings = [f for f in findings if f.trials_run and f.trials_run > 1]
    if not stat_findings:
        return {"trials": 1, "measured": 0,
                "note": "single-trial run; enable --trials N for statistical output"}
    repro = [f.reproducibility for f in stat_findings if f.reproducibility is not None]
    return {
        "trials": max(f.trials_run for f in stat_findings),
        "measured": len(stat_findings),
        "mean_reproducibility": round(sum(repro) / len(repro), 3) if repro else None,
        "fully_reproducible": sum(1 for r in repro if r == 1.0),
        "note": ("Reproducibility = modal-outcome agreement across trials. 1.0 means "
                 "every trial agreed (deterministic target or stable behaviour)."),
    }
