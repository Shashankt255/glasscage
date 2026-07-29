# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Evidence Confidence Classification (GLASSCAGE GA blocker; honesty control).

Status: Implemented.

Every report section and claim must be tagged with exactly one evidence class so no
output implies stronger evidence than exists. This module is the single authority for
the vocabulary and for mapping graph/measurement state onto it. It is intentionally
small and dependency-free; reporting/validation import from here rather than inventing
their own labels.

Ordering (weakest -> strongest) lets callers assert "a section may not claim a class
stronger than its evidence supports".
"""

from __future__ import annotations

from enum import Enum


class EvidenceClass(str, Enum):
    PENDING_EXTERNAL_VALIDATION = "Pending External Validation"
    HYPOTHESIZED = "Hypothesized"
    ESTIMATED = "Estimated"
    EXPERIMENTAL = "Experimental"
    OBSERVED = "Observed"
    DEMONSTRATED = "Demonstrated"
    MEASURED = "Measured"
    VERIFIED = "Verified"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    def at_most(self, ceiling: "EvidenceClass") -> "EvidenceClass":
        """Clamp this class so it never exceeds the evidence ceiling."""
        return self if self.rank <= ceiling.rank else ceiling


_ORDER = [
    EvidenceClass.PENDING_EXTERNAL_VALIDATION,
    EvidenceClass.HYPOTHESIZED,
    EvidenceClass.ESTIMATED,
    EvidenceClass.EXPERIMENTAL,
    EvidenceClass.OBSERVED,
    EvidenceClass.DEMONSTRATED,
    EvidenceClass.MEASURED,
    EvidenceClass.VERIFIED,
]

# Definitions shown in report legends so readers know exactly what each tag means.
DEFINITIONS = {
    EvidenceClass.VERIFIED: "Confirmed against ground truth or a cryptographic check "
                            "(e.g. chain-of-custody hash).",
    EvidenceClass.MEASURED: "Quantified from data with a stated method (e.g. detector "
                            "precision/recall on the labeled corpus).",
    EvidenceClass.DEMONSTRATED: "Observed on-target: an impact-confirmed finding or a "
                                "fully-demonstrated attack path.",
    EvidenceClass.OBSERVED: "Seen in a response but not impact-confirmed (e.g. a "
                            "steerability signal).",
    EvidenceClass.EXPERIMENTAL: "Produced by an Experimental component or small dataset; "
                                "indicative only.",
    EvidenceClass.ESTIMATED: "Heuristic estimate from an uncalibrated model (e.g. the "
                             "Indicative Risk Index).",
    EvidenceClass.HYPOTHESIZED: "Architecturally reachable but not shown on-target; must "
                                "be confirmed manually.",
    EvidenceClass.PENDING_EXTERNAL_VALIDATION: "Framework implemented but not yet run "
                                               "against real external output/tools; no "
                                               "result is claimed.",
}

# Map graph edge/path/finding state -> evidence class (single source of mapping).
_STATE_MAP = {
    "demonstrated": EvidenceClass.DEMONSTRATED,
    "hypothesized": EvidenceClass.HYPOTHESIZED,
    "not_assessable": EvidenceClass.PENDING_EXTERNAL_VALIDATION,
}


def from_state(state: str) -> EvidenceClass:
    """Map a graph/path state string onto an evidence class."""
    return _STATE_MAP.get(str(state), EvidenceClass.HYPOTHESIZED)


def tag(text: str, cls: EvidenceClass) -> str:
    """Render an inline evidence tag for a claim or section heading."""
    return f"{text}  [{cls.value}]"


def legend(classes=None) -> str:
    """Markdown legend of the evidence classes actually used in a report."""
    classes = classes or list(EvidenceClass)
    lines = ["**Evidence classification** (no claim exceeds its evidence):"]
    for c in sorted(set(classes), key=lambda x: -x.rank):
        lines.append(f"- **{c.value}** — {DEFINITIONS[c]}")
    return "\n".join(lines)
