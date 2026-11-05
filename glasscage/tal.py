# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Target Abstraction Layer (GLASSCAGE Stage A) — capability tiers L0-L3.

Status: Implemented.

Rationale
---------
The validity crisis in prior versions was that stateless single-turn probes
claimed stateful/agentic results. The fix is to make *what a target can expose*
an explicit, typed contract, and to gate every probe/detector/chain/score by a
declared minimum tier. If the target cannot satisfy the tier, the result is
NOT ASSESSABLE - never PASS or FAIL.

Tiers
-----
  L0  single-turn request/response only (a plain chat endpoint)
  L1  stateful session (turns share state; memory persistence is observable
      behaviourally across turns in the same session)
  L2  tool-call observable (planner/plan, tool invocations, memory state and
      retrieval are inspectable via a trace)
  L3  provider-native (token logprobs, multimodal input channels, tokenizer)

A Target advertises TargetCapabilities. A probe advertises min_tier. The engine
compares them. This module is dependency-free and imported by target.py, the
probes, the engine, and the reference harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Tier(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3

    @property
    def label(self) -> str:
        return {0: "L0 single-turn", 1: "L1 stateful", 2: "L2 tool-observable",
                3: "L3 provider-native"}[int(self)]


def parse_tier(value) -> Tier:
    if isinstance(value, Tier):
        return value
    if isinstance(value, int):
        return Tier(value)
    s = str(value).upper().strip()
    return {"L0": Tier.L0, "L1": Tier.L1, "L2": Tier.L2, "L3": Tier.L3}.get(s, Tier.L0)


@dataclass
class TargetCapabilities:
    """What a target can actually expose. Tier is derived from the flags."""
    stateful: bool = False          # turns share session state
    observes_tool_calls: bool = False
    observes_plan: bool = False
    observes_memory: bool = False
    observes_retrieval: bool = False
    multimodal: bool = False
    logprobs: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def tier(self) -> Tier:
        if self.multimodal or self.logprobs:
            return Tier.L3
        if self.observes_tool_calls or self.observes_plan or self.observes_memory \
                or self.observes_retrieval:
            return Tier.L2
        if self.stateful:
            return Tier.L1
        return Tier.L0

    def satisfies(self, required: Tier) -> bool:
        return self.tier >= required

    def to_dict(self) -> dict:
        return {"tier": self.tier.name, "stateful": self.stateful,
                "observes_tool_calls": self.observes_tool_calls,
                "observes_plan": self.observes_plan,
                "observes_memory": self.observes_memory,
                "observes_retrieval": self.observes_retrieval,
                "multimodal": self.multimodal, "logprobs": self.logprobs}


# Convenience presets
L0 = TargetCapabilities()
L1 = TargetCapabilities(stateful=True)
L2 = TargetCapabilities(stateful=True, observes_tool_calls=True, observes_plan=True,
                        observes_memory=True, observes_retrieval=True)
