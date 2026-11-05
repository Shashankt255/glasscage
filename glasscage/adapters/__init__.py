# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Pluggable framework-adapter architecture (GLASSCAGE Stage C).

GLASSCAGE orchestrates and benchmarks other tools rather than replacing them.
Each adapter conforms to ExternalToolAdapter. External tools are honestly gated by
availability: if the tool is not installed, available() is False and the
orchestrator records it as unavailable (never fabricates results).

Status:
  native   Implemented    (wraps GLASSCAGE's own engine)
  fake     Implemented    (deterministic, for tests/orchestration proof)
  garak    Roadmap        (interface defined; requires `garak` installed)
  pyrit    Roadmap        (interface defined; requires `pyrit` installed)
  promptfoo Roadmap       (interface defined; requires promptfoo CLI)
  deepteam Roadmap        (interface defined; requires `deepteam` installed)
  fuzzyai  Roadmap        (interface defined; requires FuzzyAI installed)
"""

from .base import AdapterResult, ExternalToolAdapter
from .external import DeepTeamAdapter, FuzzyAIAdapter, GarakAdapter, PromptfooAdapter, PyRITAdapter
from .fake import FakeAdapter
from .native import NativeAdapter

REGISTRY = {
    "native": NativeAdapter, "fake": FakeAdapter, "garak": GarakAdapter,
    "pyrit": PyRITAdapter, "promptfoo": PromptfooAdapter,
    "deepteam": DeepTeamAdapter, "fuzzyai": FuzzyAIAdapter,
}

__all__ = [
                       "REGISTRY",
                       "AdapterResult",
                       "DeepTeamAdapter",
                       "ExternalToolAdapter",
                       "FakeAdapter",
                       "FuzzyAIAdapter",
                       "GarakAdapter",
                       "NativeAdapter",
                       "PromptfooAdapter",
                       "PyRITAdapter",
]
