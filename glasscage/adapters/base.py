# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Stable adapter interface (versioned)."""

from __future__ import annotations

from dataclasses import dataclass, field

ADAPTER_API_VERSION = "1.0"


@dataclass
class AdapterResult:
    tool: str
    available: bool
    version: str | None = None
    findings: list = field(default_factory=list)   # normalized glasscage Finding list
    raw_summary: dict = field(default_factory=dict)
    error: str | None = None
    elapsed_ms: float = 0.0


class ExternalToolAdapter:
    """Contract every adapter implements. Backward-compatible via API version."""
    name = "abstract"
    api_version = ADAPTER_API_VERSION
    status = "Roadmap"

    def available(self) -> bool:
        """True only if the underlying tool is importable/executable here."""
        return False

    def version(self) -> str | None:
        return None

    def run(self, target, options: dict | None = None) -> AdapterResult:
        raise NotImplementedError
