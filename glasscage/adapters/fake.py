# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Fake adapter: deterministic canned findings to prove orchestration + tests."""

from __future__ import annotations

from ..models import Finding, Severity, Status
from .base import AdapterResult, ExternalToolAdapter


class FakeAdapter(ExternalToolAdapter):
    name = "fake-tool"
    status = "Implemented"

    def available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "0.0-fake"

    def run(self, target, options=None):
        f = Finding(probe_name="fake-probe", title="Fake external finding",
                    owasp_id="LLM01", category="Prompt Injection",
                    status=Status.VULNERABLE, severity=Severity.MEDIUM, confidence=0.7,
                    dimension="steerability")
        return AdapterResult(tool=self.name, available=True, version="0.0-fake",
                             findings=[f], raw_summary={"detections": 1}, elapsed_ms=1.0)
