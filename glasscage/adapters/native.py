# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Native adapter: wraps GLASSCAGE's own engine so it orchestrates uniformly."""

from __future__ import annotations

import time

from .base import ExternalToolAdapter, AdapterResult


class NativeAdapter(ExternalToolAdapter):
    name = "glasscage-native"
    status = "Implemented"

    def __init__(self, **engine_kwargs):
        self.engine_kwargs = engine_kwargs

    def available(self) -> bool:
        return True

    def version(self) -> str | None:
        from .. import __version__
        return __version__

    def run(self, target, options=None):
        from ..engine import Engine
        start = time.perf_counter()
        eng = Engine(target, **(options or {}), **self.engine_kwargs)
        results = eng.run()
        ms = round((time.perf_counter() - start) * 1000, 1)
        return AdapterResult(tool=self.name, available=True, version=self.version(),
                             findings=results["findings"],
                             raw_summary=results["summary"], elapsed_ms=ms)
