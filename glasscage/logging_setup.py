# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Structured logging (GLASSCAGE RC hardening).

Status: Implemented. Standard-library logging with an optional JSON formatter so
GLASSCAGE emits machine-parseable logs for SIEM/OTel pipelines without adding a
dependency. Library modules log via get_logger(__name__); they never configure
handlers themselves (only the application/CLI calls configure()).
"""

from __future__ import annotations

import json
import logging
import sys

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record (stdlib only)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for k, v in getattr(record, "extra_fields", {}).items():
            payload[k] = v
        return json.dumps(payload, default=str)


def configure(level: str = "WARNING", json_output: bool = False,
              stream=None) -> None:
    """Configure the root 'glasscage' logger once. Idempotent."""
    global _CONFIGURED
    logger = logging.getLogger("glasscage")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if json_output
                         else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, str(level).upper(), logging.WARNING))
    logger.propagate = False
    _CONFIGURED = True


def get_logger(name: str = "glasscage") -> logging.Logger:
    """Return a namespaced logger under 'glasscage'."""
    if not name.startswith("glasscage"):
        name = f"glasscage.{name.rsplit('.', 1)[-1]}"
    return logging.getLogger(name)
