# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Configuration validation (GLASSCAGE RC hardening).

Status: Implemented. Validates target/run configuration up front with clear,
actionable errors instead of failing deep in a request. Pure stdlib.
"""

from __future__ import annotations

from .errors import ConfigError

_REQUIRED_TARGET = ("url",)
_OPTIONAL_TARGET = {
    "name": str, "method": str, "headers": dict, "body_template": (dict, str),
    "response_path": str, "timeout": (int, float), "stateful": bool,
}


def validate_target_config(cfg: dict) -> dict:
    """Validate a target config dict. Returns it unchanged or raises ConfigError."""
    if not isinstance(cfg, dict):
        raise ConfigError(f"target config must be an object, got {type(cfg).__name__}")
    for key in _REQUIRED_TARGET:
        if key not in cfg or not cfg[key]:
            raise ConfigError(f"target config missing required key: '{key}'")
    url = cfg["url"]
    if not isinstance(url, str) or not url.startswith(
            ("http://", "https://", "harness://", "mock://")):
        raise ConfigError(f"target 'url' must be an http(s) URL, got: {url!r}")
    for key, types in _OPTIONAL_TARGET.items():
        if key in cfg and not isinstance(cfg[key], types):
            names = (types.__name__ if isinstance(types, type)
                     else "/".join(t.__name__ for t in types))
            raise ConfigError(f"target '{key}' must be {names}, got "
                              f"{type(cfg[key]).__name__}")
    to = cfg.get("timeout", 30)
    if isinstance(to, (int, float)) and to <= 0:
        raise ConfigError(f"target 'timeout' must be positive, got {to}")
    return cfg


def validate_trials(trials: int) -> int:
    if not isinstance(trials, int) or trials < 1:
        raise ConfigError(f"--trials must be a positive integer, got {trials!r}")
    return trials
