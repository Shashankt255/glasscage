"""Loader for CBH hunt strategy data."""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "cbh_hunt_strategies.json"
_CACHE: list[dict] | None = None


def _load() -> list[dict]:
    global _CACHE
    if _CACHE is None:
        with open(_DATA, encoding="utf-8") as f:
            _CACHE = json.load(f)["skills"]
    return _CACHE


def strategies() -> list[dict]:
    return _load()


def strategy_for(name: str) -> dict | None:
    for s in _load():
        if s["name"] == name:
            return s
    return None


def strategies_for_class(vuln_class: str) -> list[dict]:
    vc = vuln_class.lower()
    return [s for s in _load() if vc in s["name"].lower()]
