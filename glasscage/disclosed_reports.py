"""Loader for CBH disclosed report pattern libraries."""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "cbh_disclosed_reports.json"
_CACHE: list[dict] | None = None


def _load() -> list[dict]:
    global _CACHE
    if _CACHE is None:
        _CACHE = json.loads(_DATA.read_text())["reports"]
    return _CACHE


def reports() -> list[dict]:
    return _load()


def report_for(vuln_class: str) -> dict | None:
    for r in _load():
        if r["vuln_class"] == vuln_class:
            return r
    return None


def cited_examples_for(vuln_class: str) -> list[dict]:
    r = report_for(vuln_class)
    return r["cited_examples"] if r else []


def patterns_for(vuln_class: str) -> list[dict]:
    r = report_for(vuln_class)
    return r["patterns"] if r else []
