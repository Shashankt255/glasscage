"""Loader for the CBH eval corpus and CVE index data."""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data"
_EVAL: dict | None = None
_CVE: dict | None = None


def _load_eval() -> dict:
    global _EVAL
    if _EVAL is None:
        _EVAL = json.loads((_DATA / "cbh_eval_corpus.json").read_text())
    return _EVAL


def _load_cve() -> dict:
    global _CVE
    if _CVE is None:
        _CVE = json.loads((_DATA / "cbh_cve_index.json").read_text())
    return _CVE


def portswigger_labs() -> list[dict]:
    d = _load_eval()
    return d["portswigger_labs"] + d["portswigger_labs_hard"]


def juice_shop_challenges() -> list[dict]:
    return _load_eval()["juice_shop_challenges"]


def fp_cases() -> list[dict]:
    return _load_eval()["fp_cases"]


def cve_gaps() -> list[dict]:
    return _load_cve()["gaps"]


def cve_gap_for(cve_id: str) -> dict | None:
    for gap in cve_gaps():
        if gap["cve"] == cve_id:
            return gap
    return None
