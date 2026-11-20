"""CBH verification lab data loader."""
from __future__ import annotations

import json
from pathlib import Path

_DIR = Path(__file__).parent / "data"
_LABS = None
_APPS = None


def _load_labs():
    global _LABS
    if _LABS is None:
        with open(_DIR / "cbh_verification_labs.json") as f:
            _LABS = json.load(f)["labs"]
    return _LABS


def _load_apps():
    global _APPS
    if _APPS is None:
        with open(_DIR / "cbh_lab_apps.json") as f:
            _APPS = json.load(f)["labs"]
    return _APPS


def labs() -> list[dict]:
    return _load_labs()


def lab_for(name: str) -> dict | None:
    return next((l for l in _load_labs() if l["name"] == name), None)


def labs_for_class(vuln_class: str) -> list[dict]:
    vc = vuln_class.lower()
    return [l for l in _load_labs() if any(vc in c for c in l["vuln_classes"])]


def lab_apps() -> list[dict]:
    return _load_apps()
