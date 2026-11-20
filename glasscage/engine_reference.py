"""Loader for CBH engine reference data and command workflows."""

from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data"
_REF: dict | None = None
_WF: dict | None = None


def _load_ref() -> dict:
    global _REF
    if _REF is None:
        _REF = json.loads((_DATA / "cbh_engine_reference.json").read_text())
    return _REF


def _load_wf() -> dict:
    global _WF
    if _WF is None:
        _WF = json.loads((_DATA / "cbh_workflows.json").read_text())
    return _WF


def class_weights() -> dict[str, int]:
    return _load_ref()["class_weight"]


def class_skill_map() -> dict[str, list[str]]:
    return _load_ref()["class_skill"]


def tech_skill_map() -> dict[str, list[str]]:
    return _load_ref()["tech_skill"]


def class_probes() -> dict[str, str]:
    return _load_ref()["class_probe"]


def weight_for(vuln_class: str) -> int:
    return _load_ref()["class_weight"].get(vuln_class, 0)


def skills_for(vuln_class: str) -> list[str]:
    return _load_ref()["class_skill"].get(vuln_class, [])


def probe_for(vuln_class: str) -> str | None:
    return _load_ref()["class_probe"].get(vuln_class)


def phases() -> dict[str, list[str]]:
    return _load_ref()["phases"]


def scope_rules() -> dict:
    return _load_ref()["scope"]


def coverage_verdicts() -> dict:
    return _load_ref()["coverage"]


def recon_patterns() -> dict:
    return _load_ref()["recon"]


def secret_patterns() -> list[dict]:
    return _load_ref()["recon"]["secret_patterns"]


def osint_config() -> dict:
    return _load_ref()["osint"]


def roe_template() -> str:
    return _load_ref()["roe_template"]


def workflows() -> list[dict]:
    return _load_wf()["workflows"]


def workflow_for(name: str) -> dict | None:
    for w in workflows():
        if w["name"] == name:
            return w
    return None


def workflow_names() -> list[str]:
    return [w["name"] for w in workflows()]
