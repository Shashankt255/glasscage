# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Adapter validation framework (GLASSCAGE GA blocker P0-5).

Status: Implemented (framework) / Pending External Validation (genuine-tool results).

This validates that our parsers correctly normalize each framework's output. It is
honest about evidence level and NEVER fabricates a successful validation:

  * genuine   - a REAL output file from an installed tool was parsed  -> Measured
  * fixture   - only the shipped representative fixture was parsed     -> Experimental
                (proves format conformance, NOT validation vs a live tool)
  * pending   - no genuine output and tool not available              -> Pending External
                Validation (no result claimed)

To perform genuine validation, run the tool yourself and pass its real output:
  python -m glasscage ... (see docs) or call validate_adapters({"garak": "run.report.jsonl"})
"""

from __future__ import annotations

import os

from .adapters import REGISTRY
from .adapters import external as _ext
from .evidence_confidence import EvidenceClass as EC

_FIXTURES = {
    "garak": "garak.report.jsonl", "promptfoo": "promptfoo.json",
    "pyrit": "pyrit.json", "deepteam": "deepteam.json", "fuzzyai": "fuzzyai.json",
}
_FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "adapters", "fixtures")


def _parse(tool, path):
    parser = {"garak": _ext.parse_garak, "promptfoo": _ext.parse_promptfoo,
              "pyrit": _ext.parse_pyrit, "deepteam": _ext.parse_deepteam,
              "fuzzyai": _ext.parse_fuzzyai}[tool]
    return parser(path)


def validate_adapters(genuine_outputs: dict | None = None) -> dict:
    """genuine_outputs: {framework: path_to_REAL_tool_output}. Absent -> fixture/pending."""
    genuine_outputs = genuine_outputs or {}
    results = []
    for tool in _FIXTURES:
        installed = REGISTRY[tool]().available()
        genuine = genuine_outputs.get(tool)
        if genuine and os.path.exists(genuine):
            try:
                findings = _parse(tool, genuine)
                results.append({
                    "framework": tool, "level": "genuine", "installed": installed,
                    "evidence_class": EC.MEASURED.value,
                    "source": genuine, "parsed_findings": len(findings),
                    "status": "validated against genuine tool output",
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "framework": tool, "level": "genuine", "installed": installed,
                    "evidence_class": EC.OBSERVED.value, "source": genuine,
                    "parsed_findings": 0, "status": f"PARSE FAILURE on genuine output: {e}",
                })
            continue
        # only the representative fixture is available
        fx = os.path.join(_FIXTURE_DIR, _FIXTURES[tool])
        try:
            n = len(_parse(tool, fx))
            results.append({
                "framework": tool, "level": "fixture", "installed": installed,
                "evidence_class": EC.EXPERIMENTAL.value, "source": fx,
                "parsed_findings": n,
                "status": ("parser conforms to REPRESENTATIVE fixture (format check only); "
                           "genuine validation Pending External Validation"),
            })
        except Exception as e:  # noqa: BLE001
            results.append({
                "framework": tool, "level": "pending", "installed": installed,
                "evidence_class": EC.PENDING_EXTERNAL_VALIDATION.value, "source": fx,
                "parsed_findings": 0, "status": f"fixture parse error: {e}",
            })
    return {
        "summary": {
            "genuine": sum(1 for r in results if r["level"] == "genuine"
                           and "FAILURE" not in r["status"]),
            "fixture_only": sum(1 for r in results if r["level"] == "fixture"),
            "pending_external_validation": sum(
                1 for r in results if r["evidence_class"] == EC.PENDING_EXTERNAL_VALIDATION.value
                or r["level"] == "fixture"),
        },
        "results": results,
        "note": ("Fixture conformance is NOT validation against a live tool. Frameworks "
                 "without genuine output are 'Pending External Validation'; no efficacy "
                 "is claimed for them."),
    }


def to_markdown(rep: dict) -> str:
    L = ["# GLASSCAGE Adapter Validation", "",
         "| Framework | Level | Evidence | Installed | Parsed | Status |",
         "|---|---|---|---|---|---|"]
    for r in rep["results"]:
        L.append(f"| {r['framework']} | {r['level']} | {r['evidence_class']} | "
                 f"{r['installed']} | {r['parsed_findings']} | {r['status'][:70]} |")
    s = rep["summary"]
    L += ["", f"Genuine-validated: {s['genuine']} · fixture-only: {s['fixture_only']} · "
          f"Pending External Validation: {s['pending_external_validation']}",
          "", f"_{rep['note']}_"]
    return "\n".join(L)
