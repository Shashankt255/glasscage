# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Regression diff: compare two GLASSCAGE JSON reports.

Answers "did this deploy make the bot safer or riskier?" by diffing findings
keyed on (probe_name, owasp_id, title-ish). Surfaces newly introduced, fixed, and
severity-changed issues so risk can be tracked across prompt/model/tool changes.
"""

from __future__ import annotations

import json


def _key(f: dict) -> str:
    return f"{f.get('probe_name')}::{f.get('owasp_id')}"


def _vuln(f: dict) -> bool:
    return f.get("status") == "vulnerable"


def diff_reports(old_path: str, new_path: str) -> dict:
    with open(old_path, encoding="utf-8") as fh:
        old = json.load(fh)
    with open(new_path, encoding="utf-8") as fh:
        new = json.load(fh)

    old_v = {_key(f): f for f in old.get("findings", []) if _vuln(f)}
    new_v = {_key(f): f for f in new.get("findings", []) if _vuln(f)}

    introduced = [new_v[k] for k in new_v.keys() - old_v.keys()]
    fixed = [old_v[k] for k in old_v.keys() - new_v.keys()]
    changed = []
    for k in old_v.keys() & new_v.keys():
        if old_v[k].get("severity") != new_v[k].get("severity"):
            changed.append({"key": k, "from": old_v[k]["severity"],
                            "to": new_v[k]["severity"]})

    verdict = ("REGRESSED" if introduced else "IMPROVED" if fixed
               else "NO CHANGE")
    return {
        "verdict": verdict,
        "old_grade": old.get("summary", {}).get("grade"),
        "new_grade": new.get("summary", {}).get("grade"),
        "introduced": introduced, "fixed": fixed, "severity_changed": changed,
    }


def render(d: dict) -> str:
    out = [f"# Regression diff: {d['verdict']}",
           f"Grade {d['old_grade']} -> {d['new_grade']}", ""]
    out.append(f"## Newly introduced ({len(d['introduced'])})")
    out += [f"- [{f['owasp_id']}] {f['title']} ({f['severity']})" for f in d["introduced"]] or ["- none"]
    out.append(f"\n## Fixed ({len(d['fixed'])})")
    out += [f"- [{f['owasp_id']}] {f['title']}" for f in d["fixed"]] or ["- none"]
    out.append(f"\n## Severity changed ({len(d['severity_changed'])})")
    out += [f"- {c['key']}: {c['from']} -> {c['to']}" for c in d["severity_changed"]] or ["- none"]
    return "\n".join(out)
