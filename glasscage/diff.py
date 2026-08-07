# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Regression diff: compare two GLASSCAGE JSON reports.

Answers "did this deploy make the bot safer or riskier?" by diffing findings keyed on the
Finding identity of ADR 0010, as extended by ADR 0011. Surfaces newly introduced, fixed,
and severity-changed issues so risk can be tracked across prompt/model/tool changes.
"""

from __future__ import annotations

import hashlib
import json
import re

_WS = re.compile(r"\s+")


def _subject_digest(prompt: str) -> str:
    """First 12 hex chars of sha256 over the whitespace-normalised prompt (ADR 0010).

    Composed here rather than imported from `aakg.build`: ADR 0010 records the graph and
    the report diff as deliberately different layers, and a diff over serialized reports
    must not depend on the graph to read one. The two are kept in step by a test asserting
    both produce the same digest for the same prompt.
    """
    return hashlib.sha256(
        _WS.sub(" ", prompt or "").strip().encode("utf-8")).hexdigest()[:12]


def _key(f: dict) -> str:
    """Finding identity, read from a serialized report (ADR 0010 + ADR 0011).

    `probe_name::owasp_id` was not unique. `mcp.analyze_manifest` emits one finding per
    flagged tool and `architecture.assess` one per control, so several findings shared a
    key and all but the last were discarded by the dict comprehensions below - a
    regression on a discarded one was reported as NO CHANGE. ADR 0010 fixed the identical
    collapse in the graph and left this layer as follow-up; this is that follow-up.

    `source_rule_id` is deliberately not a component: identity here matches the graph's
    exactly, and the graph derives the subject from `prompt`.
    """
    return (f"{f.get('owasp_id')}:{f.get('probe_name')}:"
            f"{f.get('surface_id') or ''}:{_subject_digest(f.get('prompt'))}")


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
