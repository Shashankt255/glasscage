# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Web-attack chain references for AI security findings.

Loads curated attack chain data extracted from Claude-BugHunter (CC BY 4.0 + MIT)
and provides chain context for kb.py enrichment and posture.py calibration.

When an AI-layer finding (e.g. LLM01 Prompt Injection) can chain to a web-layer
impact (e.g. SSRF via tool-use), the chain data helps operators understand the
blast radius and severity implications.

Data provenance: Claude-BugHunter (github.com/elementalsouls/Claude-BugHunter),
licensed CC BY 4.0 (docs) + MIT (code).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def _load_chains() -> dict[str, list[dict]]:
    """Load attack chains keyed by OWASP LLM ID → list of chain descriptors."""
    path = _DATA / "cbh_attack_chains.json"
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_llm: dict[str, list[dict]] = {}
    for chain in raw.get("chains", []):
        summary = {
            "vuln_class": chain["vuln_class"],
            "ai_chain": chain["ai_chain_description"],
            "pattern_count": chain["pattern_count"],
            "report_count": chain["disclosed_report_count"],
            "atlas_id": chain.get("atlas_id", ""),
        }
        for llm_id in chain.get("owasp_llm_mappings", []):
            by_llm.setdefault(llm_id, []).append(summary)
    return by_llm


@lru_cache(maxsize=1)
def _load_severity_ref() -> list[dict]:
    path = _DATA / "cbh_severity_reference.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("entries", [])


def chains_for(owasp_id: str) -> list[dict]:
    """Return web-attack chain references relevant to an OWASP LLM category."""
    return _load_chains().get(owasp_id, [])


def severity_reference() -> list[dict]:
    """Return the full CBH severity calibration reference (94 entries)."""
    return list(_load_severity_ref())


def severity_for_finding(finding_text: str) -> str | None:
    """Look up a CBH severity calibration for a finding description (exact substring match)."""
    lower = finding_text.lower()
    for entry in _load_severity_ref():
        if entry["finding"].lower() in lower:
            return entry["severity"]
    return None
