"""Loader for CBH OSINT reference data."""
from __future__ import annotations

import json
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "cbh_osint_references.json"
_CACHE: dict | None = None


def _load() -> dict:
    global _CACHE
    if _CACHE is None:
        with open(_DATA, encoding="utf-8") as f:
            _CACHE = json.load(f)
    return _CACHE


def categories() -> list[dict]:
    return _load()["categories"]


def category_by_id(cat_id: str) -> dict | None:
    return next((c for c in categories() if c["id"] == cat_id), None)


def dork_corpus() -> dict | None:
    return category_by_id("dork-corpus")


def secret_patterns() -> list[dict]:
    cat = category_by_id("secret-patterns")
    return cat["patterns"] if cat else []


def probe_wordlists() -> dict | None:
    return category_by_id("probe-wordlists")


def identity_providers() -> list[dict]:
    cat = category_by_id("identity-fabric")
    return cat["providers"] if cat else []


def sector_notes() -> list[dict]:
    cat = category_by_id("sector-notes")
    return cat["sectors"] if cat else []


def subdomain_takeover_fingerprints() -> list[dict]:
    cat = category_by_id("probe-wordlists")
    return cat.get("subdomain_takeover_fingerprints", []) if cat else []


def secret_validators() -> list[dict]:
    cat = category_by_id("secret-validators")
    return cat.get("validators", []) if cat else []


def recon_tools() -> list[dict]:
    cat = category_by_id("tooling-install")
    return cat.get("tool_categories", []) if cat else []
