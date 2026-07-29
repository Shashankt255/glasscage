# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Plugin SDK (GLASSCAGE RC hardening).

Status: Implemented. A small, stable, versioned interface for shipping custom
probes without modifying the core. Contract (semver'd via PLUGIN_API_VERSION):

  * A plugin is a .py module in a plugins directory.
  * It registers probes by subclassing `glasscage.probes.Probe` and decorating with
    `@glasscage.probes.register`, OR by exposing a module-level `register(registry)`
    hook that receives the probe registry.
  * It MAY declare `GLASSCAGE_PLUGIN_API = "1.x"`; if the major differs from
    PLUGIN_API_VERSION the loader refuses it (raises PluginError) to avoid silently
    running incompatible plugins.
  * Every probe must declare `name`, `owasp_id`, and `min_tier` (enforced on load).

This module only loads probe plugins; it does not grant network or filesystem
capability beyond what the probe code itself does. Load only trusted plugins.
"""

from __future__ import annotations

import importlib.util
import pathlib

from .errors import PluginError
from .logging_setup import get_logger

PLUGIN_API_VERSION = "1.0"
_log = get_logger(__name__)


def _major(v: str) -> str:
    return str(v).split(".", 1)[0]


def _validate_probe(cls) -> None:
    for attr in ("name", "owasp_id", "min_tier"):
        if getattr(cls, attr, None) is None:
            raise PluginError(f"probe {cls!r} missing required attribute '{attr}'")


def load_plugins(directory: str, strict: bool = False) -> int:
    """Import every non-underscore .py in `directory`. Returns modules loaded.

    strict=True re-raises plugin errors; otherwise a bad plugin is logged and skipped.
    """
    d = pathlib.Path(directory)
    if not d.is_dir():
        _log.warning("plugin directory not found: %s", directory)
        return 0
    from .probes import REGISTRY
    before = len(REGISTRY)
    loaded = 0
    for path in sorted(d.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"glasscage_plugin_{path.stem}", path)
            if not spec or not spec.loader:
                raise PluginError(f"cannot load spec for {path}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            declared = getattr(module, "GLASSCAGE_PLUGIN_API", PLUGIN_API_VERSION)
            if _major(declared) != _major(PLUGIN_API_VERSION):
                raise PluginError(
                    f"{path.name} targets plugin API {declared}, core is "
                    f"{PLUGIN_API_VERSION}")
            hook = getattr(module, "register", None)
            if callable(hook) and getattr(hook, "__module__", "") == module.__name__:
                hook(REGISTRY)
            loaded += 1
            _log.info("loaded plugin %s", path.name)
        except Exception as e:  # noqa: BLE001
            if strict:
                raise PluginError(f"failed to load {path.name}: {e}") from e
            _log.error("skipping plugin %s: %s", path.name, e)
    # validate any newly registered probes
    for cls in REGISTRY[before:]:
        _validate_probe(cls)
    return loaded
