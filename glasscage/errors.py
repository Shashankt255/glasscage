# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Typed exception hierarchy (GLASSCAGE RC hardening).

Status: Implemented. A single, documented error hierarchy so callers can catch
GlasscageError for anything this library raises, or a specific subclass. Replaces
scattered bare exceptions at public boundaries.
"""

from __future__ import annotations


class GlasscageError(Exception):
    """Base class for all GLASSCAGE errors."""


class ConfigError(GlasscageError):
    """Invalid or incomplete configuration."""


class TargetError(GlasscageError):
    """A target could not be reached or returned an unusable response."""


class AdapterError(GlasscageError):
    """An external-tool adapter failed to run or parse output."""


class GraphError(GlasscageError):
    """An invalid operation on the AI Attack Knowledge Graph."""


class PluginError(GlasscageError):
    """A plugin could not be loaded or violated the plugin contract."""
