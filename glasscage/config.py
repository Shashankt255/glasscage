# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Configuration validation (GLASSCAGE RC hardening).

Status: Implemented. Validates target/run configuration up front with clear,
actionable errors instead of failing deep in a request. Pure stdlib.
"""

from __future__ import annotations

import ipaddress
import urllib.parse

from .errors import ConfigError

_REQUIRED_TARGET = ("url",)
_OPTIONAL_TARGET = {
    "name": str, "method": str, "headers": dict, "body_template": (dict, str),
    "response_path": str, "timeout": (int, float), "stateful": bool,
    "proxy": str, "proxy_no_verify": bool,
    "max_retries": int, "backoff_base": (int, float),
}

_MAX_URL_LEN = 8192
_MAX_HEADER_NAME_LEN = 256
_MAX_HEADER_VALUE_LEN = 8192
_MAX_TIMEOUT = 300

_METADATA_ADDRS = [
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
]


def _has_null(s: str) -> bool:
    return "\x00" in s


def _is_cloud_metadata(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr == m for m in _METADATA_ADDRS)


def _check_ssrf(url: str) -> None:
    """Block requests to cloud metadata endpoints (169.254.169.254)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        raise ConfigError(f"target URL has no hostname: {url!r}")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        import socket
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return
        for info in infos:
            try:
                addr = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if _is_cloud_metadata(addr):
                raise ConfigError(
                    f"target URL resolves to cloud metadata address {addr} "
                    f"(blocked for SSRF safety)")
        return
    if _is_cloud_metadata(addr):
        raise ConfigError(
            f"target URL points to cloud metadata address {addr} "
            f"(blocked for SSRF safety)")


def _check_headers(headers: dict) -> None:
    """Reject CRLF injection, null bytes, and oversized header values."""
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if len(name) > _MAX_HEADER_NAME_LEN:
            raise ConfigError(f"header name exceeds {_MAX_HEADER_NAME_LEN} chars: {name[:40]!r}...")
        if len(value) > _MAX_HEADER_VALUE_LEN:
            raise ConfigError(f"header '{name}' value exceeds {_MAX_HEADER_VALUE_LEN} chars")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise ConfigError(f"header '{name[:40]}' contains CR/LF characters (possible injection)")
        if _has_null(name) or _has_null(value):
            raise ConfigError(f"header '{name[:40]}' contains null bytes")


def validate_target_config(cfg: dict) -> dict:
    """Validate a target config dict. Returns it unchanged or raises ConfigError."""
    if not isinstance(cfg, dict):
        raise ConfigError(f"target config must be an object, got {type(cfg).__name__}")
    for key in _REQUIRED_TARGET:
        if key not in cfg or not cfg[key]:
            raise ConfigError(f"target config missing required key: '{key}'")
    url = cfg["url"]
    if not isinstance(url, str) or not url.startswith(
            ("http://", "https://", "harness://", "mock://")):
        raise ConfigError(f"target 'url' must be an http(s) URL, got: {url!r}")
    if len(url) > _MAX_URL_LEN:
        raise ConfigError(f"target URL exceeds {_MAX_URL_LEN} chars")
    if _has_null(url):
        raise ConfigError("target URL contains null bytes")
    if url.startswith(("http://", "https://")):
        _check_ssrf(url)
    for key, types in _OPTIONAL_TARGET.items():
        if key in cfg and not isinstance(cfg[key], types):
            names = (types.__name__ if isinstance(types, type)
                     else "/".join(t.__name__ for t in types))
            raise ConfigError(f"target '{key}' must be {names}, got "
                              f"{type(cfg[key]).__name__}")
    if "headers" in cfg and isinstance(cfg["headers"], dict):
        _check_headers(cfg["headers"])
    to = cfg.get("timeout", 30)
    if isinstance(to, (int, float)) and to <= 0:
        raise ConfigError(f"target 'timeout' must be positive, got {to}")
    if isinstance(to, (int, float)) and to > _MAX_TIMEOUT:
        raise ConfigError(f"target 'timeout' exceeds maximum of {_MAX_TIMEOUT}s, got {to}")
    if isinstance(cfg.get("name"), str) and _has_null(cfg["name"]):
        raise ConfigError("target 'name' contains null bytes")
    return cfg


def validate_trials(trials: int) -> int:
    if not isinstance(trials, int) or trials < 1:
        raise ConfigError(f"--trials must be a positive integer, got {trials!r}")
    return trials
