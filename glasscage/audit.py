# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Operational safety + chain of custody.

The review flagged --authorized as an honor-system checkbox and the SVG as a
self-drawn reconstruction rather than a tamper-evident capture. This module adds:

  * Scope    - an explicit host allowlist; requests outside it are refused.
  * RateLimiter - minimum inter-request interval (be a polite tester).
  * AuditLog - append-only JSONL of every payload sent, with sha256 + timestamp,
               chained: each entry hashes its own fields and the previous entry's
               digest, so altering a recorded field is detectable (ADR 0019).
  * capture  - hash + timestamp raw request/response for evidentiary integrity.
  * har_export - standard HAR so raw exchanges load in any HTTP tooling.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from urllib.parse import urlparse

from .errors import ConfigError


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
    return h.hexdigest()


ENTRY_VERSION = 2

# ADR 0019: the canonical serialization of an audit entry. Frozen - specified once here
# and used by both the writer and every verifier, so all implementations agree.
#
#   for each field, in exactly this order:  <utf8-byte-length> ":" <value>
#   concatenated, with no separator between fields
#
# Length-prefixing makes the form self-delimiting: `audit.sha256` concatenates its parts
# without a separator, so sha256("ab", "c") == sha256("a", "bc"). Feeding it one
# pre-delimited string instead of several parts removes that ambiguity without altering
# `sha256` itself, whose output is frozen by `evidence_hash` and `custody_hash`.
_CANONICAL_FIELDS = ("v", "prev", "ts", "url", "prompt_sha256", "response_sha256", "ok")


def _canonical_scalar(value) -> str:
    """One field's canonical text. Booleans are lower-cased so the encoding does not
    depend on Python's `str(True)`, which no other language reproduces."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def canonical_entry(entry: dict) -> str:
    """The canonical serialization of one entry (ADR 0019). Deterministic and
    self-delimiting; raises KeyError if a required field is absent."""
    return "".join(
        f"{len(s.encode('utf-8'))}:{s}"
        for s in (_canonical_scalar(entry[name]) for name in _CANONICAL_FIELDS))


class ChainStatus(str, Enum):
    """Outcome of verifying a chain (ADR 0019).

    Three states, because `bool` cannot distinguish "this chain was altered" from "this
    chain predates the integrity format and cannot be checked either way".
    """

    VERIFIED = "verified"
    TAMPERED = "tampered"
    LEGACY_UNVERIFIABLE = "legacy_unverifiable"


@dataclass
class ChainResult:
    """A chain verification result. `head` is the final entry hash, which an operator can
    record elsewhere: a forward chain can always be recomputed end to end by whoever can
    write the file, so truncation is only detectable against an external anchor."""

    status: ChainStatus
    entries: int
    head: str | None = None
    detail: str = ""

    @property
    def verified(self) -> bool:
        return self.status is ChainStatus.VERIFIED


def check_entries(entries) -> ChainResult:
    """Verify a sequence of audit entries (ADR 0019).

    Each entry is recomputed from its own canonical form, so altering any recorded field -
    url, timestamp, either payload digest, or the ok flag - is detected. The previous
    formula hashed the raw payloads, which the entry never stores, so nothing could be
    recomputed and only a broken `prev` link was ever caught.
    """
    prev = "0" * 64
    for i, e in enumerate(entries or []):
        # A line that parses as JSON but is not an object is malformed, not legacy: it
        # carries no fields to version-check, so it is reported as tampering rather than
        # reaching the field access below.
        if not isinstance(e, dict):
            return ChainResult(ChainStatus.TAMPERED, len(entries or []), None,
                               f"entry {i} is not a JSON object")
        if e.get("v") != ENTRY_VERSION:
            return ChainResult(
                ChainStatus.LEGACY_UNVERIFIABLE, len(entries or []), None,
                f"entry {i} predates the integrity format (ADR 0019); its contents "
                "cannot be verified either way")
        try:
            expected = sha256(canonical_entry(e))
        except KeyError as missing:
            return ChainResult(ChainStatus.TAMPERED, len(entries or []), None,
                               f"entry {i} is missing the required field {missing}")
        if e["prev"] != prev:
            return ChainResult(ChainStatus.TAMPERED, len(entries or []), None,
                               f"entry {i} does not link to its predecessor")
        if e["entry_hash"] != expected:
            return ChainResult(ChainStatus.TAMPERED, len(entries or []), None,
                               f"entry {i} does not match its recorded digest")
        prev = e["entry_hash"]
    return ChainResult(ChainStatus.VERIFIED, len(entries or []), prev if entries else None)


class _BadLine(Exception):
    """A JSONL line that does not parse. Internal to this module: `verify_file` turns it
    into a `ChainResult` so the public contract stays 'returns a result'."""

    def __init__(self, lineno: int, parsed: int):
        super().__init__(f"line {lineno} is not valid JSON")
        self.lineno, self.parsed = lineno, parsed


def _read_entries(path: str) -> list:
    """Parse a JSONL audit log into a list, skipping blank lines (ADR 0019/0020).

    Shared by `verify_file` and by `AuditLog.__init__`'s resume, so a file is read the
    same way whether it is being checked or continued.
    """
    entries: list = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                raise _BadLine(i + 1, len(entries)) from None
    return entries


def verify_file(path: str) -> ChainResult:
    """Verify a JSONL audit log written by `--audit-log` (ADR 0019).

    The on-disk log previously had no reader at all; `AuditLog.verify()` only ever checked
    the in-memory list. A malformed line is reported as tampering rather than skipped.
    """
    try:
        entries = _read_entries(path)
    except _BadLine as bad:
        return ChainResult(ChainStatus.TAMPERED, bad.parsed, None,
                           f"line {bad.lineno} is not valid JSON")
    return check_entries(entries)


class Scope:
    """Explicit allowlist of hosts that may be tested."""

    def __init__(self, allowed_hosts: list[str] | None = None):
        self.allowed = {h.lower() for h in (allowed_hosts or [])}

    def check(self, url: str) -> None:
        if not self.allowed:
            return  # no scope configured -> caller relies on --authorized
        host = (urlparse(url).hostname or "").lower()
        if host not in self.allowed:
            raise PermissionError(
                f"Refusing to test out-of-scope host '{host}'. "
                f"Allowed: {sorted(self.allowed)}")


class RateLimiter:
    def __init__(self, rps: float | None = None):
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        delta = time.perf_counter() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.perf_counter()


class AuditLog:
    """Append-only, hash-chained JSONL audit trail of everything sent."""

    def __init__(self, path: str | None = None):
        # ADR 0020: a log file is ONE append-only chain. Opening an existing one resumes it
        # rather than starting a second chain from genesis, which is what previously left a
        # twice-used `--audit-log` reporting as tampered at the first entry of run two.
        #
        # The existing chain is verified before it is trusted: the head is only adopted
        # once every prior entry has been recomputed under the ADR 0019 v2 rules. A file
        # that is tampered, or that predates the integrity format, is refused rather than
        # continued - appending to it would extend a chain that cannot be vouched for.
        # This inherits ADR 0019's accepted limitation unchanged: verification proves the
        # entries present are internally consistent, not that none were removed.
        self.path = path
        self.prev = "0" * 64
        self.entries: list[dict] = []
        if path and os.path.exists(path):
            existing = verify_file(path)
            if existing.status is ChainStatus.TAMPERED:
                raise ConfigError(
                    f"refusing to append to {path!r}: its audit chain does not verify "
                    f"({existing.detail}). Appending would extend a chain that cannot be "
                    "vouched for; write this run to a different --audit-log path and keep "
                    "the existing file for investigation")
            if existing.status is ChainStatus.LEGACY_UNVERIFIABLE:
                raise ConfigError(
                    f"refusing to append to {path!r}: it predates the integrity format "
                    f"({existing.detail}), so its contents cannot be verified either way "
                    "and it cannot be upgraded. Write this run to a different "
                    "--audit-log path")
            if existing.head:
                self.entries = _read_entries(path)
                self.prev = existing.head

    def record(self, url: str, prompt: str, response: str, ok: bool) -> dict:
        # ADR 0019: the digest covers the fields the entry retains, so any of them can be
        # recomputed later. The raw prompt and response are deliberately still not stored -
        # this is the one artifact that has never held a payload, which is why `redaction`
        # has nothing to do here.
        entry = {"v": ENTRY_VERSION, "ts": now_iso(), "url": url,
                 "prompt_sha256": sha256(prompt),
                 "response_sha256": sha256(response), "ok": ok,
                 "prev": self.prev}
        entry["entry_hash"] = sha256(canonical_entry(entry))
        # ADR 0024: durable before visible. The append happens BEFORE `prev` and `entries`
        # advance, so the in-memory chain can never claim more than the file holds. The
        # previous order committed in memory first, so a failed write left `prev` pointing
        # at an entry that was never persisted; the next successful record then chained
        # from that unpersisted hash and wrote a gap. Measured on
        # `v0.4.8-transport-custody-exception`, an intermittent write fault produced 19
        # entries for 21 exchanges whose on-disk chain read `tampered` - "entry 4 does not
        # link to its predecessor" - while the CLI reported `verified (21 entries)`. The
        # integrity control was accusing a file the tool itself had gapped.
        # A failed write now commits nothing: the `OSError` propagates, the file stays a
        # verifiable prefix, and the next successful record chains from the last persisted
        # entry. Ordering only - the entry, its linkage, the canonical form, the hashes and
        # the return value are unchanged, and a `path=None` log is bit-identical.
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        self.prev = entry["entry_hash"]
        self.entries.append(entry)
        return entry

    def check(self) -> ChainResult:
        """Verify this chain, distinguishing verified / tampered / legacy (ADR 0019).

        The API new code should use. `verify()` below is retained only for callers written
        against the previous contract.
        """
        return check_entries(self.entries)

    def verify(self) -> bool:
        """Compatibility API (ADR 0019). True only for a fully verified chain.

        A legacy chain returns False: `bool` cannot separate "altered" from "predates the
        format", and reporting an unverifiable chain as verified is the defect this ADR
        corrects. Use `check()` to tell the two apart.
        """
        return self.check().status is ChainStatus.VERIFIED


def har_export(exchanges: list[dict], path: str) -> None:
    """exchanges: [{url, method, request_body, status, response_body, ts, ms}]."""
    entries = []
    for x in exchanges:
        entries.append({
            "startedDateTime": x.get("ts", now_iso()),
            "time": x.get("ms", 0),
            "request": {"method": x.get("method", "POST"), "url": x.get("url", ""),
                        "httpVersion": "HTTP/1.1", "headers": [], "queryString": [],
                        "postData": {"mimeType": "application/json",
                                     "text": x.get("request_body", "")},
                        "headersSize": -1, "bodySize": -1},
            "response": {"status": x.get("status", 0), "statusText": "",
                         "httpVersion": "HTTP/1.1", "headers": [],
                         "content": {"size": len(x.get("response_body", "")),
                                     "mimeType": "application/json",
                                     "text": x.get("response_body", "")},
                         "redirectURL": "", "headersSize": -1, "bodySize": -1},
            "cache": {}, "timings": {"send": 0, "wait": x.get("ms", 0), "receive": 0},
        })
    har = {"log": {"version": "1.2",
                   "creator": {"name": "GLASSCAGE", "version": "0.5.0"},
                   "entries": entries}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(har, fh, indent=2)
