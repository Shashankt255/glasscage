# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Secret redaction & optional encrypted evidence (GLASSCAGE GA blocker P0-1).

Status: Implemented (redaction) / Implemented-gated (encryption).

Rationale
---------
The disclosure probe deliberately elicits secrets; previously they were written to
evidence SVGs, HAR, and JSON in cleartext, turning the assessment artifact into a
secondary breach vector. This module redacts secret-shaped content from everything
persisted BY DEFAULT, preserving chain of custody: the original evidence hash is
computed before redaction, and each redacted secret is replaced by a stable
`[REDACTED:<8-hex>]` token (sha256-derived) so identical secrets remain correlatable
without exposing the value.

Raw (unredacted) evidence is only written with explicit user consent (`--store-raw`).

Encryption at rest is offered honestly: real AEAD encryption requires the optional
`cryptography` extra (Fernet = AES-128-CBC + HMAC). We do NOT ship a homemade cipher;
if the extra is absent and encryption is requested, we refuse with a clear error
rather than provide security theater.
"""

from __future__ import annotations

import hashlib

from .probes import SECRET_PATTERNS
from .errors import ConfigError

_REDACT_PREFIX = "[REDACTED:"


def _token(secret: str) -> str:
    return f"{_REDACT_PREFIX}{hashlib.sha256(secret.encode()).hexdigest()[:8]}]"


def redact_text(text: str) -> tuple[str, int]:
    """Return (redacted_text, count). Deterministic; safe on None."""
    if not text:
        return text or "", 0
    count = 0
    out = text
    for pat in SECRET_PATTERNS:
        def _sub(m):
            nonlocal count
            count += 1
            return _token(m.group(0))
        out = pat.sub(_sub, out)
    return out, count


def contains_secret(text: str) -> bool:
    return any(p.search(text or "") for p in SECRET_PATTERNS)


_FINDING_TEXT_FIELDS = ("response_excerpt", "raw_request", "raw_response", "prompt",
                        "evidence_svg", "raw_output")


def redact_finding(f) -> int:
    """Redact secret-shaped content in a Finding's persisted text fields in place.

    Assumes evidence_hash was already computed from the ORIGINAL raw content, so
    chain of custody is preserved. Returns number of redactions applied.
    """
    total = 0
    for attr in _FINDING_TEXT_FIELDS:
        val = getattr(f, attr, None)
        if isinstance(val, str) and val:
            red, n = redact_text(val)
            if n:
                setattr(f, attr, red)
                total += n
    # multi-turn trails
    for turn in getattr(f, "turns", []) or []:
        for k in ("sent", "got"):
            if isinstance(turn.get(k), str):
                turn[k], n = redact_text(turn[k])
                total += n
    if total:
        f.metadata = getattr(f, "metadata", {}) or {}
        f.metadata["redactions"] = f.metadata.get("redactions", 0) + total
    return total


def redact_all(findings) -> int:
    return sum(redact_finding(f) for f in findings)


def redact_exchanges(exchanges) -> int:
    """Redact HAR-style exchange bodies in place."""
    total = 0
    for ex in exchanges or []:
        for k in ("request_body", "response_body", "request", "response", "body"):
            if isinstance(ex.get(k), str):
                ex[k], n = redact_text(ex[k])
                total += n
    return total


# ---- optional encryption (gated on the 'crypto' extra) --------------------- #
def encryption_available() -> bool:
    try:
        import cryptography.fernet  # noqa: F401
        return True
    except Exception:
        return False


def _derive_key(password: str, salt: bytes) -> bytes:
    import base64
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(dk)


def encrypt_dir(evidence_dir: str, password: str) -> int:
    """Encrypt every file in evidence_dir in place (.enc), removing plaintext.

    Requires the optional 'cryptography' extra. Raises ConfigError if unavailable
    so callers get an honest failure instead of fake encryption.
    """
    if not encryption_available():
        raise ConfigError(
            "encrypted evidence requires the optional dependency: "
            "pip install glasscage[crypto]  (no homemade cipher is provided)")
    import os
    from cryptography.fernet import Fernet
    salt = os.urandom(16)
    fernet = Fernet(_derive_key(password, salt))
    count = 0
    for root, _, files in os.walk(evidence_dir):
        for name in files:
            if name.endswith(".enc") or name == "SALT":
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                data = fh.read()
            with open(path + ".enc", "wb") as fh:
                fh.write(fernet.encrypt(data))
            os.remove(path)
            count += 1
    with open(os.path.join(evidence_dir, "SALT"), "wb") as fh:
        fh.write(salt)
    return count
