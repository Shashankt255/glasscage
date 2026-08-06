# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Reproduction steps: numbered, manual re-validation guidance per finding.

Produces exact steps a security team follows to reproduce a finding by hand,
including a ready-to-run curl built from the target config (auth redacted). MCP
findings get manifest-inspection steps instead of an HTTP request.
"""

from __future__ import annotations

import json
import re

_REDACT_HEADERS = {"authorization", "x-api-key", "api-key", "cookie", "x-auth-token"}
_CANARY_HINT = {
    "direct-injection-canary": "the token GLSSCG-INJECT-OK appears as the reply",
    "indirect-injection-rag": "the token GLSSCG-INDIRECT-OK appears in the reply",
    "multi-turn-erosion": "GLSSCG-INJECT-OK appears by the final turn",
    "encoded-injection": "the decoded token GLSSCG-INJECT-OK appears",
    "payload-splitting": "the reassembled token GLSSCG-INJECT-OK appears",
    "jailbreak-persona": "GLSSCG-INJECT-OK appears in persona mode",
    "multilingual-injection": "GLSSCG-INJECT-OK appears from the foreign-language instruction",
    "insecure-output-handling": "the literal <script>GLSSCG-XSS-CANARY</script> is returned unescaped",
    "system-prompt-leak": "configuration/system-prompt text is disclosed",
    "sensitive-info-disclosure": "secret-shaped content (keys/passwords) is returned",
}


_CANONICAL_FIRST_LINE = re.compile(r"^[A-Z]+ https?://\S*$")


def _is_canonical_request(prompt: str) -> bool:
    """True when the prompt is a canonical REST request (ADR 0012 R2/R3).

    The canonical form's first line is `<METHOD> <absolute-url>`. A chat prompt is free
    text and cannot match: it would have to begin with an uppercase verb followed by a
    single absolute URL and nothing else.
    """
    first = (prompt or "").split("\n", 1)[0]
    return bool(_CANONICAL_FIRST_LINE.match(first))


def _split_canonical(prompt: str) -> tuple[str, list[str], str]:
    """Split a canonical request into (request line, header lines, body).

    Mirrors the producer in `targets.rest.canonical_request`, which joins
    `[request line, header block, "", body]`. An empty header block is still a line, so a
    request with no headers serializes its separator as `\\n\\n\\n`. Partitioning on the
    first `\\n\\n` therefore stops one line early on exactly the requests the REST probe
    issues - it has no headers - and hands the separator's own newline to the body,
    inventing a body for a bodyless GET and prefixing a real one with a stray newline.
    Splitting positionally keeps reproduction equal to what was sent (ADR 0012 R3).
    """
    lines = (prompt or "").split("\n")
    if len(lines) > 1 and lines[1] == "":
        return lines[0], [], "\n".join(lines[3:])   # empty header block occupies line 1
    sep = 1
    while sep < len(lines) and lines[sep] != "":
        sep += 1
    return lines[0], lines[1:sep], "\n".join(lines[sep + 1:])


def _curl_from_canonical(prompt: str) -> str:
    """Render curl from the canonical REST request that produced the finding.

    Reproduction is built from `Finding.prompt`, which carries the exact serialization the
    driver hashed for custody, so the reproduced request is the request that was issued.
    """
    request_line, header_lines, body = _split_canonical(prompt)
    method, _, url = request_line.partition(" ")
    parts = [f"curl -sS -X {method} '{url}' \\"]
    for header in header_lines:
        if not header.strip():
            continue
        name, _, value = header.partition(":")
        val = "<REDACTED>" if name.strip().lower() in _REDACT_HEADERS else value.strip()
        parts.append(f"  -H '{name.strip()}: {val}' \\")
    if body:
        parts.append("  --data '" + body.replace("'", "'\\''") + "'")
    else:
        parts[-1] = parts[-1].rstrip(" \\")
    return "\n".join(parts)


def _curl(target, prompt: str) -> str:
    from .target import _inject, PROMPT_PLACEHOLDER  # local import to avoid cycle
    body = _inject(target.body_template, prompt)
    parts = [f"curl -sS -X {target.method} '{target.url}' \\"]
    headers = {"Content-Type": "application/json", **target.headers}
    for k, v in headers.items():
        val = "<REDACTED>" if k.lower() in _REDACT_HEADERS else v
        parts.append(f"  -H '{k}: {val}' \\")
    body_str = json.dumps(body).replace("'", "'\\''")
    parts.append(f"  --data '{body_str}'")
    return "\n".join(parts)


def build(finding, target=None) -> list[str]:
    # MCP findings: no HTTP request; inspect the manifest.
    if finding.probe_name == "mcp-analyzer":
        tool = finding.prompt.replace("tool: ", "")
        steps = [
            "Obtain the MCP server's tool manifest (call `tools/list` or read the config).",
            f"Locate the tool '{tool}' and read its description and inputSchema in full.",
            "Confirm the flagged pattern is present (model-directed instruction, invisible "
            "characters, or a URL/path parameter) exactly as shown in Evidence.",
        ]
        if "rug pull" in finding.title.lower() or "changed" in finding.title.lower():
            steps.append("Diff the current definition against your approved baseline snapshot "
                         "(`glasscage --mcp-baseline`) and confirm the change was unapproved.")
        steps.append("Then work through the false-positive checks under 'Verify'.")
        return steps

    prompt = finding.prompt or ""
    indicator = _CANARY_HINT.get(finding.probe_name, "the indicator described in Evidence appears")
    steps = [f"Target: {getattr(target, 'name', 'the endpoint')}"]
    if _is_canonical_request(prompt):
        # ADR 0012: a REST finding carries the canonical request that produced it.
        steps.append("Re-issue this exact request (auth redacted — insert your own token):")
        steps.append(_curl_from_canonical(prompt))
    elif target is not None and prompt and not prompt.startswith("("):
        steps.append("Send this exact request (auth redacted — insert your own token):")
        steps.append(_curl(target, prompt))
    elif prompt:
        steps.append(f"Send this exact prompt to the bot:\n{prompt}")
    if finding.turns:
        steps.append("Multi-turn: send each message below in order, same session:")
        for t in finding.turns:
            steps.append(f"  turn {t['turn']}: {t['sent']}")
    steps.append(f"Capture the full response and confirm: {indicator}.")
    steps.append("Screenshot the request + response (see the attached evidence card).")
    steps.append("Before reporting, run the false-positive checks under 'Verify'.")
    return steps


def build_all(findings, target=None) -> None:
    for f in findings:
        if not f.reproduction_steps:
            f.reproduction_steps = build(f, target)
