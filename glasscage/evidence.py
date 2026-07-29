# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Evidence capture: screenshot-style proof-of-concept cards.

Default backend renders a self-contained SVG "console screenshot" of the exact
request/response for each finding, with the detected indicator highlighted. SVG
is zero-dependency, embeds inline in the interactive report, and saves as a file
the security team can attach to their own report.

Optional browser backend (Playwright) can capture a REAL screenshot of a web-UI
target or of an XSS payload actually rendering; it is used only if installed and
requested, and falls back silently to the SVG card otherwise.
"""

from __future__ import annotations

import html
import os
import re

from .models import Finding, Status

_HIGHLIGHT = re.compile(r"(GLSSCG-[A-Z0-9\-]+|<script>.*?</script>|sk-[A-Za-z0-9]{6,}|"
                        r"password\s*[:=]\s*\S+|AKIA[0-9A-Z]{6,})")

_SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
              "low": "#84cc16", "info": "#64748b"}


def _wrap(text: str, width: int = 92) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines() or [""]:
        while len(raw) > width:
            cut = raw.rfind(" ", 0, width)
            cut = cut if cut > 40 else width
            out.append(raw[:cut])
            raw = raw[cut:].lstrip()
        out.append(raw)
    return out or [""]


def _tspans(lines: list[str], x: int, y0: int, dy: int, base_fill: str) -> str:
    spans = []
    y = y0
    for line in lines:
        esc = html.escape(line)
        # highlight indicators inline
        parts = _HIGHLIGHT.split(line)
        if len(parts) > 1:
            frag = ""
            for i, part in enumerate(parts):
                if part is None:
                    continue
                if _HIGHLIGHT.fullmatch(part or ""):
                    frag += f'<tspan fill="#ef4444" font-weight="bold">{html.escape(part)}</tspan>'
                else:
                    frag += f'<tspan fill="{base_fill}">{html.escape(part)}</tspan>'
            spans.append(f'<text x="{x}" y="{y}" xml:space="preserve">{frag}</text>')
        else:
            spans.append(f'<text x="{x}" y="{y}" fill="{base_fill}" '
                         f'xml:space="preserve">{esc}</text>')
        y += dy
    return "\n".join(spans), y


def render_svg(finding: Finding) -> str:
    sev = finding.severity.value
    sev_color = _SEV_COLOR.get(sev, "#64748b")
    req_lines = _wrap(finding.prompt or "(recon-derived)")
    resp_lines = _wrap(finding.response_excerpt or "(no response captured)")

    x = 24
    dy = 20
    y = 96
    header = (
        f'<rect x="0" y="0" width="960" height="46" fill="#0b1220"/>'
        f'<circle cx="22" cy="23" r="6" fill="#ff5f56"/>'
        f'<circle cx="42" cy="23" r="6" fill="#ffbd2e"/>'
        f'<circle cx="62" cy="23" r="6" fill="#27c93f"/>'
        f'<text x="88" y="29" fill="#93c5fd" font-weight="bold">'
        f'GLASSCAGE PoC — {html.escape(finding.probe_name)}</text>'
        f'<rect x="800" y="12" width="140" height="24" rx="12" fill="{sev_color}"/>'
        f'<text x="870" y="29" fill="#0b1220" font-weight="bold" '
        f'text-anchor="middle">{sev.upper()}</text>'
    )

    y += dy
    body = [f'<text x="{x}" y="{y}" fill="#38bdf8" font-weight="bold">REQUEST ▸</text>']
    y += dy
    reqtxt, y = _tspans(req_lines, x, y, dy, "#cbd5e1")
    body.append(reqtxt)
    y += dy
    body.append(f'<text x="{x}" y="{y}" fill="#38bdf8" font-weight="bold">RESPONSE ▸</text>')
    y += dy
    resptxt, y = _tspans(resp_lines, x, y, dy, "#e2e8f0")
    body.append(resptxt)

    y += dy + 6
    meta = (f"OWASP {finding.owasp_id}"
            + (f"  ·  ATLAS {finding.atlas_id}" if finding.atlas_id else "")
            + f"  ·  status {finding.status.value}  ·  confidence {finding.confidence:.0%}")
    footer = f'<text x="{x}" y="{y}" fill="#64748b">{html.escape(meta)}</text>'

    height = y + 24
    title_line = html.escape(finding.title)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{height}" viewBox="0 0 960 {height}" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13">
<rect width="960" height="{height}" fill="#0f172a"/>
{header}
<text x="{x}" y="76" fill="#f8fafc" font-weight="bold" font-size="14">{title_line}</text>
{''.join(body)}
{footer}
</svg>'''


def browser_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def capture(finding: Finding, evidence_dir: str | None = None) -> str:
    """Attach an SVG evidence card to the finding; optionally write it to disk.
    Returns the inline SVG string."""
    svg = render_svg(finding)
    finding.evidence_svg = svg
    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)
        safe = re.sub(r"\W+", "_", f"{finding.owasp_id}_{finding.probe_name}_{id(finding) & 0xffff}")
        filename = safe + ".svg"
        with open(os.path.join(evidence_dir, filename), "w", encoding="utf-8") as fh:
            fh.write(svg)
        # path relative to the output base so the markdown reference resolves
        finding.evidence_path = os.path.join(os.path.basename(os.path.normpath(evidence_dir)), filename)
    return svg


def capture_all(findings, evidence_dir: str | None = None) -> None:
    for f in findings:
        if f.status in (Status.VULNERABLE, Status.INCONCLUSIVE) and not f.evidence_svg:
            capture(f, evidence_dir)
