# Before / After — the narrative reporting layer

Same run, same graph, same analysis. Only the rendering changed.

| | Before (1.0.0rc2) | After (narrative layer) |
|---|---|---|
| Markdown report | 6,617 bytes | 18,219 bytes |
| Assessment Story | absent | 13 evidence-classified sections |
| Attack Narratives | absent | 8 strategies, deduped to distinct paths |
| Attack Paths section | prose repeated per path | condensed index table (prose moved to narratives) |
| Executive summary | metrics only | + one-line "most consequential scenario" headline |
| Audience views | none | 5 (`--views all`) |
| Analysis performed | — | **identical (zero new analysis)** |

Files: `BEFORE_report_rc2.md`, `AFTER_report_with_narratives.md`,
`VIEW_executive.md`, `VIEW_incident_response.md`, `VIEW_compliance.md`.

## What the reader gains
Before, a reader got metrics and a list of paths. After, they get the same facts told as
a story whose every clause cites the graph — plus an explicit statement of what is NOT
demonstrated, which the metrics alone never conveyed.

## What did NOT change
Findings, paths, trust analysis, blast radius, coverage, posture, remediation, SARIF,
and replay bundles are byte-for-byte the same logic. The narrative layer only reads.
