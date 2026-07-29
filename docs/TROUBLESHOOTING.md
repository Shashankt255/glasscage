# Troubleshooting

Fixes for common problems, grouped by area. For install-specific issues see
[INSTALL.md](INSTALL.md#common-installation-failures).

## Installation

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: glasscage` | Activate your venv; `pip install .` from the repo root. |
| `SyntaxError` on import | Python < 3.10. Install 3.10+. |
| `error: externally-managed-environment` | Use a virtual environment (PEP 668). |
| `pip install glasscage[crypto]` fails | No `crypto` extra exists in rc3. Run `pip install cryptography`. |

## Invalid targets

| Symptom | Cause | Fix |
|---|---|---|
| "Refusing to run … without --authorized" (exit 2) | live target without consent gate | add `--authorized` |
| Empty responses / no findings | wrong `response_path` | validate the dotted path against a manual curl of the API |
| Connection errors | bad URL / auth / network | test the endpoint with curl first; check headers |
| All agentic probes `NOT ASSESSABLE` | target is L0/L1 | expected — those probes need an L2 (planner/tool-trace) target |
| Config rejected on load | schema/type error | error message names the field; fix and re-run |

## Plugin failures

| Symptom | Fix |
|---|---|
| "requires --allow-plugins" (exit 2) | add `--allow-plugins` (consent to run unsandboxed code) |
| Plugin didn't run | ensure module sets `GLASSCAGE_PLUGIN_API = "1.0"`, class uses `@register`, and `min_tier` ≤ target tier |
| "plugin API mismatch" | your plugin's major API version differs from `PLUGIN_API_VERSION` ("1.0") |
| Import error inside plugin | the plugin's own bug; run with `--log-level DEBUG` to see the traceback |

## Missing or unexpected reports

| Symptom | Cause | Fix |
|---|---|---|
| No output files | missing/incorrect `--out` | pass `--out BASE`; check write permissions |
| No `_aakg.json` | `--no-aakg` was set | remove `--no-aakg` (AAKG is the default) |
| No narratives/story in JSON | `--no-aakg` was set | narratives/story require the AAKG |
| No view files | `--views` not passed | add `--views all` (or specific audiences) |
| Fewer findings than expected | a probe may be failing silently | run `--log-level DEBUG`; rc3 has broad exception handlers that can turn a failure into a note |

## Narrative generation

| Symptom | Explanation |
|---|---|
| A strategy shows "Not demonstrated." | No graph path matched that strategy. This is correct behaviour — GLASSCAGE refuses to invent a path. |
| A path reads `Hypothesized` despite demonstrated hops | A path's state is its **weakest** hop. One hypothesized hop makes the whole path hypothesized. Not a bug. |
| "no evidence id (structural edge)" in a citation | The edge is architectural (e.g. `crosses`), which carries no finding-level evidence id. Finding evidence is in the Evidence Ledger. |
| MCP Compromise Narrative never demonstrated | GLASSCAGE never contacts an MCP server; MCP is configuration review only. |

## HTML rendering

| Symptom | Fix |
|---|---|
| HTML looks unstyled | open the file directly in a browser; it is self-contained (no external assets) |
| Graph doesn't render | fall back to `*_aakg.json` in a viewer; the JSON is the source of truth |
| Odd characters where model text was | that is HTML-escaping of model output (a safety feature), not corruption |

## Replay bundle issues

| Symptom | Fix |
|---|---|
| Bundle missing | pass `--replay` |
| Replay can't authenticate | replay bundles **strip auth headers** by design; supply credentials in your environment when re-running |

## Redaction issues

| Symptom | Explanation / fix |
|---|---|
| A secret still appears in output | redaction is pattern-based (API key / AWS / password / PEM). Novel formats may pass through — **review before sharing**; extend patterns if needed |
| Everything shows `[REDACTED:…]` | default behaviour; use `--store-raw` on a sandboxed host to retain raw values |
| Encryption "not available" | `pip install cryptography`; verify with `redaction.encryption_available()` |

## Performance

| Symptom | Cause | Mitigation |
|---|---|---|
| Slow on large agentic graphs | narrative edge lookup is a linear scan (no `edge(id)` accessor in rc3); path enumeration is bounded at depth 6 with no count cap | expected against network-bound targets the cost is negligible; for very dense graphs, reduce scope |
| Slow overall | serial execution — no async, no resume | use `--rate` sensibly; run overnight for large engagements |
| High memory | large graphs | memory is linear in graph size; reduce tool/schema breadth if needed |

If a problem is not listed here, re-run with `--log-level DEBUG --log-json` and inspect
the logs; open an issue with the (redacted) log and your GLASSCAGE version.
