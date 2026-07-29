# Release Notes — PR #3: `--discover` surface inventory

Phase 1 · CLI exposure · merged on top of PR #1 (engine surface wiring) and PR #2
(surface discovery).

## Summary

`--discover SPEC` enumerates the **drivable surface inventory** of an AI application from
an OpenAPI document or an MCP `tools/list` manifest, prints an ASCII markdown table, and
writes `<out>_surfaces.md` and `<out>_surfaces.json`.

Before this release, the discovery capability added in PR #2 had **no consumer outside
its own package** — no CLI flag, no report, no pipeline call site could reach it. This
release gives it a user-facing entry point and retires that documented debt.

The mode constructs no target, sends no probe, produces no assessment report, and binds
no surface to a driver. It is an inventory, not a test.

## Architecture impact

**None.** No architectural decision was made and no ADR was written for this PR.

- No new module. Two additive renderers (`discovery.to_markdown`, `discovery.to_json`)
  were added to the module that already owns the data, following the convention already
  used by `benchmark`, `adapter_validation`, `orchestrator` and `validation`.
- The CLI branch reuses the existing target-free standalone-mode shape
  (`--validate-adapters`, `--benchmark`): compute → print markdown → write
  `<out>_X.(md|json)` → `return 0`. It reuses `cli._load` and the existing
  `GlasscageError` → exit-2 handler; no new error convention was introduced.
- No new AAKG node or edge type, no probe, no detector, no scoring change.
- **PR #1's attribution guard is untouched.** Inventory reporting never binds a surface
  to a driver, so the "one authoritative target" invariant is not engaged.
- The layering rule holds: `targets/discovery.py` still imports only `.surface` and
  `..errors`, and `tests/test_targets_foundation.py::TestDependencyDirection` passes
  unmodified.

## User-visible changes

- **New flag `--discover SPEC`** (Experimental). Runs standalone: no `--config`,
  `--demo`, `--harness` or `--authorized` required.
  ```bash
  python -m glasscage --discover samples/mcp_manifest.json --out inv
  ```
- **New artifacts:** `<out>_surfaces.md` and `<out>_surfaces.json`. The JSON is
  deterministic — identical input produces byte-identical output across runs.
- **Table output is ASCII-only**, so it prints safely on a Windows cp1252 console.
- **Honest empty result:** a document with no drivable operations prints
  "No surfaces discovered." and writes an empty JSON list rather than an empty table.
- **Malformed input** raises `ConfigError`, which both `python -m glasscage` and
  `python cli.py` map to exit code 2.
- Documented in [`docs/COMMAND_REFERENCE.md`](docs/COMMAND_REFERENCE.md), including why
  this is **not** the same as `--schema`.

### `--discover` vs `--schema`

Both read OpenAPI; they answer different questions and neither replaces the other.

| | `--schema` | `--discover` |
|---|---|---|
| Runs during | an assessment | nothing — standalone |
| Produces | schema-confirmed tools feeding blast radius | a surface inventory |
| Keeps | capability, side-effect classification | path, HTTP method, I/O schema |
| Discards | path, method, parameters | capability classification |

## Developer changes

- `glasscage.targets.discovery.to_json(candidates) -> list[dict]` — plain JSON-safe dicts
  with the `SurfaceCandidate` field set and order; `kind` serializes to its string value.
- `glasscage.targets.discovery.to_markdown(candidates) -> str` — deterministic ASCII
  table. Locator renders per kind: `POST /v1/chat` for REST, the bare tool name for MCP.
- Both are pure functions: no I/O, no mutation of the input list.
- Neither is re-exported from `glasscage.targets`; import the submodule directly
  (`from glasscage.targets import discovery`). This kept `targets/__init__.py` unchanged.
- Tests: `tests/test_surface_inventory.py`, 14 tests. Suite total **270 passing**.
- Detector benchmark unchanged: P 0.9697 · R 0.9143 · F1 0.941 · reproducibility 1.0.

## Backward compatibility

**Fully preserved.** The change is additive and default-off.

- `--discover` defaults to unset; every existing CLI mode behaves exactly as before.
- No existing function signature, return shape, or output artifact changed.
- No existing test file was modified; the full pre-PR baseline passes unchanged.
- No deletions. No new runtime dependency — standard library only.
- `glasscage/targets/__init__.py`, `engine.py`, probes, recon, attackers, reporting,
  scoring, the AAKG package and `schema.py` were not touched.

## Migration notes

**None required.** No action is needed to upgrade.

- Existing scripts, configs and CI invocations are unaffected.
- If you begin consuming `<out>_surfaces.json`, note that its field names mirror
  `SurfaceCandidate` (`id`, `kind`, `locator`, `io_schema`, `source`) and that the format
  is **Experimental** — it may change before GA.
- Candidate ids are `rest:<method>:<path>` and `mcp_tool:<name>`. Treat them as stable
  within a release, not across releases.

## Known limitations

- **Experimental.** The output format is not yet a stability commitment.
- **`$ref` is not resolved.** Unresolved references pass through into `io_schema`
  verbatim, so the surface count is a **lower bound** on specs that lean on references.
- **Only `paths` → HTTP methods and MCP `tools` are enumerated.** Webhooks, callbacks and
  server-variable expansion are out of scope.
- **Candidates are never bound or driven.** Nothing in the inventory is probed; the
  inventory is not evidence about the application's security posture.
- **No live discovery.** The spec must be supplied as a local file; GLASSCAGE does not
  fetch a spec from the network.
- **Inconsistent robustness with `--schema`:** `schema.from_openapi` raises
  `AttributeError` on a path whose value is not an object, while `--discover` skips such
  entries. Pre-existing, recorded in ADR 0003, not fixed here.
- The pre-existing Windows cp1252 failure in `tests/test_hardening.py` is unchanged; local
  full-suite runs still need `PYTHONIOENCODING=utf-8`. `--discover` itself is unaffected.

## Future work

In dependency order, per ADR 0003:

1. **Per-surface attribution** — the gateway. Until a finding records the surface it was
   observed on, PR #1's one-authoritative-target guard correctly prevents driving any
   endpoint other than the supplied target.
2. **Binding** — promoting a discovered `SurfaceCandidate` to a driven `Surface`.
3. **Non-chat drivers** (REST, GraphQL) — blocked additionally by the action model:
   `PromptAction` is the only `Action` kind and every probe is prompt-shaped.

Not planned in Phase 1: live spec fetching, `$ref` resolution, and surfacing the
inventory inside an assessment report.

## Related ADR

- **None of its own** — deliberate. This PR made no architectural decision; a fourth ADR
  would have been documentation noise.
- [ADR 0003 — Read-only surface discovery](docs/adr/0003-surface-discovery.md): the
  capability this release exposes, including the `schema.py` boundary and the scope limits
  inherited here.
- [ADR 0002 — Engine surface wiring](docs/adr/0002-engine-surface-wiring.md): the
  attribution guard that makes inventory-only exposure the correct step at this point, and
  the follow-up list that names "CLI exposure".

## Related roadmap milestone

**Phase 1 — CLI exposure**, the third follow-up named in ADR 0002 ("surface discovery,
non-chat drivers, CLI exposure") and the only one of the three that was unblocked: a
non-chat driver requires a new `Action` kind, and driving a discovered endpoint requires
per-surface attribution.

Not a GA blocker. The Priority-0 items in [`docs/ROADMAP.md`](docs/ROADMAP.md) —
real-target validation, genuine external-tool ingestion, control verification, release
signing — are unaffected by this release and remain open.
