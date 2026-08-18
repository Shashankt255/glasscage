# ADR 0026 — MCP manifest shape contract

Status: Accepted · Phase 3 / PR #27

Applies the refusal discipline `targets/discovery.py` already uses to `mcp.py`'s manifest
reader. Amends no existing ADR. No format, hash, dependency or CLI contract change.

## Context
`_iter_tools` read the manifest like this:

```python
tools = manifest.get("tools", manifest if isinstance(manifest, list) else [])
```

`manifest.get(...)` is evaluated **before** the default expression beside it, so the
`isinstance(manifest, list)` fallback could never run: any manifest that was not a `dict`
raised `AttributeError` on the `.get` itself. The fallback was unreachable dead code, and
the bare-list form it was written to accept was exactly one of the shapes that crashed.

Both public entry points route through it — `analyze_manifest` and `snapshot` — so both
`--mcp-manifest` and `--mcp-baseline` were affected.

Measured on `v0.5.0-custody-completeness`, ten shapes through both functions:

```
object with tools     ok               list of tools                  AttributeError
object without tools  ok               empty list                     AttributeError
string / number       AttributeError   boolean / null                 AttributeError
list with a non-dict  AttributeError   dict whose `tools` is not list AttributeError
```

Eight of ten crashed. An `AttributeError` is not part of this repository's error contract:
`errors.py` defines `GlasscageError` so that `cli.py` can render `error: …` and exit 2.
`targets/discovery.py` already refuses the identical input correctly —
`ConfigError(f"MCP manifest must be an object, got {type(manifest).__name__}")` — so the
codebase already contained the right answer in one place and the wrong one in another.

## Decision

### 1. The shape is checked before any field access
`_iter_tools` establishes what it is holding before reading from it. This is the whole
defect: an evaluation-order fault, not a parser design problem, so the parser is not
redesigned.

### 2. A top-level list is accepted
A `tools/list` response is a list of tool objects, and the dead fallback shows this was
always the intent. It is accepted and treated as the tool list. `snapshot([t])` and
`snapshot({"tools": [t]})` are required to agree.

### 3. A well-formed object keeps its existing behaviour
Precisely, for a top-level `dict`:

- **no `tools` key** — retains existing behaviour: it yields nothing rather than erroring.
- **`tools` present and a list** — retains existing behaviour, read exactly as before.

Both were verified byte-identical against `v0.5.0` for findings and snapshots. The third
case is *not* unchanged and is stated separately below.

### 4. An object whose `tools` is present but not a list is invalid
It raises `ConfigError` identifying the type received — for example
`MCP manifest 'tools' must be a list, got str`.

This is a **deliberate behavioural change**, and the only one affecting object-shaped
manifests: on `v0.5.0` this shape raised `AttributeError` when the entry was iterated, so
it was already broken; it now fails through the documented error contract instead of
crashing. Coercing it to an empty list was rejected — a manifest declaring `tools` and
supplying something that is not a list is malformed, and silently analysing zero tools
would report a clean result for input the operator got wrong.

### 5. Anything else is refused, naming the type
A string, number, boolean or null raises `ConfigError` identifying the type received. This
matches `targets/discovery.py` for the same input, so the two MCP readers now agree.

### 6. A malformed element is refused, not skipped
A list entry that is not an object raises `ConfigError` naming its index. Skipping it would
silently shrink the analysed surface — the tool would report on fewer tools than the
operator supplied without saying so, which is the failure mode this project has been
closing since [ADR 0021](0021-operational-controls-precede-traffic.md).

### 7. An empty list is valid
Zero tools is a legitimate manifest, not an error. It yields no tool findings.

## Security analysis
- **What this fixes:** malformed manifest input is refused through the documented error
  contract instead of crashing, and a partially malformed manifest can no longer be
  analysed with entries quietly dropped.
- **Severity:** low. It requires operator-supplied malformed input and has no security
  consequence beyond the crash itself; the value is contract consistency and the
  no-silent-shrinkage property of §6.
- **What it does not change:** the analysis itself, the detectors, `Finding` shape, and
  every object-shaped manifest's output. `--mcp-manifest`/`--mcp-baseline` CLI semantics
  are unchanged for all previously-working inputs.
- **Not in scope:** runtime MCP interaction remains static-manifest-only (ROADMAP P2), and
  MCP-manifest-only mode still discards `--rest-config`/`--harness`
  ([ADR 0021](0021-operational-controls-precede-traffic.md) follow-up, untouched here).

## Consequences
- **Positive:** the bare-list manifest form now works as intended; every JSON-valid input
  produces either analysis or a typed refusal.
- **Behavioural change, intended:** inputs that previously raised `AttributeError` now
  raise `ConfigError`, which `cli.py` renders as `error: …` with exit 2. Inputs that
  previously crashed and now succeed (bare list, empty list) gain analysis they should
  always have had.
- **Unchanged:** every other module; object-manifest findings and snapshots verified
  byte-identical to `v0.5.0`; all frozen invariants; PR #26's exit-code semantics.
- **No migration.** No format or schema change.

## Rejected alternatives
1. **Refuse every non-dict, including lists** — as `discovery.py` does. Rejected: it is
   simpler, but it discards the evident intent of the existing fallback and would reject a
   raw `tools/list` payload, which is the most natural thing an operator will paste.
2. **Coerce scalars to an empty manifest.** Rejected: silent acceptance of nonsense input,
   producing an empty report that looks like a clean result.
3. **Skip malformed list elements.** Rejected: see §6 — it shrinks the analysed surface
   without telling the operator.
4. **Move the guard into `analyze_manifest` and `snapshot` separately.** Rejected: two call
   sites to keep in step; `_iter_tools` is the single point both already share.
