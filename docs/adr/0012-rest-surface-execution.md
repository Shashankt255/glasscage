# ADR 0012 — REST surface execution

Status: Accepted · Phase 2 / PR #12

Discharges the follow-up [ADR 0011](0011-multi-surface-execution.md) deferred to "the first
non-chat driver PR", including its open review risk D3 (operational controls enforced by the
target rather than the driver). Makes [ADR 0007](0007-action-model-generalisation.md)'s
`HttpAction` non-experimental by giving it a consumer, and supplies the first probe that
exercises [ADR 0006](0006-probe-surface-applicability.md)'s non-CHAT branch in production
rather than only in tests.

> **Requirement labels.** The implementation cites R1, R2, R3, R4 and R8. R5–R7 were
> assigned in a drafting record that is not present in this repository and are **not**
> reconstructed here — inventing them would fabricate a contract nothing implements. The
> labels below are the ones the code actually references, kept at their original numbers so
> existing source comments stay accurate.

## Context
Every surface driven end to end before this PR was CHAT, and every built-in probe was
prompt-shaped: it called `send(prompt)` and read free text back. Three layers had been
declared against a future non-chat driver without one existing — `HttpAction` (ADR 0007,
"no driver consumes it yet"), `Observation.request`/`status`/`custody_hash` (ADR 0008), and
`Probe.surface_kinds` (ADR 0006, defaulting to CHAT for all built-ins). ADR 0011 closed
multi-surface execution for CHAT and named the REST driver as the next step.

The authorisation asymmetry is the load-bearing part of the context. `audit.Scope.check()`
returns silently on an empty allowlist, and its own comment defers enforcement to the
`--authorized` CLI flag. REST has no CLI path, so that gate never runs. A REST target with
no scope would therefore have enforced nothing at all while appearing governed.

## Decision

### R1 — A REST target requires a non-empty Scope, and is refused without one
Possession of a target is not authorisation. `RestDriver` declares `requires_scope = True`;
the ownership boundary in `targets/compat.py` enforces the declaration without knowing which
kind demanded it, and `rest.require_scope` refuses both an absent scope and one whose
allowlist is empty. Refusal happens when the `SurfaceTarget` is constructed — before any
socket is opened. Chat keeps its optional scope because `--authorized` gates it; the
asymmetry is deliberate and has exactly one reason.

### R2 — One canonical serialization serves custody, identity and reproduction
`rest.canonical_request` emits

```
<METHOD> <absolute-url>[?<sorted query>]
<lowercased header>: <value>     one per line, sorted
                                 blank line
<canonical body>
```

Every ordering is total: no timestamps, no dict iteration order, no locale. One format serves
three consumers, so the hash that attests to a request, the subject digest that gives its
Finding identity (ADR 0010), and the command that reproduces it cannot drift apart.

### R3 — Reproduction re-issues exactly what was sent
`repro.build` renders curl from `Finding.prompt`, which carries the very string the driver
hashed for custody — not a request rebuilt from remembered parts. Authorization-bearing
headers are redacted; nothing else is altered, added or dropped.

### R4 — `SurfaceTarget.drive(action)` is the contract for non-chat probes
`send(prompt)` remains the CHAT contract and is unchanged. A probe reaching for `drive` on a
run with no bound surface cannot occur: ADR 0006 resolves the driven kind to CHAT when no
surface is bound, so a non-chat probe is gated to NOT ASSESSABLE before it runs.

### R8 — The absolute URL is composed once
`RestDriver._url_for` composes it, and the scope check, the issued request, the custody hash
and the reproduction command all read that one value. Four consumers agreeing by construction
rather than by parallel string-building.

### The drivable set widens from {CHAT} to {CHAT, REST}
`drivable_surfaces_of` accepts both. Every other kind still has no driver and is refused
loudly rather than silently assessed at the wrong surface. `chat_surfaces_of` is retained as
an unchanged-signature alias so existing callers, including `engine.py`, keep working;
its behaviour widens with the set.

### The REST probe is registered and included in the default battery
`RestResponseDisclosureProbe` (LLM02) is a first-class registered probe, not opt-in. It
reuses `SECRET_PATTERNS` — the detector the chat disclosure probe uses — so the verdict rule
is identical across transports and only the transport differs. It drives the surface's *own
declared locator*, so it issues an operation the surface already describes rather than
guessing at paths.

The visible consequence is accepted deliberately: because the probe declares `(REST,)` and a
default run is CHAT, **every chat run now emits one additional NOT_ASSESSABLE finding**
recording that a registered probe was not applicable. Gating a registered probe honestly is
preferred to hiding the probe from the battery; a battery that silently omits what it cannot
assess reports a coverage figure it has not earned.

### Recon is determined per surface kind
A chat prompt is meaningless to a REST endpoint. Sent to one it arrives as a refused
`PromptAction`, so a prompt-only recon would mark every REST surface unreachable and skip it.
`run_recon` dispatches on the bound surface's kind and re-issues the surface's declared
locator as its reachability probe. `model_hints`, `guardrail_signals`, `tool_surface` and
`refusal_style` stay empty for REST — that is the honest answer for the kind, not a gap to be
filled later.

### Driving a surface is runtime evidence
`coverage_provenance` classifies a probe by how it obtains evidence. A probe that drives with
an Action is runtime-tested exactly as one that sends a prompt is; only the transport
differs. `runtime_coverage_ratio` is unchanged in value, because LLM02 already had a
runtime chat probe.

## Alternatives considered
1. **Optional/opt-in REST probe, excluded from the default battery.** Rejected: it would
   remove the extra NOT_ASSESSABLE finding from chat runs at the cost of a battery whose
   membership depends on invocation, and coverage figures that vary with it.
2. **Making `Scope` mandatory for every target kind.** Rejected: it would break every
   existing chat invocation to solve a problem chat does not have, since `--authorized`
   already gates it.
3. **Reproducing REST findings by rebuilding the request from method/path/headers.**
   Rejected: a second construction path can drift from the one that was hashed. Rendering
   from the stored canonical string makes drift structurally impossible.
4. **A shared prompt-and-action probe base.** Rejected: the two contracts have disjoint
   inputs; merging them makes every field optional and the base class meaningless.
5. **Teaching `run_recon` to fingerprint REST (verbs, status codes, headers).** Rejected as
   out of scope and dishonest by default: reachability is what recon can establish for REST
   without inventing chat concepts that do not apply.

## Consequences
- **Positive:** the first non-chat surface is assessed end to end, with fail-closed
  authorisation, custody, Finding identity that separates endpoints, and reproduction equal
  to what was issued. Three previously declared-but-unconsumed layers gain a consumer.
- **Unavoidable:** every chat run gains one NOT_ASSESSABLE finding, and `not_assessable_count`
  rises by one. Three tests encoding "no probe is ever surface-gated on a chat run" and "every
  registered probe is chat-applicable" were replaced knowingly — those invariants are false by
  construction once a non-chat probe is registered.
- **Unchanged:** the benchmark, `runtime_coverage_ratio`, replay bundles, SARIF, chat
  behaviour, custody hashes, graph identity scheme and determinism. Verified by comparison
  against the Commit 1 tree, not by assertion.
- **Accepted:** REST recon establishes reachability only. A REST surface contributes no
  model or guardrail fingerprint, so probes that read those from recon have nothing to read
  on a REST surface — correct, since they are all chat probes and are gated there anyway.
- **Follow-up (not this ADR):** GraphQL, MCP runtime and function drivers; REST surface
  binding from `discovery` candidates; per-operation batteries beyond disclosure.

## Defect found and fixed during implementation
`repro._curl_from_canonical` split the canonical request on the first `\n\n`. An empty header
block still occupies a line, so a header-less request serializes its separator as `\n\n\n`;
partitioning stopped one line early and handed the separator's own newline to the body. A
bodyless GET reproduced as `--data '<newline>'` and a real body gained a leading newline —
so the reproduction command was **not** the request that was issued, contradicting R3. The
REST probe sends no headers, so this fired on every REST finding. Fixed by splitting
positionally against the producer's grammar (`repro._split_canonical`); regression tests
fail against the pre-fix implementation.
