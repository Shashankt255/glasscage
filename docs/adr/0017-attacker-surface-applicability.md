# ADR 0017 — Attacker surface applicability

Status: Accepted · Phase 2 / PR #18

Extends [ADR 0006](0006-probe-surface-applicability.md)'s applicability rule from probes to
the adaptive and genetic attackers. Supersedes nothing.

## Context
ADR 0006 established that an assessor which cannot drive the bound surface kind is **never
invoked** and yields one `NOT ASSESSABLE` finding naming the driven kind — *"honest NOT
ASSESSABLE instead of an invalid pass/fail"*. The engine implements that for every
registered probe.

The adaptive and genetic attackers were never brought under it. They are invoked from the
same per-surface loop, immediately after the probe loop, but unconditionally: `driven_kind`
is computed and passed in, and consulted only by the probes above them.

Both are prompt-shaped — `mutation.run` and `genetic.run` each drive through
`target.send()` — so they are CHAT-only in exactly the sense ADR 0006 describes, without
ever declaring it.

The consequence was not a silent skip. Measured on `v0.4.1-coverage-provenance`, a REST
surface with `--adaptive` or `--genetic` **crashed the run**:

```
REST + --adaptive   AttributeError: 'RestTarget' object has no attribute 'body_template'
REST + --genetic    AttributeError: 'RestTarget' object has no attribute 'body_template'
```

The chain: the attacker runs ungated → `RestDriver` refuses the `PromptAction` and returns a
failed `Observation` → a finding is still produced carrying a chat-shaped prompt →
`repro.build_all`, which is outside any `try`, renders it as a chat request → `_curl` reads
`target.body_template` → `SurfaceTarget` delegates to `RestTarget`, which has no such
attribute.

PR #16 made this operator-reachable: `--rest-config … --rest-spec … --adaptive` is a
supported combination of documented flags.

## Decision

### The attackers are CHAT-only, and gated where ADR 0006 gates probes
When the driven kind is not CHAT, each requested attacker emits one `NOT ASSESSABLE`
finding and does not run. The gate lives in the engine's per-surface loop, beside the probe
gate, not inside `mutation.py` or `genetic.py` — the applicability rule stays in the single
place ADR 0006 put it, and the attacker modules keep knowing nothing about surfaces.

### The gated finding reuses the existing shape
Same fields, same `"(surface-gated)"` prompt, same `NOT_ASSESSABLE` status and `INFO`
severity as the probe gate emits. No new sentinel, no new finding shape, no new field.
Reporting, reproduction, the graph and the provenance map treat it identically to a gated
probe because it *is* the same record.

### Gated, not silent
An operator who passes `--adaptive` and receives nothing would have no way to distinguish
"ran and found nothing" from "never ran". Reporting the gate is the same reasoning ADR 0006
gave for probes, and the same reasoning ADR 0012 accepted when registering a REST probe into
a chat-shaped battery.

### Declared by the engine, not by an attacker attribute
A probe declares `surface_kinds`; the attackers are not probes and have no such attribute.
Adding one would make them probe-shaped without making them probes — a new abstraction for
two call sites. The engine states the constraint at the point of invocation instead.

## Alternatives considered
1. **Skip silently when the kind does not match.** Rejected: fixes the crash, reproduces the
   defect ADR 0006 exists to prevent.
2. **Give `mutation` and `genetic` a `surface_kinds` attribute.** Rejected: both are out of
   scope for this PR, and it would spread the applicability rule across three modules.
3. **Make reproduction tolerate a chat prompt on a non-chat target.** Rejected: it treats the
   symptom. The finding should not exist — the attacker should not have run.
4. **Let the attackers drive non-chat surfaces.** Rejected: they generate prompt payloads;
   there is nothing for them to send to a REST endpoint, and inventing one would be a new
   capability.

## Consequences
- **Positive:** a supported flag combination no longer crashes. `--adaptive` and `--genetic`
  now behave on a REST surface exactly as an inapplicable probe does.
- **Changed:** a REST run with an attacker flag produces one additional `NOT ASSESSABLE`
  finding per requested attacker, where it previously produced an exception.
- **Unchanged:** every CHAT run, every direct run with no bound surface (ADR 0006 resolves
  the driven kind to CHAT), and every run without attacker flags. `runtime_coverage_ratio`,
  battery composition, `Finding` field order and count, graph identity, custody, SARIF,
  replay, benchmark, `discovery` output and determinism all verified byte-identical against
  `v0.4.1-coverage-provenance`.
- **Accepted:** the gate names CHAT directly rather than reading a declaration from the
  attacker modules. If a future attacker drives a non-chat kind, this constraint must move
  with it — recorded here so that is a decision rather than a discovery.
