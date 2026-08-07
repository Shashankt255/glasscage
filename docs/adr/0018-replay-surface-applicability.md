# ADR 0018 — Replay surface applicability

Status: Accepted · Phase 2 / PR #19

Applies [ADR 0006](0006-probe-surface-applicability.md)'s applicability discipline to the
replay bundle, as [ADR 0017](0017-attacker-surface-applicability.md) applied it to the
attackers. Supersedes nothing.

## Context
`--replay` crashed a REST assessment:

```
AttributeError: 'RestTarget' object has no attribute 'body_template'   (cli.py:426)
```

`cli.py` built the bundle's `target_config` from `target.body_template` and
`target.response_path` whenever `--config` was absent. A REST run supplies `--rest-config`,
so that branch always fired, and `RestTarget` declares neither attribute. Measured on
`v0.4.2-correctness`: `--demo --replay` and `--harness --replay` both succeed; only REST
crashed. PR #16 made the combination reachable — `--rest-config … --replay` is a supported
pairing of documented flags.

**Guarding the attribute read would not have been sufficient.** The replay artifact is
chat-shaped in three independent places:

- `to_replay` writes `target_config` carrying `body_template` and `response_path`;
- `REPLAY_RUNNER` opens with `from glasscage.target import HTTPChatTarget`, constructs one
  from that config, and calls `t.send(step["prompt"])`;
- `_INDICATOR` has no entry for `rest-response-disclosure`, so a REST step would carry a
  null indicator and the runner's success test could never be true.

A REST finding's prompt is the canonical request, which does not start with `(`, so
`to_replay` would have accepted it as a step. The bundle would have been produced and been
unusable — posting an HTTP request line as a chat prompt.

## Decision

### Replay is unsupported for non-chat surfaces, and says so
When the run drove any non-CHAT surface, no bundle and no runner are written, one warning
naming the kind and the reason goes to stderr, and the assessment completes with its normal
exit code. The report, SARIF and HAR are untouched.

This is the discipline ADR 0006 established and ADR 0017 extended: an artifact that cannot
work for the driven kind is refused explicitly rather than emitted broken. It is also the
shape `cli.py` already uses for HAR, which is skipped when there is nothing to export and
omitted from the `Wrote …` line — with the difference that this warns rather than staying
silent, because an operator who asked for a bundle must learn they did not get one.

### The guard keys on surface kind, not on target type
`_driven_kinds` resolves through `drivable_surfaces_of`, so it reports what the engine
actually drove rather than inferring it from the target's class, and returns CHAT when
nothing is bound — matching ADR 0006's rule for an unbound run. A future non-chat surface
inherits the guard without further change, and a kind with no driver is refused by ADR
0009's existing resolution rather than by a second rule here.

### No replay format is invented
Defining a REST bundle would require at least five new contracts: a format version bump, a
per-kind `target_config` schema, a second runner, a canonical-request parser exposed to a
standalone script, and indicator semantics for a detector-based probe. It would also raise a
safety question no ADR answers: `REPLAY_RUNNER` builds its target with no `Scope`, which is
consistent for chat because `--authorized` gates it, but [ADR 0012](0012-rest-surface-execution.md)
R1 holds that possession is not authorisation for REST and requires a non-empty allowlist
before any request. A standalone REST runner would either re-implement R1 or bypass a
control an ADR calls fail-closed. None of that is specified, so none of it is invented here.

## Alternatives considered
1. **Guard only the attribute read, still emit a bundle.** Rejected: produces an artifact
   whose runner cannot execute it, with a null indicator. Worse than none, because it looks
   like evidence.
2. **Emit a REST bundle and a second runner.** Rejected: five undefined contracts and an
   unresolved R1 question. Recorded above so a future ADR can take it up deliberately.
3. **Fail the run when `--replay` is passed on a REST target.** Rejected: a replay bundle is
   an optional export. Losing an entire assessment because one artifact is unavailable is
   disproportionate, and no other export behaves that way.
4. **Skip silently, as HAR does.** Rejected: HAR skips when there is nothing to export,
   which is self-evident from an empty exchange list. Here the operator explicitly requested
   an artifact that will not appear, and silence would leave them to discover it.

## Consequences
- **Positive:** a supported flag combination no longer loses the assessment. The limitation
  is stated at the moment it applies rather than discovered from a traceback.
- **Changed:** REST plus `--replay` writes no bundle or runner and emits one stderr warning,
  where it previously raised `AttributeError`.
- **Unchanged:** every chat run. `--demo`, `--harness` and `--config` produce byte-identical
  bundles and runners — the runner is asserted by SHA-256 against `v0.4.2-correctness`. The
  report, SARIF, HAR, graph identity, custody, provenance, `runtime_coverage_ratio`, battery
  size, `Finding` field order/defaults/count, discovery output, benchmark and determinism
  are all verified byte-identical.
- **Accepted:** REST assessments have no replay path at all. Reproduction remains available
  through `Finding.reproduction_steps`, which ADR 0012 R3 renders as a curl command from the
  canonical request — so a REST finding is still independently re-issuable, just not through
  the replay bundle.
- **Follow-up (not this ADR):** a replay format for non-chat surfaces, should the five
  contracts above and the R1 question be settled.
