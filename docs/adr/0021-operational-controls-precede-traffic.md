# ADR 0021 — Operational controls precede traffic

Status: Accepted · Phase 3 / PR #22

Concerns the wiring of the controls defined in [ADR 0012](0012-rest-surface-execution.md)
(scope), [ADR 0019](0019-audit-chain-integrity.md) and
[ADR 0020](0020-audit-log-append-semantics.md) (custody). Supersedes nothing; no control's
semantics change.

## Context
`Scope`, `RateLimiter` and `AuditLog` are attached to the target by `cli.py`, and each is
enforced only when present — `HTTPChatTarget.send()` reads `if self.scope is not None`,
`if self.rate is not None`, and `_record()` writes the chain only `if self.audit is not
None`. All three default to `None` at construction. **Unwired therefore means unenforced,
silently.**

`main()` attached them at one point, below the branches for `--orchestrate` and
`--validate`. Both of those branches construct the target, build an `Engine` over it
(`adapters/native.py` → `Engine(target)`), drive it, and `return 0` — before the wiring
was reached. On exactly the two paths that send traffic, none of the three controls
existed.

Measured on `v0.4.5-audit-append` against a local counting server, with `--scope` naming a
host other than the target's:

```
normal assessment       0 requests   PermissionError (refused, correct)
--orchestrate native   21 requests   exit 0
--validate             63 requests   exit 0
```

With `--rate 0.5` (one request per two seconds) and 21 requests: the normal path took
40.05s; `--orchestrate` took 0.06s. With `--audit-log` set, neither path created the file.

The allowlist is what stands between an authorised engagement and a host the operator
excluded. `--authorized` still gated both paths, so this was never an authorisation
bypass; it was a **scope-confinement bypass**, with rate limiting and chain of custody
lost alongside it, reported as success.

That the audit log was absent on two paths while PRs #19–#21 hardened the integrity of
that same log is the sharper point: those PRs secured a file that, on these paths, was
never opened.

## Decision

### 1. The controls are attached immediately after the target is constructed
Not at the point of use, and not at the top of `main()` — immediately after target
selection completes, which is the first moment a target exists and the last moment before
any branch can drive it.

### 2. Ordering only
No enforcement point moves. No error type changes. No exit code changes. An out-of-scope
host still raises `PermissionError` from `Scope.check()` inside `send()`, propagating
exactly as it already did on the normal assessment path. A tampered or legacy
`--audit-log` still raises `ConfigError` from `AuditLog.__init__` under ADR 0020, which
`cli.py`'s existing handler renders as `error: …` and exit 2. `--orchestrate` and
`--validate` now behave as the normal assessment path always did.

### 3. The wiring does not move above target construction
Paths that never build a target — `--arch-template`, `--discover`, `--benchmark`,
`--diff`, `--validate-adapters`, and MCP-manifest-only mode — return before it and are
unaffected. In particular a custody log is not opened for a run that cannot happen: the
ADR 0020 refusal must not fire on an invocation that was never going to send a request.

### 4. The ordering is pinned by test, not only by its effects
The defect was positional, and a purely behavioural test suite did not catch it: the
existing tests exercise `orchestrator.orchestrate(target, …)` directly, below `main()`,
where the wiring is not in play. Tests therefore assert both the observable behaviour
(server-side request counts, custody chains, elapsed time) and the source ordering
relative to each driving branch.

## Security analysis
- **What this fixes:** `--scope`, `--rate` and `--audit-log` are honoured on every path
  that sends a request. Traffic to a host outside the allowlist is refused before the
  first request rather than after the last.
- **What it does not change:** every control's semantics, error type and exit code. Scope
  still enforces host-level confinement only; ADR 0019 §8's truncation limitation is
  untouched; nothing about redaction, evidence or reporting moves.
- **Residual, unchanged:** an out-of-scope refusal surfaces as an uncaught
  `PermissionError` rather than the `GlasscageError` handler's `error: …`/exit 2. That is
  pre-existing behaviour on the normal assessment path and is deliberately left alone —
  converting it is an error-contract change, not this ADR's ordering fix.

## Rejected alternatives
1. **Re-attach the controls inside each branch.** Rejected: duplicates the wiring three
   ways and leaves the next branch to be added with the same defect.
2. **Enforce inside `Scope`/`RateLimiter`/`AuditLog` by making them non-optional on the
   target.** Rejected: changes the enforcement contract in `target.py`, `rest.py` and
   `refagent.py`, far beyond an ordering defect, and would alter behaviour for library
   callers who construct targets directly.
3. **Move the wiring to the top of `main()`.** Rejected: no target exists there, and it
   would open a custody log for invocations that never send a request (§3).
4. **Fail closed when a driving branch runs with unwired controls.** Rejected: invents a
   new refusal contract to detect a condition that correct ordering makes unreachable.

## Consequences
- **Positive:** the documented behaviour of `--scope`, `--rate` and `--audit-log` is now
  the actual behaviour on every path that drives a target.
- **Behavioural change, intended:** `--orchestrate` and `--validate` now refuse an
  out-of-scope host, throttle to `--rate`, and write and verify `--audit-log`. An
  invocation that previously "succeeded" by testing an excluded host now correctly stops.
- **Unchanged:** every control's semantics, `audit.sha256` and the entry format, findings,
  graph identity, SARIF, replay, provenance, reporting, benchmark determinism, and the
  behaviour of every path that returns before a target is built.
- **No migration.** No format, schema or API change.
- **Follow-up (not this ADR):** MCP-manifest-only mode silently discards `--rest-config`
  and `--harness`, because its guard predates both surfaces. That is a CLI precedence
  contract question, recorded but deliberately not decided here.
