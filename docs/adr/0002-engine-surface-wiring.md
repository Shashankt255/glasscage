# ADR 0002 — Engine surface wiring via an attribute-compatible shim

Status: Accepted · Phase 1 / Sprint 1 / PR #2 (executes the ADR 0001 follow-up)

> **Representational clause superseded by [ADR 0011](0011-multi-surface-execution.md).**
> The direct/surface *behavioural* equivalence below still holds: a single-surface driven
> run produces the same findings as a direct run. The *representational* half — identical
> graph node ids and serialization — was retired when multi-surface execution restored
> `surface_id` into Finding identity.


> **Partially superseded by [ADR 0005](0005-declared-and-governed-ownership.md).** The
> "one authoritative target" clause below — requiring the driven surface to be bound to
> the *same object* supplied to the engine — was generalised to *declared and governed
> ownership* in PR #5, so that non-chat drivers can exist. Every other decision in this
> ADR stands, and the invariant it protects is preserved, not weakened.

## Context
[ADR 0001](0001-surface-driver-foundation.md) added `glasscage/targets/` as a frozen,
unconsumed contract and deferred two follow-ups: wire `ChatDriver` into `engine.run()`
behind a shim, and migrate the `.send()` call sites.

An audit of the working tree established two facts the follow-up plan depended on:

1. The `.send()` migration surface is **24 call sites across 7 modules** (12 `probes.py`,
   7 `agent_probes.py`, 3 `recon.py`, 1 `mutation.py`, 1 `genetic.py`, plus a string
   template in `sarif.py` and the adapter itself), not the seven ADR 0001 states. Seven
   is the module count.
2. The complete set of attributes any *in-repo* caller reads off a `send()` result is
   `.ok`, `.text`, `.error`, `.trace`, `.latency_ms`. `ChatResponse.raw` is read in
   exactly one place — `_to_observation` in `targets/chat.py`. `Observation` declares all
   five with identical names and semantics.

   **Qualification (post-review).** That survey covered this repository only. The plugin
   SDK is public and a third-party probe may read `.raw`, which `Observation` did not
   have. `Observation.raw` was therefore added as an additive read-only alias for
   `response`. It is a property, not a field, so serialization and equality are
   unaffected. Parity now holds for external probes too.

## Decision
Wire the engine, and **do not migrate the call sites**.

Because `Observation` is attribute-compatible with `ChatResponse` for every attribute
actually consumed, a surface-driven `Observation` is accepted by every existing probe
unchanged. `targets/compat.py` adds `SurfaceTarget`, which presents a bound `Surface`
through `send(prompt)` and delegates every other attribute to the origin target.
`Engine` gains a trailing keyword-defaulted `surface=` parameter; when it is `None` the
pipeline is textually and behaviourally what it was.

Identity, custody and reproduction continue to read `self.target`, so `name`, `url`,
`method` and `capabilities` are sourced exactly as before and `repro.build_all` is
untouched.

**One authoritative target (post-review).** Because traffic goes to the surface while
attribution reads `self.target`, the two must be the same object. Review demonstrated
that they were not required to be: a surface bound to a different target produced 21
findings whose reproduction steps cited a host that was never probed, and would have left
`--har` and the audit chain reading the wrong object's `exchanges`. `SurfaceTarget` now
verifies the driver's `.target` is the supplied origin and raises `TargetError` before any
traffic. A driver that does not declare what it drives is refused for the same reason —
unverifiable attribution is treated as failed attribution, never as an acceptable default.

## Alternatives considered
1. **Rewrite the 24 call sites to drive surfaces directly.** Rejected: ~10× the diff for
   no functional gain, and it puts three things at risk — the documented plugin SDK
   contract (`target.send`), the `.trace` coupling in the five agentic probes, and
   `coverage_provenance.py`, which derives the published `runtime_coverage_ratio` by
   `inspect`-ing probe source for send calls.
2. **Give `SurfaceTarget` an `Observation → ChatResponse` inverse.** Rejected: nothing
   reads `.raw`, so the conversion would exist only to satisfy a type nobody checks.
3. **Put the shim in `engine.py`.** Rejected: the layering guard in
   `tests/test_targets_foundation.py` keeps the dependency direction `engine → targets`;
   the shim belongs on the targets side, importing only `.driver`/`.surface`/
   `.application`.
4. **Expose a CLI flag now.** Deferred: it would pull `cli.py`, `--har`, the audit log
   and replay bundles into the blast radius for no architectural gain. The capability is
   Python-API-only until a discovery PR gives it something to select.

## Consequences
- **Positive:** probe traffic can flow through the Surface/Driver model with a ~105-line
  production change, zero edits to probes/recon/attackers/CLI, and zero edits to
  existing tests. Rollback is a clean revert.
- **Structural typing is load-bearing:** `SurfaceTarget` performs no `isinstance` check,
  so `ReferenceAgent` (which only duck-types the target contract) drives surfaces on
  equal terms. Do not add a nominal type check.
- **Delegation preserves `hasattr`:** `stats.TrialRunner` decides whether to seed a run
  with `hasattr(target, "set_seed")`. `__getattr__` forwarding keeps that answer
  identical to the unshimmed object; a test asserts the call reaches the harness.
- **Accepted:** only `SurfaceKind.CHAT` is drivable. Anything else is refused loudly
  rather than silently assessed at the wrong surface.
- **Follow-up (not this PR):** surface discovery, non-chat drivers, CLI exposure.
