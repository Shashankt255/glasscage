# ADR 0001 — Surface/Driver foundation for multi-surface assessment

Status: Accepted · Phase 1 / Sprint 1 / PR #1

## Context
GLASSCAGE 1.0.0rc3 models a target as a single `HTTPChatTarget` (one URL, one
`response_path`, `send(prompt) -> ChatResponse`). This is why an application exposing
several endpoints can only be tested at one of them, leaving other findings
`hypothesized` rather than `demonstrated`. The approved Phase 1 roadmap generalises the
target into a multi-surface application model. The riskiest part of that change is
editing `target.py`/`engine.py`, which are referenced by six modules and underpin the
full existing test suite.

## Decision
Introduce an **additive** `glasscage/targets/` package that defines the stable
abstractions — `Surface`, `Driver`, `SurfaceKind`, `Observation`, `Action`,
`ApplicationTarget`, `AuthContext` — and adapt the existing `HTTPChatTarget` as a
`ChatSurface`/`ChatDriver` **without modifying it**. No pipeline code (`engine`,
`probes`, `recon`, `sarif`, `cli`) is rewired in this PR. `Observation`'s fields mirror
`ChatResponse` so the adapter mapping is lossless.

## Alternatives considered
1. **Refactor `target.py` and wire the engine in one PR.** Rejected: couples the
   highest-risk edit with new abstractions in a single un-reviewable change and puts the
   green-test bar at risk on first merge.
2. **Put the abstractions inside `target.py`.** Rejected: grows an already central
   module and blurs the layering the roadmap depends on.
3. **A second graph/evidence model for surfaces.** Rejected: duplicates the AAKG and
   evidence vocabulary — the exact debt the architecture forbids.

## Consequences
- **Positive:** later PRs (drivers, discoverers, engine surface-iteration) implement
  against a frozen contract; zero behavioural change now; all existing tests preserved;
  layering enforced by a source-level dependency-direction test.
- **Negative / accepted:** the package is intentionally not yet consumed by the run
  pipeline ("unused" until the wiring PR). This is deliberate and documented, not debt.
- **Follow-up (not this PR):** wire `ChatDriver` into `engine.run()` behind a shim;
  migrate the seven `.send()` call sites incrementally.
