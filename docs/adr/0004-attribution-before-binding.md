# ADR 0004 — Attribution before binding

Status: Accepted · Phase 1 / Sprint 2 / PR #4

## Context
[ADR 0003](0003-surface-discovery.md) leaves three Phase 1 items in order: **per-surface
attribution**, then **binding** (promoting a discovered `SurfaceCandidate` to a driven
`Surface`), then **non-chat drivers**. Two of them were re-evaluated from first
principles before choosing this PR.

**Binding cannot be built today.** `Surface` requires a bound `Driver`; the only driver in
the tree is `ChatDriver`; and `discovery` emits only `REST` and `MCP_TOOL` candidates,
never `CHAT`. The three ways to close that gap are each unacceptable now:

1. Write REST/MCP drivers — that is the non-chat-driver milestone, blocked because
   `PromptAction` is the only `Action` kind and every probe is prompt-shaped, and it is
   two architectural concepts in one change.
2. Bind a placeholder driver — invents a `Surface` that cannot be driven, contradicting
   the abstraction's own definition, and guaranteed to be deleted when real drivers land.
3. Ship a promotion helper nothing can call — a fourth consecutive unconsumed abstraction
   in `targets/`.

**Binding first would also be unsafe.** `compat.chat_surface_of` selects
`surfaces_of(SurfaceKind.CHAT)[0]` — the *first registered* CHAT surface. A promotion API
writes into that same list, so it could silently change which surface the engine drives.
And promoted surfaces that fail `SurfaceTarget`'s identity check would create pressure to
relax the [ADR 0002](0002-engine-surface-wiring.md) attribution guard *before* anything
exists to replace it — reintroducing the misattribution failure that guard was written
for.

## Decision
Do attribution first, and start with the smallest reviewable piece of it: **a finding
records the surface it was observed on.** `Finding` gains an additive `surface_id`,
populated by the engine for findings produced by target interaction when a run is
surface-driven.

**Honest framing.** This PR does *not* remove a blocker — neither candidate did; both are
preparation. It is the strict prerequisite: the one-authoritative-target guard cannot
relax until findings can carry surface provenance. Unlike binding, it also delivers
something observable on merge — a surface-driven run was previously indistinguishable
from a direct run in every artifact, which made the driven path unauditable.

## Scope of attribution in this PR
- **Attributed:** probe-loop findings, tier-gated `NOT_ASSESSABLE` findings, and
  `--adaptive` / `--genetic` attacker findings.
- **Never attributed:** MCP-manifest findings (configuration review) and architecture
  answers (questionnaire). They are not observations on a surface, and tagging them would
  fabricate provenance. This mirrors the runtime / config_review / questionnaire split
  `coverage_provenance.py` already draws. The tagging pass is placed before those findings
  are appended, which is the mechanism that enforces it.
- **Deliberately unchanged:** custody, HAR export and reproduction steps still read the
  single supplied target. Moving those onto the driven surface is a separate concept and a
  separate PR.

Tagging tier-gated findings is a judgment call: they were never sent, but they describe
whether *that surface* is assessable, so they carry the id. Recorded here so it is a
reviewed decision rather than an accident.

## Alternatives considered
1. **Promote candidates to Surfaces first (the binding milestone).** Rejected for the
   reasons above.
2. **Model attribution as an AAKG node or edge.** Rejected: the architecture is frozen
   against new node/edge types, and a flat provenance field sits naturally beside the
   existing `assessed_tier`, `source_framework` and `provenance` fields on `Finding`.
3. **Attribute on `Observation` instead of `Finding`.** Rejected: `Observation` is
   transient and discarded after a probe returns; provenance must survive into the report.
4. **Do full attribution (custody + HAR + repro) in one PR.** Rejected: several concepts,
   and it would reach `repro.py`, `audit.py` and `cli.py` simultaneously.

## Consequences
- **Positive:** the driven path is auditable for the first time; the join key every later
  consumer needs (per-surface coverage, report grouping, graph attribution) now exists;
  ~8 production LOC and a clean revert.
- **Verified non-perturbing:** `aakg/build.py`, `sarif.py` and `repro.py` read named
  `Finding` fields — none uses `asdict`, `vars()` or `__dataclass_fields__` — so graph
  serialization, SARIF, replay bundles and reproduction steps are unaffected. Asserted by
  test.
- **Accepted:** `Finding.to_dict()` and the JSON report gain one key. Additive and empty
  on the default path.
- **Accepted debt, not addressed here:** `Finding` already declares six fields twice
  (`source_framework`, `source_rule_id`, `cwe_id`, `capec_id`, `nist_id`, `raw_output`).
  Pre-existing; tidying it is unrelated refactoring and belongs in its own PR.
- **Follow-up (not this PR):** generalise the one-authoritative-target guard to
  per-surface attribution, then binding, then non-chat drivers.
