# Changelog

All notable changes. Versions prior to 1.0.0rc1 were internal stage-build milestones
during development; the first public release candidate is **1.0.0rc1**.

## [Unreleased] — Engine surface wiring (Phase 1)
Plumbing only. No new probe, detector, graph node/edge type, attack technique, or scoring.
### Added
- `targets/compat.py`: `SurfaceTarget` presents a bound `Surface` through the `send(prompt)`
  contract and delegates every other attribute to the origin target; `chat_surface_of()`
  resolves a `Surface`/`ApplicationTarget` to the CHAT surface to drive.
- `Engine(..., surface=...)`: optional, keyword-defaulted, appended last. Routes probe,
  recon and attacker traffic through the bound surface.
- Evidence-attribution guard: a surface bound to a target other than the supplied one is
  refused with `TargetError` before any traffic, so evidence, HAR export, replay and
  reproduction steps can never cite a system that was not probed. Drivers expose the
  target they drive via an additive read-only `ChatDriver.target`.
- `Observation.raw`: additive read-only alias for `response`, preserving plugin probes
  written against `ChatResponse.raw`. A property, not a field — serialization unchanged.
- `docs/adr/0002-engine-surface-wiring.md`.
- `targets/discovery.py`: read-only surface discovery (**Experimental**). `discover_openapi`
  / `discover_mcp` / `discover` emit `SurfaceCandidate` records preserving the locator,
  HTTP method and I/O schema that `schema.ingest` discards; `ApplicationTarget` gains an
  idempotent candidate registry (`add_candidate` / `candidates_of`). Candidates are never
  bound to a Driver and no pipeline code consumes them yet — binding waits on per-surface
  attribution. Deterministic ids (`rest:<method>:<path>`, `mcp_tool:<name>`), sorted and
  deduplicated output; malformed input raises `ConfigError` and nothing is ever invented.
  `schema.py` is unmodified and its output is asserted unchanged.
- `docs/adr/0003-surface-discovery.md`.
- `Finding.surface_id` (additive, defaulted `""`): runtime findings record the id of the
  `Surface` they were observed on when a run is surface-driven. Probe-loop, tier-gated and
  `--adaptive`/`--genetic` findings are attributed; MCP-manifest (configuration review) and
  architecture (questionnaire) findings never are, because they are not observations on a
  surface. Empty on the default path. Custody, HAR and reproduction still read the supplied
  target. Graph serialization, SARIF, replay bundles and reproduction steps are unaffected.
### Added
- **Multi-surface execution** (`engine.py`, `targets/compat.py`, `aakg/build.py`):
  `Engine(target, surface=<ApplicationTarget>)` now drives **every** registered CHAT surface
  instead of only the first, in `chat_surfaces_of()` order (INV-1), with every surface's
  ownership and governance validated before any traffic. Each surface gets its own
  `ReconResult` — probes read `tool_surface`/`model_hints` while assessing and three derive
  findings entirely from recon, so a merged fingerprint would let one endpoint drive
  another's verdicts. Findings carry their producing surface's `surface_id` and cite that
  surface's target in reproduction steps. `Finding` node identity gains `surface_id`
  (`Finding:<owasp>:<probe>:<surface>:<digest>`); a direct run carries an empty component,
  so **every CLI invocation is unchanged**. `ApplicationTarget.scope`, declared by ADR 0001
  and never read, is now verified against every driven target and refuses a mismatch
  pre-traffic. An unreachable surface is skipped and named in `notes`; if none is reachable
  the run is distinguishable from a clean assessment (INV-4). Report identity is the
  application's `base_url` for an application run (discharges ADR 0005's deferral). Attacker
  budgets are `PER_SURFACE` (INV-3) with the effective total reported.
  See `docs/adr/0011-multi-surface-execution.md`.
### Fixed
- **`techniques_run` counted findings, not techniques** (`engine.py`): the graph-native
  figure reported 27 on a baseline run in which 23 distinct techniques ran and 21 probes
  were registered, because it counted graph-eligible Finding nodes. It is now a run-level
  property owned by the orchestration layer and is surface-count independent. A pre-existing
  defect on v0.1.0-phase1, independent of multi-surface, which restoring `surface_id` would
  have amplified ~N×. Every evidence-derived analysis remains graph-native.
- **AAKG Finding-node identity** (`aakg/build.py`): Finding nodes were keyed
  `f"{owasp_id}:{probe_name}"`, which is not unique — `mcp.analyze_manifest` emits one finding
  per flagged tool and `architecture.assess` one per control, so findings merged into a single
  node keeping the first label and the last status. `--demo --mcp-manifest
  samples/mcp_manifest.json` emitted a node labelled `Tool 'fetch_url' …` with status
  `vulnerable`, while `fetch_url` was assessed `inconclusive` — a fabricated per-tool verdict
  and a breach of the evidence ceiling. Independent of surface driving.
  Keys are now `Finding:<owasp_id>:<probe_name>:<subject_digest>`, where the digest is the
  first 12 hex of `sha256` over the whitespace-normalised prompt. One node per graph-eligible
  finding: 29/29 on a maximal run (was 26/29). No new node or edge type; merge policy, node
  types, edge types, `node_id`/`edge_id`, replay bundles, SARIF, `diff.py`, CLI and the
  benchmark unchanged. `surface_id` is deliberately **not** part of the identity — it is empty
  on every current run and would break the direct/surface graph equivalence guaranteed by
  ADR 0002 and re-asserted by ADRs 0004 and 0008; surface differentiation is deferred to
  multi-surface execution. See `docs/adr/0010-finding-node-identity.md`.
  **Unavoidable:** all Finding node ids change, and edge ids incident to them change with
  them. Posture (45.4/54.6) and `runtime_coverage_ratio` (0.54) are unchanged.
- `docs/adr/0010-finding-node-identity.md`.

### Added
- **Plural surface resolution** (`targets/compat.py`): `chat_surfaces_of()` returns every
  drivable CHAT surface in **registration order** (deliberately not id-sorted, unlike
  `discovery`), deduplicated first-wins. `chat_surface_of()` is now a one-line wrapper
  returning the first result, with byte-identical behaviour and identical exception types
  and messages. All refusals originate in the plural form, so the two cannot drift.
  Resolution performs no ownership validation — that remains per-surface at
  `SurfaceTarget` construction (ADR 0005). Closes Phase 1 Review risk N2 (the silent
  `surfaces_of(CHAT)[0]` selection) and gives multi-surface iteration a defined input.
- `docs/adr/0009-surface-resolution-contract.md`.
- **Driver-side chain of custody** (`targets/chat.py`): a driven `Observation` now carries
  the `request` that produced it and a `custody_hash` of `audit.sha256(request, response)`,
  reusing the same helper and argument order the engine uses for `Finding.evidence_hash`.
  Retires a field declared in ADR 0001 and never populated, closing the last
  evidence-integrity gap named in the Phase 1 Foundation Review before any non-chat driver
  exists. The driver hashes but does **not** record — `exchanges` and the audit chain stay
  with the target, so entry counts are unchanged. Transport failures carry custody;
  `Observation.failure()` does not. No model change, and no serialization, reporting, AAKG
  or CLI impact: observations are transient and never persisted.
- `docs/adr/0008-driver-side-custody.md`.
- **Action model generalisation** (`targets/driver.py`, **Experimental**): `HttpAction`
  (`method`, `path`, `query`, `headers`, `body`) and `ToolCallAction` (`name`,
  `arguments`) added as additive `Action` subclasses, giving REST/GraphQL and MCP/function
  drivers a request descriptor to implement against. `Action`, `PromptAction`,
  `Observation` and the `Driver` protocol are unchanged; `ChatDriver` is unchanged and
  still refuses a non-`PromptAction` with `Observation.failure`. Pure data records — no
  validation, no driver logic, no I/O. Nothing constructs them yet.
- `docs/adr/0007-action-model-generalisation.md`.
- **Probe surface applicability** (`probes.py`, `engine.py`): `Probe.surface_kinds`
  (default `(SurfaceKind.CHAT,)`) declares which surface kinds a probe can drive, and the
  engine refuses to run a probe against a kind it does not declare — emitting
  `NOT ASSESSABLE` rather than a meaningless verdict, exactly as it already does for an
  unmet `min_tier`. Applicability is checked before tier. All 21 built-in probes are
  prompt-shaped and inherit the CHAT default unedited, so every current run is unchanged.
  Probes that declare nothing are read as chat-applicable, preserving existing plugins.
  Prevents a whole class of invalid findings before the first non-chat driver exists.
- `docs/adr/0006-probe-surface-applicability.md`.
- **Declared and governed ownership** (`targets/compat.py`, `targets/driver.py`): the
  attribution guard generalises from object identity to declared ownership, unblocking
  future non-chat drivers. Every driver must declare the target it drives (`Driver.target`,
  additive protocol member); the driven target becomes authoritative for attribution, so
  capability tier and reproduction steps follow what was probed; and a driven target other
  than the supplied one is allowed only when governed by the same `scope`, `rate` and
  `audit` objects — otherwise the run is refused with `TargetError` before any traffic.
  Closes a scope-allowlist and rate-limiter bypass that relaxing attribution alone would
  have opened. Two engine reads (capability tier, reproduction) now use the resolved probe
  target; on the default path that is the supplied target, so behaviour is unchanged.
- `docs/adr/0005-declared-and-governed-ownership.md`; partially supersedes ADR 0002's
  "one authoritative target" clause.
- `docs/adr/0004-attribution-before-binding.md`: records the sequencing decision —
  attribution precedes binding, which cannot be built while `ChatDriver` is the only driver
  and discovery emits no CHAT candidates.
- `--discover SPEC` (**Experimental**): standalone CLI mode that enumerates the drivable
  surface inventory from an OpenAPI document or MCP manifest, prints an ASCII table and
  writes `<out>_surfaces.md` / `<out>_surfaces.json`. Constructs no target, sends no
  probe, produces no report, and binds nothing. Backed by additive
  `discovery.to_markdown()` / `discovery.to_json()` renderers, following the renderer
  convention already used by `benchmark`, `adapter_validation`, `orchestrator` and
  `validation`. This gives surface discovery its first user-facing consumer.
### Changed
- ADR 0001's "seven `.send()` call sites" corrected to 24 call sites across 7 modules.
### Unchanged (by design)
- Probes, agent probes, recon, mutation, genetic, CLI, AAKG, reporting, scoring, and every
  existing test. No `.send()` call site was migrated — `Observation` and `ChatResponse`
  agree on every field any caller reads, so probes needed no change.
- `Engine(target).run()` without `surface=` is behaviourally identical; identity, custody
  and reproduction still read the target.
### Tests
- 406 passing (+201). Multi-surface (+38): iteration and registration order, per-surface
  attribution, graph distinctness, recon isolation, per-surface reproduction,
  validate-all-before-traffic, `ApplicationTarget.scope` verification, failure and total
  failure, determinism, backward compatibility, report identity, INV-2 severity invariance,
  surface-count-independent `techniques_run`, and `PER_SURFACE` budget accounting.
  Ten existing tests changed as authorised by ADR 0011 (eight superseded guarantees, two
  identity updates); no other existing test was modified.
- Finding identity (+18): one node per eligible finding on four run
  configurations, both documented collisions eliminated with per-finding status restored,
  `surface_id` excluded, direct/surface graph equivalence, determinism across repeats/seeds/
  configurations, and no unredacted content in node ids.
- Surface resolution (+14): plural resolution, registration ordering
  proven not id-sorted, first-wins dedup, singular equivalence, verbatim message parity
  across both forms, and resolution/ownership separation.
- Driver custody (+12): population and hash correctness, transport
  failures vs `Observation.failure`, determinism, no double-recording (audit entries and
  `exchanges` unchanged, chain still verifies), and `evidence_hash`/AAKG non-perturbation.
- Action model (+13): construction and defaults, per-instance mutable
  defaults, the frozen contract's field sets unchanged, ChatDriver's existing rejection of
  non-prompt actions, and deterministic equality/repr.
- Probe applicability (+14): declared default, gating without
  invocation or traffic, applicability-before-tier ordering, plugin backward
  compatibility, and unchanged CHAT-path behaviour.
- Declared/governed ownership (+15, 2 updated): declaration required,
  governance verified per control, attribution follows the driven target, refusals typed
  and pre-traffic. The two updated tests asserted ADR 0002's superseded identity rule.
- Surface attribution (+12): runtime tagging including tier-gated and
  attacker findings, config-review and questionnaire findings left untagged, legacy
  invariance, serialization, and graph/SARIF/reproduction non-perturbation.
- Surface inventory (+14): renderer shape and purity, per-kind locator
  rendering, ASCII-only output, honest empty rendering, and the standalone CLI mode
  (no target, no assessment, byte-identical artifacts across runs).
- Discovery (+21): OpenAPI/MCP enumeration, deterministic and sorted
  ids, duplicate collapse, empty-vs-malformed handling, candidate registry, no-network and
  never-bound guarantees, and `schema.ingest` non-regression.
- Surface wiring (+30): positive routing verification via a counting driver (traffic through
  `Driver.drive` equals traffic reaching the target), report/AAKG/summary equivalence
  between the driven and direct paths, `set_seed` and capability-tier forwarding,
  structural typing, adaptive and genetic paths, legacy invariance, evidence-attribution
  refusal, plugin `.raw` compatibility, and typed refusal of unsupported inputs.

### Added
- **REST surface execution** (`targets/rest.py`, `probes.py`, `recon.py`, `repro.py`,
  `coverage_provenance.py`): the first non-chat surface driven end to end. `RestTarget` /
  `RestDriver` consume `HttpAction` (ADR 0007, previously declared with no consumer), attach
  custody to every observation (ADR 0008) and compose the absolute URL once so the scope
  check, the issued request, the custody hash and the reproduction command cannot disagree
  (R8). A REST target **requires a non-empty `Scope` and is refused without one, before any
  socket opens** (R1): `audit.Scope.check()` defers to `--authorized`, a gate REST never
  crosses, so possession of a target is not authorisation. Chat keeps its optional scope
  because `--authorized` does gate it. One canonical request serialization serves custody
  hashing, Finding identity and reproduction (R2), with every ordering total.
  `SurfaceTarget.drive(action)` is the documented contract for non-chat probes (R4);
  `send(prompt)` remains the CHAT contract, unchanged. The drivable set widens from `{CHAT}`
  to `{CHAT, REST}`; `chat_surfaces_of` is retained as an unchanged-signature alias.
  `RestResponseDisclosureProbe` (LLM02) is **registered and part of the default battery**,
  reusing `SECRET_PATTERNS` so the verdict rule is identical across transports, and driving
  the surface's own declared locator rather than guessing paths. `run_recon` dispatches on
  surface kind — a chat prompt reaches a REST endpoint as a refused `PromptAction`, so a
  prompt-only recon would mark every REST surface unreachable and skip it; chat concepts
  (`model_hints`, `guardrail_signals`, `tool_surface`, `refusal_style`) stay empty for REST
  because that is the honest answer for the kind. Driving a surface with an Action counts as
  runtime evidence in `coverage_provenance` exactly as sending a prompt does.
  See `docs/adr/0012-rest-surface-execution.md`.
  **Unavoidable:** because the probe declares `(REST,)` and a default run is CHAT, every chat
  run now emits one additional NOT_ASSESSABLE finding and `not_assessable_count` rises by
  one. Gating a registered probe honestly is preferred to a battery that silently omits what
  it cannot assess and reports coverage it has not earned.
  **Unchanged:** the benchmark (byte-identical corpus report), `runtime_coverage_ratio`
  (0.54), replay bundles, SARIF, chat findings including `evidence_hash` and reproduction
  steps, custody, the graph identity scheme and determinism — verified by comparison against
  the pre-PR tree, not by assertion.
- `docs/adr/0012-rest-surface-execution.md`.
### Fixed
- **REST reproduction did not reproduce the request that was issued** (`repro.py`):
  `_curl_from_canonical` split the canonical request on the first `\n\n`, but an empty header
  block still occupies a line, so a header-less request serializes its separator as `\n\n\n`.
  The split stopped one line early and handed the separator's own newline to the body: a
  bodyless GET rendered as `--data '<newline>'` and a real body gained a leading newline —
  contradicting R3, which requires reproduction to equal what was sent. The REST probe sends
  no headers, so this fired on every REST finding. Now split positionally against the
  producer's grammar (`_split_canonical`). Chat reproduction is untouched.
### Tests
- 464 passing (+58). REST driver and contract (+30, PR #12 Commit 1): `HttpAction`
  consumption, fail-closed scope, canonical serialization and custody determinism, the
  `drive` contract, declared ownership and governance, widened resolution with INV-1 ordering
  preserved, and the alias contract. REST probe, recon, reproduction and provenance (+32):
  probe declaration and registration, locator-driven requests, verdict parity with the shared
  detector, transport and HTTP errors reported as errors rather than clean passes, canonical
  prompts giving distinct endpoints distinct Finding identity, recon reachability without a
  chat prompt with chat concepts honestly empty, reproduction regressions covering the defect
  above, and provenance counting a driven probe as runtime.
  Three existing tests were replaced as authorised: `test_every_registered_probe_is_chat_`
  `applicable`, `test_default_run_has_no_surface_gated_finding` and
  `test_chat_surface_driven_run_is_not_gated` encoded invariants that are false by
  construction once a non-chat probe is registered. No other existing test was modified.

### Added
- **Request material at the REST transport boundary** (`targets/rest.py`,
  `targets/compat.py`, `targets/application.py`): `ApplicationTarget.auth`, declared by
  ADR 0001 and never read, is now consumed. `RestTarget` accepts an `AuthContext` exactly as
  it accepts `scope`/`rate`/`audit`, and `RestDriver` merges its headers into the outbound
  request at the one point `RestTarget.headers` is already merged. `AuthContext` is
  classified as **request material, not an operational control**: ADR 0011's "verify, never
  propagate" governs objects that *enforce* something (`compat._CONTROLS` — `scope`, `rate`,
  `audit`), while auth is material that is *sent*, so `auth` is deliberately not added to
  that tuple. Because `canonical_request` is built from the `Action` alone, a credential
  supplied this way never reaches the canonical form — and therefore never reaches custody,
  Finding identity, reproduction, `exchanges`, HAR or the audit chain, all of which are
  computed over it. Precedence is `{**auth, **target.headers, **action.headers}`, so an
  explicit header always wins. A driven target not carrying the supplied target's
  `AuthContext` is refused with `TargetError` before any traffic — verification *in addition
  to* consumption, never instead of it. **CHAT is not extended**: `HTTPChatTarget` keeps
  `config["headers"]`, and a test asserts it has no `auth` attribute so the boundary cannot
  erode silently. See `docs/adr/0013-request-material-at-the-transport-boundary.md`.
  **Unchanged:** the default path is byte-identical to `v0.3.1-rest-runtime` — benchmark,
  `runtime_coverage_ratio` (0.54), replay, SARIF, chat findings including `evidence_hash`,
  custody, graph identity and determinism — verified by tree comparison, not assertion. No
  existing test required modification.
- `docs/adr/0013-request-material-at-the-transport-boundary.md`.
### Fixed
- **Credentials disclosed in cleartext through `repr`** (`targets/application.py`):
  `AuthContext` and `ApplicationTarget` are dataclasses with a generated `repr`, which
  renders every field. Interpolating an application target into a log line, an f-string or
  an exception message emitted the bearer token and session cookie verbatim. Not recoverable
  by redaction either — `redaction` matches `SECRET_PATTERNS`, which describes API-key and
  password shapes and does not match a bearer token. The credential-bearing fields are now
  excluded from the generated `repr`; `scheme` is retained because it names the mechanism
  without disclosing material. Pre-existing on `v0.3.1-rest-runtime` and independent of the
  feature work above; the regression test fails against that baseline.
### Tests
- 503 passing (+37). REST transport authentication: inert default and canonical-form
  invariance, the credential reaching the outbound headers, one negative assertion per
  prohibited sink (canonical request, `Observation.request`, custody, Finding identity,
  reports, SARIF, replay, HAR, `exchanges`, audit log, reproduction steps, exception
  messages), header precedence in both directions, `_CONTROLS` and CHAT boundaries,
  determinism with and without credentials, `repr` safety, absence from issued and audited
  URLs, parity refusal pre-traffic, and authenticated recon. No existing test was modified.

## [1.0.0rc3] — Attack Narratives & Assessment Story
Reporting layer only. No new analysis, graph node types, attack techniques, or scoring.
### Added
- `aakg/narrative.py`: NarrativeModel + 8 strategies (filters over existing paths), strategy
  dedup, full per-transition citation (node ids, edge id, evidence ids, confidence, state).
- `aakg/story.py`: 13-section Assessment Story, each section evidence-classified.
- `aakg/views.py`: executive / security / developer / incident_response / compliance views
  over the same models; `--views` CLI flag writes `<out>_view_<audience>.md`.
- Narratives + story integrated into markdown, HTML, JSON, and the executive summary.
- `docs/NARRATIVES.md` (incl. honest limitations) and `docs/examples/` before/after reports.
### Changed
- Markdown "Attack Paths" section condensed to an index table (prose now lives in the
  narratives) to avoid duplicating the same information twice.
- `report.write_json` / `report.to_html` accept optional `narratives`/`story` (omitting them
  reproduces the previous output exactly).
### Unchanged (by design)
- SARIF output and replay bundles.
### Tests
- 189 passing (+44), including anti-hallucination guarantees: every cited node/edge must
  exist in the graph, states must match graph edges verbatim, no path may be invented, and
  hostile model text must be HTML-escaped.

## [1.0.0rc1] — Release Candidate hardening
Engineering quality only; no new security capabilities, node types, or graph features.
### Added
- Typed error hierarchy (`errors.py`), structured logging (`logging_setup.py`, JSON
  option), configuration validation (`config.py`), `--log-level/--log-json` flags.
- Formal Plugin SDK (`PLUGIN_API_VERSION`, version gating, contract validation) + example.
- `python -m glasscage`; `py.typed`; richer `pyproject.toml` (extras, classifiers, URLs).
- Developer CI (`.github/workflows/ci.yml`), `Makefile`, profiling + perf tools.
- Fuzz tests, stdlib property-based tests, hardening tests (config/errors/logging/plugin/cache).
- Developer docs, Plugin SDK doc, graph-model reference, auto-generated API docs (pydoc).
- Graph analysis cache (paths/trust/blast memoized; invalidated on mutation; ~56x on repeat).
### Changed
- Target construction now validates config and raises `ConfigError` with clear messages.
### Removed
- Dead modules `validation_report.py`, `build_corpus.py`; dead `--paper` CLI branch;
  unused imports across the codebase.
### Tests
- 125 passing (unit/integration/fuzz/property/hardening), zero regressions.

## [1.4.0] — Stage E5: single source of truth
Posture, coverage, reporting, remediation migrated to read the AAKG directly.

## [1.3.0] — Stage E (E1–E4): AI Attack Knowledge Graph
Property-graph engine, attack-path engine, trust-boundary engine, blast-radius sim.

## [1.2.0] — Stage D: external integration & validation
garak/PyRIT/Promptfoo/DeepTeam/FuzzyAI normalization adapters; 109-case corpus; Wilson
CIs; cross-framework validation; paper report.

## [1.1.0] — Stages A–C: abstraction, statistics, validation
Target Abstraction Layer (tiers L0–L3), NOT ASSESSABLE, statistical engine, benchmark,
reference agent harness.

## [1.0.0] — platform upgrade
Exploit chains, genetic engine, agent probes, trust boundaries, posture, SARIF/replay.

## [0.5.0] — initial hardened prototype
Probes, recon, CVSS-style scoring, interactive report, evidence, audit log.
