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

### Fixed
- **Regression diffs merged distinct findings and could report NO CHANGE on a regression**
  (`diff.py`): the comparison key was `probe_name::owasp_id`, which is not unique —
  `mcp.analyze_manifest` emits one finding per flagged tool and `architecture.assess` one
  per control. The dict comprehensions in `diff_reports` therefore discarded all but the
  last finding per key, so a newly-vulnerable finding sharing a probe/OWASP pair with an
  existing one never reached `introduced` and the verdict read `NO CHANGE`. Reproduced on
  `v0.3.2-rest-auth`: the shipped MCP sample manifest produced two `mcp-analyzer::MCP07`
  findings collapsing to one. ADR 0010 fixed the identical collapse in the graph — calling
  it "a fabricated per-tool verdict and a breach of the evidence ceiling" — and recorded
  this layer as follow-up; this is that follow-up. The key is now the Finding identity of
  ADR 0010 as extended by ADR 0011: `owasp_id:probe_name:surface_id:subject_digest(prompt)`.
  The digest is composed in `diff.py` rather than imported from `aakg.build`, because ADR
  0010 records the graph and the report diff as deliberately different layers; a test
  asserts both produce the same digest for the same prompt.
  **Unavoidable:** diff keys change, so a stored baseline report from before this change is
  not comparable against one produced after it. Re-generate baselines.
  **Note:** a diff between a direct run and a surface-driven run now separates findings by
  `surface_id`, so they compare as all-introduced plus all-fixed. That reflects two
  different assessment configurations rather than a regression.
- **`Finding` declared six fields twice** (`models.py`): `source_framework`,
  `source_rule_id`, `cwe_id`, `capec_id`, `nist_id` and `raw_output` appeared in both the
  original block and the Stage D block. A dataclass collapses a repeated annotation into
  one field that keeps its **first position** and takes its **last default**, so
  `source_framework`'s first default `"glasscage"` was unreachable — the effective value
  was `"glasscage-native"` — and editing the first declaration had no effect. Recorded as
  owed debt by ADR 0004 ("belongs in its own PR"); resolved here because populating
  `source_rule_id` required editing one of the shadowed declarations. Consolidated onto the
  first declaration carrying Stage D's values, so field order, field count (41) and every
  effective default are unchanged.
### Added
- **`source_rule_id` populated for subject-per-finding probes** (`mcp.py`,
  `architecture.py`): the tool name and the control id respectively. ADR 0010 recorded that
  the subject is carried by `prompt` "by convention, not contract" and named populating this
  field as the durable fix. **This PR introduces no production reader for it**: the
  comparison key above deliberately excludes it so that diff identity matches graph
  identity exactly, and the graph derives its subject from `prompt`. That state is
  intentional and recorded here rather than left to be re-discovered as a defect.
### Tests
- 525 passing (+22). Diff identity: the collision reproduced and eliminated for both
  subject-per-finding probes, a regression on a second subject now reported, key components
  matching `aakg.build._finding_key`, digest parity across whitespace variants, `surface_id`
  separation and absent-key coercion, `source_rule_id` excluded from the key, subject
  carriage per tool and control, and a `Finding` shape freeze asserting no duplicate
  declaration in source plus unchanged field order, count and effective defaults. Guards
  that pass against the pre-fix code were mutation-tested against five wrong keys. No
  existing test was modified.

### Added
- **Surface binding** (`targets/binding.py`): `bind_candidate(candidate, target)` promotes a
  discovered `SurfaceCandidate` to a bound `Surface`. `discovery` has emitted candidates
  since ADR 0003 and nothing consumed them — the module recorded its own precondition,
  *"binding cannot happen until per-surface attribution exists"*, which ADR 0004/0011
  cleared, and ADR 0012 then supplied a non-chat driver. Binding is **pure resolution**: no
  I/O, no target construction, no mutation of the candidate or the target. The caller
  supplies the target, because ADR 0002 requires a bound surface to be bound to the target
  supplied to the engine and ADR 0011 rejected propagating an application's controls onto a
  target the engine does not own. Ownership, governance and ADR 0012's fail-closed scope
  check stay at `SurfaceTarget` construction, so binding raises `ConfigError` and never
  `TargetError` — a candidate bound to a scopeless target binds and is refused later, at the
  boundary that owns that refusal. Only a kind with a driver can be bound; **REST is the
  only bindable kind**, because `discovery` emits only REST and MCP_TOOL candidates and
  MCP_TOOL has no driver. The bound surface keeps the candidate's id, so a finding's
  `surface_id` traces back to the discovered operation, and the candidate's `locator` and
  `io_schema` are carried through unchanged rather than rebuilt. Promotion is a free
  function rather than an `ApplicationTarget` method: the container is pure data whose every
  method stores or queries, and neither existing surface constructor is a method either, so
  the operator idiom is unchanged — `app.add_surface(bind_candidate(c, target))` has the
  same shape as `app.add_surface(rest_surface_from_target(...))`.
  See `docs/adr/0014-surface-binding.md`.
  **Unchanged:** `discovery`'s JSON and markdown output byte-identical; graph identity,
  custody, SARIF, replay, benchmark, `runtime_coverage_ratio`, CHAT and REST behaviour and
  determinism all verified against `v0.3.3-diff-identity` by tree comparison rather than
  assertion. No existing module was modified beyond one export; no existing test was
  modified.
- `docs/adr/0014-surface-binding.md`.
### Tests
- 551 passing (+26). Surface binding: discovered-candidate round trip with id, locator and
  `io_schema` preserved; the bound surface resolving as drivable and driving its declared
  operation; registration through the existing `add_surface` idiom; purity (no request
  issued, no target constructed, neither candidate nor target mutated); refusal by name for
  every driverless kind and for a malformed REST locator; `ConfigError` never `TargetError`,
  with scope and governance refusals still raised downstream at `SurfaceTarget`;
  determinism; and a freeze on `discovery`'s output plus on the fact that it emits no CHAT
  candidate. Guards were mutation-tested against six wrong binders, since a new module's
  baseline run fails only on import and proves nothing.

### Added
- **CLI exposure of surface-driven assessment** (`cli.py`): `--rest-config FILE` plus
  `--rest-spec SPEC` discover an OpenAPI document's operations, bind them to a `RestTarget`
  and assess every one. ADR 0002 deferred this *"until a discovery PR gives it something to
  select"*; discovery landed in ADR 0003 and binding in ADR 0014, so the REST programme
  built across PRs #12–#15 — driver, probe, transport-boundary auth, binding — is reachable
  by an operator for the first time. `--authorized` gates the REST path exactly as it gates
  `--config`, and **the CLI adds no refusal logic of its own**: ADR 0012 R1's non-empty
  `Scope` is enforced where it already lives, by `require_scope` at `SurfaceTarget`
  construction, so there is one enforcement point rather than two that could drift. Surfaces
  are bound after `--scope`/`--rate`/`--audit-log` are attached, and the same target object
  is passed as both the engine's target and the bound driver's, so ADR 0005's governance
  check compares an object with itself and nothing is propagated.
  **`--discover` is untouched** — not reused, not overloaded, unchanged in every
  combination. It remains an inventory command that drives nothing, which is why a dedicated
  `--rest-spec` exists: overloading one flag would have made `discovery`'s documented
  read-only guarantee conditional on which other flags were present.
  See `docs/adr/0015-cli-surface-exposure.md`.
  **Expect a mostly NOT ASSESSABLE report.** ADR 0006 gates every chat probe on a REST
  surface and ADR 0012 registered the REST probe into the default battery, so a
  two-operation spec yields 42 gated findings and 2 assessed ones. That is the honest
  reading of a battery that is 21/22 chat-shaped, shown rather than hidden.
  **Accepted, unfixed:** `--discover` alongside `--config` still silently ignores
  `--config`, exactly as before; fixing it would modify `--discover`.
  **Unchanged:** every existing invocation — `--demo`, `--harness`, `--config`,
  `--benchmark`, `--diff`, `--mcp-manifest`, and `--discover` in all combinations — plus the
  benchmark, `runtime_coverage_ratio`, replay, SARIF, custody, graph identity, `discovery`
  output and determinism, verified against `v0.3.4-surface-binding` by tree comparison. No
  existing test was modified.
- `docs/adr/0015-cli-surface-exposure.md`.
### Changed
- `docs/adr/0012-rest-surface-execution.md` carries a banner marking its
  **authorisation-asymmetry rationale** superseded by ADR 0015. R1's requirement is
  unchanged — REST still requires a non-empty `Scope` — but the reason given for it, that
  REST has no CLI path, is no longer true. ADR 0015 re-grounds the asymmetry on ADR 0014's
  accepted limitation that binding does not verify a target's host against the discovered
  document, which is an exposure chat does not have.
### Tests
- 572 passing (+21). CLI surface exposure: end-to-end REST assessment with every discovered
  operation driven and attributed; a secret in a REST response reported; ADR 0012 R1
  preserved with the refusal raised before any request; `--authorized` gating and no report
  written on refusal; `--discover` byte-identical with and without `--rest-spec` present,
  still returning without assessing alongside `--config` and `--rest-config`, and still
  writing its inventory files; existing invocations unaffected; the NOT ASSESSABLE ratio
  asserted as a recorded expectation; and determinism across repeated runs.

### Fixed
- **`coverage_provenance` reported assessed categories as untested**
  (`coverage_provenance.py`): provenance was derived from `probes.REGISTRY` alone, but
  `mcp.analyze_manifest` is not a registered probe — the engine calls it directly — so
  MCP03 and MCP07 fell through to `not_tested` while being assessed. Measured on
  `v0.4.0-cli-surface`: `config_review_only` was `[]` and `not_tested` was
  `['LLM04','MCP03','MCP07','MULTIMODAL']`, while the analyzer emitted
  `{'MCP07': 2, 'MCP03': 1}` on the shipped sample manifest. The `config_review` bucket the
  module documents (*"e.g. MCP"*) was structurally unreachable: across 22 registered probes,
  19 classified runtime and 3 questionnaire, none config_review, because no registered probe
  carries an MCP `owasp_id`. A module whose stated purpose is *"an honest runtime coverage
  figure"* was under-reporting. Provenance now derives from the registry **plus** a declared
  set of categories assessed by non-probe assessors; strength order is unchanged, so a
  runtime category is never demoted by a declaration.
  See `docs/adr/0016-non-probe-assessor-provenance.md`.
  **Reporting-layer only, by decision:** MCP is **not** registered as a probe, the battery
  stays at 22, no gated finding is introduced, and **`runtime_coverage_ratio` stays 0.54** —
  arithmetically, not by adjustment, since the ratio is `runtime / universe = 7/13` and
  neither term moves.
  **Visible change:** the report's `coverage_provenance` field moves `MCP03` and `MCP07`
  from `not_tested` to `config_review_only`; `not_tested` now holds only `LLM04` and
  `MULTIMODAL`, which genuinely have no assessor.
  **Accepted:** `architecture.assess` is also a non-probe assessor and is deliberately not
  declared — every category it covers is already runtime-tested or questionnaire-covered, so
  declaring it changes no bucket (simulated and confirmed identical). The gap is latent and
  recorded in ADR 0016.
  **Unchanged:** `runtime_tested`, `universe` (13), battery composition, gated-finding
  counts, graph identity, custody, SARIF, replay, benchmark, `discovery` output and
  determinism, verified against `v0.4.0-cli-surface` by tree comparison. No existing test was
  modified.
- `docs/adr/0016-non-probe-assessor-provenance.md`.
### Tests
- 589 passing (+17). Non-probe assessor provenance: MCP03/MCP07 classified `config_review`
  and removed from `not_tested`; the frozen invariants asserted explicitly
  (`runtime_coverage_ratio == 0.54`, the exact `runtime_tested` set, `universe == 13`,
  battery of 22, unchanged gated-finding count, buckets partitioning the universe); MCP still
  absent from the probe registry; two-direction anti-drift checks against both what
  `mcp.analyze_manifest` emits and the `MCP\d\d` literals in `mcp.py`; non-canonical `MCP00`
  excluded from every bucket; and precedence, so a runtime category is not demoted and
  config_review outranks questionnaire. Guards were mutation-tested against four wrong
  declarations — omitting a category, declaring a non-canonical one, classifying MCP as
  runtime, and declaring nothing — all caught.

### Fixed
- **A REST assessment crashed when `--adaptive` or `--genetic` was passed** (`engine.py`):
  ADR 0006 gates every registered probe on the driven surface kind, but the adaptive and
  genetic attackers were invoked unconditionally from the same per-surface loop. Both are
  prompt-shaped — each drives through `target.send()` — so on a REST surface the
  `PromptAction` was refused, a finding was still produced carrying a chat-shaped prompt,
  and `repro.build_all` (outside any `try`) rendered it as a chat request, reading
  `target.body_template` off a `RestTarget` that has no such attribute. Measured on
  `v0.4.1-coverage-provenance`: `AttributeError: 'RestTarget' object has no attribute
  'body_template'` for both flags. PR #16 made this operator-reachable —
  `--rest-config … --rest-spec … --adaptive` is a supported combination. The attackers are
  now gated where the probes are, emitting the **same** `NOT ASSESSABLE` record ADR 0006
  already defines — same fields, same `"(surface-gated)"` prompt, no new shape or sentinel.
  Reported rather than skipped silently, so an operator can tell "did not run" from "ran and
  found nothing". See `docs/adr/0017-attacker-surface-applicability.md`.
- **`rest.py` told operators REST has no CLI path** (`targets/rest.py`): three sites — the
  module docstring, `require_scope`'s docstring, and the raised `TargetError` — asserted
  that `--authorized` does not gate REST. PR #16 gave REST a CLI path where it does, and
  ADR 0015 recorded the wording as owed. R1's requirement and behaviour are **unchanged**;
  only the stated reason is corrected, to ADR 0014's accepted limitation that binding does
  not verify a target's host against the document it was discovered from — which is what
  makes the allowlist load-bearing, and an exposure chat does not have.
- **`schema.from_openapi` raised `AttributeError` on a malformed path entry**
  (`schema.py`): a path whose value is not an object reached `.items()`. ADR 0003 recorded
  this in its *"Note for the next PR"*, drawing the contrast that `discovery.py` skips such
  entries. It now skips them the same way, so the two OpenAPI consumers agree; a malformed
  sibling no longer suppresses valid operations in the same document.
- **Redaction wrote its count to unreachable state** (`redaction.py`): `redact_finding` set
  `f.metadata["redactions"]` on a field `Finding` does not declare, so `dataclasses.asdict`
  never saw it and the value reached no report, bundle or export. The dead write is removed;
  the count remains the function's return value. Recording it for real would require a new
  `Finding` field and a changed report format, which this change deliberately does not do.
- `docs/adr/0017-attacker-surface-applicability.md`.
### Tests
- 616 passing (+27). Recorded correctness defects: the REST-plus-attacker crash reproduced
  and eliminated for both flags with the gate reported rather than silent; CHAT, direct and
  no-attacker runs asserted unchanged; the false `rest.py` claims asserted absent from both
  source and the raised message while every scope refusal is asserted unchanged; malformed
  OpenAPI entries skipped across five shapes without suppressing valid siblings, and
  `schema` asserted to agree with `discovery` on the same document; no undeclared attribute
  left on a redacted `Finding`, with redaction behaviour and the 41-field shape unchanged;
  plus `runtime_coverage_ratio`, provenance buckets and battery size frozen.

### Fixed
- **`--replay` crashed a REST assessment** (`cli.py`): the bundle's `target_config` was
  built from `target.body_template` and `target.response_path` whenever `--config` was
  absent, which is exactly the REST path's condition — a REST run supplies `--rest-config` —
  and `RestTarget` declares neither. Measured on `v0.4.2-correctness`:
  `AttributeError: 'RestTarget' object has no attribute 'body_template'`. `--demo --replay`
  and `--harness --replay` both succeeded, so the defect was REST-specific and reachable
  only since PR #16 made `--rest-config … --replay` a supported pairing.
  **Guarding the attribute read alone would not have been enough.** The artifact is
  chat-shaped in three places: `to_replay` writes `body_template`/`response_path`;
  `REPLAY_RUNNER` imports `HTTPChatTarget`, constructs one, and calls `send()`; and
  `_INDICATOR` has no entry for `rest-response-disclosure`, so a REST step would carry a
  null indicator the runner can never satisfy. A REST finding's prompt is the canonical
  request and does not start with `(`, so the bundle would have been produced and been
  unusable — posting an HTTP request line as a chat prompt.
  **Replay is now unsupported for non-chat surfaces.** No bundle and no runner are written,
  one warning naming the kind and the reason goes to **stderr**, and the assessment
  completes with its normal exit code. Stdout, the report, SARIF and HAR are untouched. The
  guard keys on the **driven surface kind** via `drivable_surfaces_of`, not on the target's
  class, so a future non-chat surface inherits it and a driverless kind is still refused by
  ADR 0009's existing resolution. See `docs/adr/0018-replay-surface-applicability.md`.
  **No replay format was invented.** A REST bundle would need a version bump, a per-kind
  `target_config` schema, a second runner, a canonical-request parser exposed to a
  standalone script, and indicator semantics for a detector-based probe — plus an answer to
  a safety question no ADR settles: `REPLAY_RUNNER` builds its target with no `Scope`, which
  is consistent for chat because `--authorized` gates it, but ADR 0012 R1 requires a
  non-empty allowlist before any REST request. All recorded in ADR 0018 for a future
  decision.
  **Unchanged:** every chat run — `--demo`, `--harness` and `--config` produce
  byte-identical bundles and runners, the runner asserted by SHA-256 against
  `v0.4.2-correctness` — plus graph identity, custody, SARIF, provenance,
  `runtime_coverage_ratio` (0.54), battery size (22), `Finding` field order/defaults/count
  (41), discovery output, benchmark and determinism, all verified by tree comparison. No
  existing test was modified.
- `docs/adr/0018-replay-surface-applicability.md`.
### Tests
- 638 passing (+22). Replay surface applicability: the crash reproduced and eliminated,
  alone and combined with `--sarif`/`--har`; exit code matching a run without `--replay`; no
  bundle, no runner, and the `Wrote …` line omitting the bundle; the warning asserted on
  stderr with the kind and the reason, and stdout asserted line-for-line unchanged; SARIF,
  HAR and the report still written on the same run; chat bundles frozen, with the runner
  pinned by SHA-256 and the `target_config` shape asserted; and the guard's kind resolution
  covered for an unbound run, a chat surface, a REST surface, a mixed application, and a
  driverless kind that resolution still refuses.

### Fixed
- **The audit chain did not detect tampering** (`audit.py`): `AuditLog.verify()` walked the
  `prev` links and recomputed nothing — it could not, because the digest covered the **raw**
  prompt and response while the entry stores only their sha256 digests. Measured on
  `v0.4.3-replay-applicability`, altering an entry's `url`, `ts`, `prompt_sha256`,
  `response_sha256` or `ok` all left `verify()` returning `True`, while the module docstring,
  `README`, `THREAT_MODEL` and four guides described the log as tamper-evident and the
  CLI printed the verdict to the operator. Two further gaps surfaced: `ok` was stored but was
  never a hash input, so it was unprotected in principle; and nothing read the `--audit-log`
  file back, so the on-disk artifact had no verification path at all.
  The digest now covers the fields the entry **retains** — `v`, `prev`, `ts`, `url`,
  `prompt_sha256`, `response_sha256`, `ok` — so any entry is recomputable from itself.
  Raw payloads are still never persisted: the audit log remains the one artifact that cannot
  leak a payload, which is what justifies `redaction` having nothing to do to it, and that is
  now a stated contract rather than an accident.
  See `docs/adr/0019-audit-chain-integrity.md`.
  **Canonical serialization is frozen and specified once:** each field emitted as
  `<utf8-byte-length>":"<value>` in fixed order, booleans as `true`/`false`, passed to
  `sha256` as a single argument. Length-prefixing is required because `audit.sha256`
  concatenates its parts without a separator — `sha256("ab","c") == sha256("a","bc")` — and
  **`sha256` itself is unchanged**, because `evidence_hash` (`engine.py`) and `custody_hash`
  (`chat.py`, `rest.py`) are frozen invariants computed with it.
  **Legacy logs are unverifiable, never tampered.** Entries gain `"v": 2`; a chain
  containing an entry without it returns a distinct legacy state, detected *before* any
  digest comparison, because a v1 digest can never match the v2 formula and reporting that as
  tampering would accuse the operator of something that did not happen. v1 chains cannot be
  upgraded — recomputing them needs raw payloads that were never stored.
  **`verify()` is now a compatibility API only.** It keeps its signature and `bool` return
  for existing callers and is called by no new code; `AuditLog.check()` returns a three-state
  result and `verify_file(path)` applies the same rule to a JSONL log — the first reader that
  artifact has ever had. `cli.py` uses `check()`, so "cannot be verified" no longer reads the
  same as "was altered".
  **Not claimed:** truncation of the log's tail is still undetected — a forward chain can be
  recomputed by whoever can write the file, so detecting a removed tail needs an anchor kept
  outside it. The run now prints the final entry hash for that purpose, a test pins the
  limitation, and the documentation no longer implies otherwise.
  **Unchanged:** `audit.sha256` byte-for-byte and with it `evidence_hash` and `custody_hash`;
  `Scope`; `RateLimiter`; `har_export`; graph identity, `_finding_key`, SARIF, replay bundles
  and runner, provenance, `runtime_coverage_ratio`, battery size, `Finding` field
  order/defaults/count, discovery output, benchmark corpus and determinism — all verified by
  tree comparison. No existing test was modified.
- `docs/adr/0019-audit-chain-integrity.md`.
### Tests
- 677 passing (+39). Audit chain integrity: eight tamper cases (`url`, `ts`, both payload
  digests, `ok`, `entry_hash`, `prev`, deleted middle entry), the truncation limitation
  pinned as accepted, legacy chains asserted unverifiable rather than tampered including a
  mixed chain and a legacy entry with a forged digest, `verify()`'s signature and bool
  contract, canonical-form determinism with a field-boundary-shift proof and the deliberate
  record that the underlying `sha256` helper is still ambiguous, frozen `sha256` digests, a
  canary proving no raw payload is persisted, the exact entry shape, and JSONL verification
  agreeing with in-memory including on-disk tampering and a malformed line.

### Fixed
- **A twice-used `--audit-log` reported as tampered** (`audit.py`): the flag is documented
  as *"path to **append-only**, hash-chained JSONL audit log"*, but `AuditLog.__init__` set
  `prev` to genesis unconditionally and never read the file, so a second run wrote a second
  chain into the same file. Measured on `v0.4.4-audit-integrity`, two `--demo` runs to one
  log produced 42 lines that `verify_file` rejected — *"entry 21 does not link to its
  predecessor"*. The integrity control was accusing a correctly-used custody log of
  tampering, which is worse than silence: it devalues every true positive it will ever
  report. Not a regression from PR #20 — the broken on-disk linkage had existed since the
  flag shipped, and PR #20's verifier is what made it visible.
  A log file is now **one append-only chain**. Opening an existing file verifies it under
  the ADR 0019 v2 rules and resumes from its verified head; the head is adopted only after
  every prior entry has been recomputed, because resuming from an unverified head would let
  one altered entry silently anchor everything appended afterwards.
  See `docs/adr/0020-audit-log-append-semantics.md`.
  **Tampered or legacy logs are refused, not extended.** Both raise `ConfigError` — an
  existing `GlasscageError`, so the CLI's existing handler turns it into `error: …` and exit
  2 — and **nothing is written**: no partial entry, no sibling file, no backup. The message
  names the path and says to write this run elsewhere. The consequence is deliberate: such a
  path becomes unusable, because every softer option (rotate, migrate, repair, segment) is a
  mechanism this repository does not have, and inventing one to smooth over a failed
  integrity check would defeat the control.
  **Also fixed:** a JSONL line that is valid JSON but not an object (a bare array, string or
  number) reached a field access and raised `AttributeError`. `verify_file` already promised
  *"a malformed line is reported as tampering rather than skipped"*; the guard now sits in
  `check_entries` so both callers inherit one rule.
  **Security posture is unchanged in both directions.** Resuming inherits ADR 0019 §8's
  accepted limitation exactly — verification proves the entries present are internally
  consistent, not that none were removed — and this change makes no truncation claim. It is
  a strict improvement only in that a tampered log is no longer silently appended to.
  **Unchanged:** `audit.sha256` and with it `evidence_hash` and `custody_hash`;
  `AuditLog.verify()`'s signature and `bool` return; `ChainStatus`/`ChainResult`;
  `ENTRY_VERSION` and the canonical serialization; no raw payload persisted across a resume;
  zero dependencies; graph identity, `_finding_key`, SARIF, replay bundles and runner,
  provenance, `runtime_coverage_ratio`, battery size, `Finding` field order/defaults/count,
  discovery output, benchmark corpus and determinism — all verified by tree comparison. No
  existing test was modified, and `cli.py` needed no change.
- `docs/adr/0020-audit-log-append-semantics.md`.
### Tests
- 708 passing (+31). Audit-log append: two and three runs to one path verifying, the first
  new entry linking to the previous head, prior entries loaded so the in-memory chain still
  checks, line counts growing by the new entries only; every genesis case (no path, absent
  file, empty file, blank lines); refusal for tampered and legacy logs asserted to write
  nothing and to create no sibling file; non-object JSONL lines across array, string, number
  and boolean; and the ADR 0019 contracts re-asserted intact — all eight tamper cases,
  truncation still accepted both in memory and on disk after a resume, `verify()`'s bool
  contract, entry shape, canonical form, the frozen `sha256`, and a canary proving no raw
  payload is persisted across a resume.

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
