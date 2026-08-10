# Command Reference

Every CLI option in GLASSCAGE 1.0.0rc3. Invoke as `python -m glasscage`, `glasscage`
(if installed as a script), or `python cli.py`.

**Exit codes:** `0` success · `2` refused (missing `--authorized`, missing
`--allow-plugins`, invalid config, unknown view).

There is **no `--version` flag** in rc3; use `python -c "import glasscage;
print(glasscage.__version__)"`.

---

## Target selection & scope

### `--config PATH`
- **Purpose:** assess a real HTTP target described by a JSON (or YAML with the `yaml`
  extra) config.
- **Example:** `python -m glasscage --config target.json --authorized --out r`
- **When:** any real engagement.
- **Common mistake:** forgetting `--authorized` (run is refused, exit 2). Malformed
  `response_path` returns empty responses — validate against a manual curl first.

### `--rest-config PATH` + `--rest-spec SPEC`
- **Purpose:** assess a REST application. `--rest-spec` is an OpenAPI document whose
  operations are discovered and bound; `--rest-config` is a JSON
  `{url, headers?, timeout?, name?}` describing the endpoint to drive. Both are required
  together (ADR 0015).
- **Example:**
  `python -m glasscage --rest-spec openapi.json --rest-config rest.json --scope api.example --authorized --out r`
- **When:** assessing an HTTP API rather than a chat endpoint.
- **`--scope` is mandatory here, unlike `--config`.** A REST target with no host allowlist
  is refused before any request (ADR 0012 R1). The reason is ADR 0014's accepted
  limitation: binding does not check that `--rest-config`'s host matches the document in
  `--rest-spec`, so the allowlist is the only thing preventing traffic to an unintended
  host if the two are mis-paired.
- **Expect a mostly NOT ASSESSABLE report.** 21 of the 22 registered probes are
  chat-shaped and are gated on a REST surface (ADR 0006), so a two-operation spec yields
  42 gated findings and 2 assessed. The gated entries record that a probe was not
  applicable — they are not failures.
- **Not the same as `--discover`.** `--discover` only prints an inventory and drives
  nothing; `--rest-spec` assesses. Neither affects the other.
- **Common mistake:** omitting `--scope` (refused), or omitting `--rest-spec` (there is
  nothing to drive without operations to bind).

### `--demo`
- **Purpose:** run against a built-in mock (L0). No network, no authorization.
- **Example:** `python -m glasscage --demo --out r`
- **When:** verifying the install; learning the output format.

### `--harness`
- **Purpose:** run against the built-in L2 reference agent (planner/memory/tools).
- **Example:** `python -m glasscage --harness --schema samples/function_schema.json --out r`
- **When:** seeing agentic analysis end-to-end.
- **Common mistake:** treating harness output as evidence about a real system. It is a
  deterministic fixture.

### `--authorized`
- **Purpose:** your assertion that you own or have written permission to test the target.
- **When:** required for every `--config` target.
- **Common mistake:** assuming it bypasses anything — it is a gate, not a capability.

### `--scope HOST [HOST ...]`
- **Purpose:** hostname allowlist; requests outside it are refused (defence in depth).
- **Example:** `--scope api.example.com staging.example.com`

### `--rate N`
- **Purpose:** cap requests per second.
- **Example:** `--rate 2`
- **When:** always, against real targets. GLASSCAGE does **not** back off automatically.

### `--schema PATH`
- **Purpose:** ingest an OpenAPI / function / MCP tool schema → schema-confirmed tools,
  which materially improve blast-radius accuracy.
- **Example:** `--schema tools.json`

### `--architecture PATH`
- **Purpose:** supply declared controls (a questionnaire).
- **Common mistake / warning:** answers are **trusted, not verified**. A declared
  control suppresses trust-boundary violations and lowers the risk index. Only answer
  what you know to be true. Generate a blank template with `--arch-template`.

### `--arch-template`
- **Purpose:** print a blank architecture questionnaire to stdout.
- **Example:** `python -m glasscage --arch-template > arch.json`

### `--discover SPEC` — Experimental
- **Purpose:** enumerate the **drivable surface inventory** from an OpenAPI document or
  an MCP manifest. Prints a table and writes `<out>_surfaces.md` / `<out>_surfaces.json`.
- **Example:** `python -m glasscage --discover openapi.json --out inv`
- **When:** scoping an engagement — "where can this application be driven?" — before or
  independently of an assessment.
- **Runs nothing.** No target is constructed, no probe is sent, no report is produced.
  Discovered surfaces are **candidates**: they are not bound to a driver and are not
  driven. Promotion to a driven surface is not available in this release.
- **Not the same as `--schema`.** `--schema` feeds schema-confirmed blast radius *during*
  an assessment and flattens operations into capability records; `--discover` keeps the
  locator, HTTP method and I/O schema that `--schema` discards, and assesses nothing.
- **Common mistake:** expecting findings. This is an inventory, not a test. `$ref` is not
  resolved and only `paths` → HTTP methods and MCP `tools` are enumerated, so the count
  is a lower bound on a spec that leans on references.

---

## Attack engines

### (default probes)
- **Purpose:** run the 21 built-in probes (18 active, 3 questionnaire-only).
- **When:** always on unless you scope differently.

### `--adaptive`
- **Purpose:** mutation loop over a payload (encoding/rephrasing variants).
- **Maturity:** Implemented.

### `--genetic`
- **Purpose:** evolutionary payload search.
- **Example:** `--genetic --seed 7`
- **Maturity:** Implemented. Use `--seed` for reproducibility.

### `--judge`
- **Purpose:** LLM-as-judge scoring of responses.
- **Maturity:** **Experimental.** Requires the `llm` extra and an API key.
- **Common mistake:** enabling without the extra installed → falls back / errors.

### `--trials N`
- **Purpose:** repeat each probe N times → Wilson confidence intervals.
- **Example:** `--trials 5`
- **When:** any real engagement; single trials on a nondeterministic target are noise.

### `--seed N`
- **Purpose:** deterministic replay of stochastic engines.
- **Example:** `--seed 1`

### Attacker budget contract: `PER_SURFACE`
- `--adaptive` and `--genetic` budgets are **per-surface exploration allowances**, not run
  totals. Driving an application at N surfaces performs **N × budget** evaluations — five
  surfaces at `--genetic 40` is 200. The effective total is reported in
  `results["tier"]["effective_adaptive_budget"]` / `["effective_genetic_budget"]`, with
  `["attacker_budget_contract"] == "PER_SURFACE"`.
- **Why named:** dividing a budget across surfaces would silently weaken every surface's
  assessment as an application grows. Naming the contract means any future total-budget
  mode arrives as an additional named option rather than a silent redefinition of these
  flags. See [ADR 0011](adr/0011-multi-surface-execution.md).
- **Reachable from the Python API only.** The CLI drives a single target, so `N` is 1 and
  the effective budget equals the flag value.

---

## Evidence & safety

### (default) redaction
- **Purpose:** secret-shaped content is masked in **all** artifacts as
  `[REDACTED:<8hex>]` tokens. On by default.

### `--store-raw`
- **Purpose:** retain live secrets in artifacts (consent action).
- **Warning:** writes live secrets to disk. **Sandboxed hosts only.**

### `--encrypt-evidence` / `--evidence-password PW`
- **Purpose:** encrypt the evidence directory at rest.
- **Requires:** the `cryptography` package (see [INSTALL.md](INSTALL.md#encrypted-evidence)).
- **Example:** `--encrypt-evidence --evidence-password "$PW"` (or env
  `GLASSCAGE_EVIDENCE_PASSWORD`).
- **Common mistake:** expecting `glasscage[crypto]` to install it — no such extra
  exists in rc3; `pip install cryptography`.

### `--no-evidence`
- **Purpose:** skip SVG evidence cards (faster runs).

### `--har`
- **Purpose:** write an HTTP archive of the exchange (redacted unless `--store-raw`).

### `--audit-log PATH`
- **Purpose:** hash-chained chain-of-custody log.
- **What it records:** one JSONL entry per request — timestamp, URL, outcome, and the
  sha256 **digests** of the request and response. The payloads themselves are never
  written, which is why this is the one artifact redaction has nothing to do to.
- **What the chain proves:** each entry's digest covers its own recorded fields and the
  previous entry's digest, so altering any recorded field is detected. Confirming what a
  payload *was* requires the original to hash against — the log cannot reconstruct it.
- **What it does not prove:** truncation of the log's tail. A forward chain can be
  recomputed by anyone who can write the file; detecting a removed tail needs the final
  entry hash recorded somewhere else. The run prints it for that purpose.
- **Older logs:** entries written before the integrity format report as *unverifiable*
  rather than valid, and cannot be upgraded (ADR 0019).

---

## Output

### `--out BASE`
- **Purpose:** basename for all artifacts. **Required in practice.**
- **Example:** `--out engagement-01`

### `--views AUDIENCE [AUDIENCE ...]`
- **Purpose:** write audience views: `executive`, `security`, `developer`,
  `incident_response`, `compliance`, or `all`.
- **Example:** `--views executive compliance`
- **Common mistake:** an unknown audience name → exit 2.

### `--sarif`
- **Purpose:** emit SARIF 2.1.0 for code-scanning platforms.

### `--replay`
- **Purpose:** write a reproducible replay bundle (auth headers stripped).
- **Chat surfaces only.** The bundle's `target_config` and the emitted runner are built
  around `HTTPChatTarget`, so there is no format for a REST or other non-chat surface. On
  such a run the assessment completes normally, no bundle or runner is written, and a
  warning is printed to stderr ([ADR 0018](adr/0018-replay-surface-applicability.md)).
- **Reproducing a REST finding** does not need the bundle: each finding carries
  `reproduction_steps` rendering the exact request as curl (ADR 0012 R3).

### `--diff OLD.json NEW.json`
- **Purpose:** differential report between two prior JSON runs.
- **Example:** `python -m glasscage --diff run-A.json run-B.json`

### `--no-aakg`
- **Purpose:** use the legacy engines instead of the AAKG.
- **Maturity:** Implemented but **deprecated**; removal planned next major. Narratives
  and story are unavailable in this mode.

---

## MCP (configuration review only)

### `--mcp-manifest PATH`
- **Purpose:** static analysis of an MCP manifest (tool-poisoning, SSRF-prone params).
- **Warning:** GLASSCAGE **never contacts an MCP server**. This parses a JSON file.
  Runtime MCP is Roadmap.

### `--mcp-baseline PATH`
- **Purpose:** rug-pull detection — diff a manifest against an approved baseline.
- **Example:** `--mcp-manifest new.json --mcp-baseline approved.json`

---

## External frameworks (Pending External Validation)

### `--orchestrate TOOL [TOOL ...]`
- **Purpose:** run external tools (garak, pyrit, promptfoo, deepteam, fuzzyai) and
  ingest their output.
- **Maturity:** **Pending External Validation** — parsers conform to fixtures; genuine
  tool output has not been ingested at scale.

### `--adapter-file TOOL=PATH`
- **Purpose:** ingest a real output file from an external tool.
- **Example:** `--adapter-file garak=run.report.jsonl`

### `--validate-adapters` / `--genuine-output TOOL=PATH`
- **Purpose:** honestly report parser validation status; supply genuine output to
  upgrade a framework's status to `Measured`.
- **Example:** `python -m glasscage --validate-adapters --out a`

### `--benchmark PATH` / `--validate`
- **Purpose:** run the detector corpus benchmark (precision/recall/F1).
- **Maturity:** **Experimental** (corpus n=109, single annotator).

---

## Plugins & logging

### `--plugins DIR` / `--allow-plugins`
- **Purpose:** load custom probe modules. **`--plugins` requires `--allow-plugins`.**
- **Warning:** plugins are arbitrary, unsandboxed code. See [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md).

### `--log-level LEVEL` / `--log-json`
- **Purpose:** logging verbosity (DEBUG/INFO/WARNING/ERROR); JSON logs for SIEM.
- **When:** `--log-level DEBUG` when results look unexpectedly thin (a probe may be
  failing silently — see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)).
