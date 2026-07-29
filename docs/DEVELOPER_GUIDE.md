# GLASSCAGE Developer Guide — 1.0.0rc3

Zero-dependency Python (stdlib only) built around the **AI Attack Knowledge Graph**.
**The architecture is frozen** (since Stage E5). Extend via probes, adapters and
plugins — not by editing the core.

---

## 1. Layout

```
glasscage/
  aakg/            # THE substrate + graph-native engines
    types.py       #   24 node types, 12 edge types, EdgeState        [Implemented]
    engine.py      #   PropertyGraph: deterministic, cached           [Implemented]
    build.py       #   assemble graph from a run                      [Implemented]
    paths.py       #   E2 attack paths (weakest-link state)           [Implemented]
    trust_graph.py #   E3 trust boundaries                            [Implemented]
    blast.py       #   E4 blast radius                                [Implemented]
    posture.py     #   Indicative Risk Index (heuristic)              [Implemented]
    coverage.py    #   per-taxonomy coverage                          [Implemented*]
    remediation.py #   graph-cited prioritized mitigations            [Implemented]
    report.py      #   graph-native markdown                          [Implemented]
    narrative.py   #   8 narrative strategies (renderer only)         [Implemented]
    story.py       #   13-section Assessment Story                    [Implemented]
    views.py       #   5 audience views                               [Implemented]
  probes.py        # 21 probes (18 active, 3 questionnaire)           [Implemented]
  agent_probes.py  # tier-aware agentic probes (L0-L2)                [Implemented]
  tal.py           # capability tiers L0-L3                           [Implemented]
  target.py        # HTTP target + config validation                  [Implemented]
  refagent.py      # deterministic L2 reference harness               [Implemented]
  adapters/        # external framework parsers          [Pending External Validation]
  stats.py         # Wilson CIs, trial runner                          [Implemented]
  benchmark.py     # detector corpus runner                            [Experimental]
  taxonomy.py      # OWASP<->ATLAS<->CWE<->CAPEC<->NIST crosswalk      [Implemented]
  redaction.py     # secret redaction + optional encryption            [Implemented]
  evidence_confidence.py  # the 8-class vocabulary + clamp             [Implemented]
  errors.py logging_setup.py config.py plugins.py   # production infra [Implemented]
```

`*` coverage has a known accounting defect — see §6.

---

## 2. Architectural rules (do not violate)

1. **The AAKG is the single source of truth.** Posture, coverage, remediation and
   reporting *query the graph*. Never reintroduce independent calculation.
2. **No new node or edge types.** The vocabulary is frozen.
3. **Never fabricate.** An unavailable tool reports `Not Tested` /
   `Pending External Validation` — never synthetic data.
4. **Determinism is a guarantee.** Sorted traversal, deterministic ids, seeded
   randomness, exact serialization round-trip. Property tests enforce it.
5. **Evidence discipline is enforced in code**, via `EvidenceClass.at_most()`. A claim
   may never exceed its evidence.
6. **Reporting layers read; they never analyse.** Narratives/story/views select and
   render existing graph objects only.

---

## 3. Adding a probe — **Implemented extension point**

```python
from glasscage.probes import Probe, register, canary_verdict, CANARY_INJECT
from glasscage.models import Severity, Status
from glasscage.tal import Tier

@register
class MyProbe(Probe):
    name = "my-probe"          # required
    owasp_id = "LLM01"         # required
    min_tier = Tier.L0         # required — below-tier targets auto-return NOT ASSESSABLE
    category = "My Technique"
    dimension = "steerability"  # or "impact"

    def run(self, target, recon):
        r = target.send(f"...{CANARY_INJECT}...")
        if not r.ok:
            return [self._finding(Status.ERROR, "transport error", Severity.INFO,
                                  "prompt", r.error or "", 0.0)]
        status, conf, _ = canary_verdict(CANARY_INJECT, r.text)
        return [self._finding(status, "what happened", Severity.LOW,
                              "prompt", r.text, conf)]
```

**Rules:** declare `min_tier` (tier gating is free — don't hand-roll it); separate
**steerability** from **impact** (only impact drives high risk); use `r.trace` to
*confirm* agentic impact rather than infer it; never claim what you did not observe.

---

## 4. Adding an adapter — **Implemented extension point**

```python
from glasscage.adapters.base import ExternalToolAdapter, AdapterResult

class MyToolAdapter(ExternalToolAdapter):
    name = "mytool"
    def available(self) -> bool: ...      # is the tool installed?
    def version(self) -> str | None: ...
    def run(self, target, opts) -> AdapterResult:
        # If the tool is absent AND no from_file is given:
        #   return an honest Not-Tested result. NEVER fabricate findings.
        ...
```

Register in `adapters/__init__.REGISTRY`. Parsers must emit normalized `Finding`s with
full taxonomy. **Fixture conformance is not validation** — see §6.

---

## 5. Writing a plugin — **Implemented**

See `docs/PLUGIN_SDK.md` and `plugins_example/example_probe.py`.
Declare `GLASSCAGE_PLUGIN_API = "1.0"`; a major mismatch is refused. Plugins load only
with `--allow-plugins` and run **unsandboxed**.

---

## 6. Known defects a contributor should know

| Defect | Status |
|---|---|
| **`coverage_ratio` counts questionnaire + config-review findings as "tested"** (true runtime coverage 7/13 = 0.54; reported 0.85) | **P0 — open** |
| **`PropertyGraph` exposes `node(nid)` but no `edge(eid)`**, so `aakg/narrative.py::_edge_by_id` linear-scans `g.edges()` (which sorts every call) — ~41 µs vs <1 µs for the dict that already exists in `self._edges`. Root cause of the rc3 3× slowdown. | **P1 — open** |
| `simple_paths` is exponential worst case; bounded by `max_depth=6`, no path-count cap | **P1 — open** |
| Self-declared `--architecture` answers are trusted, never verified | **P0 — open** |
| 16 broad `except Exception` handlers | **P2 — open** |
| Dual graph systems (`graph.py` vs `aakg/`) and legacy shims still ship | **P2 — open** |
| CI lint/type gates are advisory (`|| true`) | **P2 — open** |

---

## 7. Testing

```bash
python -m unittest discover -s tests -q          # 189 tests
python -m unittest tests.test_fuzz -q            # malformed input never crashes
python -m unittest tests.test_property -q        # invariants (stdlib property tests)
python -m unittest tests.test_narrative -q       # anti-hallucination guarantees
python tools/benchmark_perf.py                   # performance
python tools/profile_run.py                      # cProfile + tracemalloc
```

**Every change needs tests.** Core changes need fuzz + property runs. The
anti-hallucination tests (`test_narrative.py`) assert that every cited node/edge exists
in the graph and no state is laundered — do not weaken them.

---

## 8. Contributing

See `CONTRIBUTING.md`. Keep the core stdlib-only; preserve determinism; preserve
backward compatibility (`VERSIONING.md`); never fabricate results.
