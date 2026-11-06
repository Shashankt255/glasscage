# GLASSCAGE API Reference — 1.0.0rc3

Stable within a major version unless marked otherwise (see `VERSIONING.md`).
Auto-generated per-module docs: `python tools/gen_api_docs.py` → `docs/api/`.


## Engine — **Implemented / Stable**

```python
from glasscage.engine import Engine

Engine(target, *, schema_tools=None, mcp_manifest=None, architecture_answers=None,
       evidence_dir=None, capture_evidence=True, adaptive=False, genetic=False,
       judge=False, rate=None, build_chains=True, trials=1, seed=None,
       use_aakg=True, store_raw=False)

results = Engine(target).run()          # -> dict
md   = engine.report_markdown(results)  # graph-native markdown
html = engine.report_html(results)      # interactive HTML
```

### `run()` result keys — **Stable**

| Key | Type | Meaning |
|---|---|---|
| `recon` | ReconResult | reconnaissance output |
| `findings` | list[Finding] | one per probe (**21 probes → 21 findings, 1:1**) |
| `summary` | dict | counts + `posture_score` + `risk_index` |
| `graph` | dict | legacy attack-surface graph |
| `coverage` | dict | taxonomy coverage (**see accounting defect below**) |
| `architecture` | dict | declared-controls summary |
| `trust` | dict | trust-boundary model (graph-derived) |
| `chains` | list[dict] | attack paths (graph traversal) |
| `posture` | dict | Indicative Risk Index + contributions |
| `stats` | dict | Wilson CIs when `trials > 1` |
| `tier` | dict | assessed capability tier |
| `aakg` | dict\|None | graph statistics |
| `blast` | dict\|None | blast radius summary |
| `remediation_priorities` | list\|None | graph-cited mitigations |
| `narratives` | list\|None | NarrativeModel per strategy |
| `story` | StoryModel\|None | 13-section Assessment Story |

`aakg`/`blast`/`remediation_priorities`/`narratives`/`story` are `None` when
`use_aakg=False`.


## Models — **Implemented / Stable**

```python
from glasscage.models import Finding, Status, Severity, Dimension, ReconResult

Status:   VULNERABLE | NOT_VULNERABLE | INCONCLUSIVE | NOT_ASSESSABLE | ERROR
Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
```

Key `Finding` fields: `probe_name`, `owasp_id`, `atlas_id`, `cwe_id`, `capec_id`,
`nist_id`, `status`, `severity`, `confidence`, `dimension`, `impact_confirmed`,
`evidence_hash`, `assessed_tier`, `required_tier`, `trials_run`, `success_rate`,
`ci_low`, `ci_high`, `reproducibility`, `source_framework`.


## Target — **Implemented / Stable**

```python
from glasscage.target import HTTPChatTarget
target = HTTPChatTarget({"url": "https://...", "headers": {...},
                         "body_template": {...}, "response_path": "..."})
resp = target.send("prompt")     # -> ChatResponse(ok, text, error, trace, ...)
```
Config is validated on construction; raises `errors.ConfigError`.


## AAKG — **Implemented / Stable**

```python
from glasscage.aakg import PropertyGraph, NodeType, EdgeType, EdgeState
from glasscage.aakg import build, paths, trust_graph, blast
from glasscage.aakg import posture, coverage, remediation, report
from glasscage.aakg import narrative, story, views

g = build.build_graph(recon, findings, mcp_manifest, architecture_answers,
                      target_tier="L2", ts="...")
g.node(nid); g.nodes(ntype); g.edges(etype)
g.out_edges(nid); g.in_edges(nid); g.neighbors(nid)
g.simple_paths(src, dst_ids, edge_types=None, max_depth=6)
g.reachable(src, edge_types=None, max_depth=8)
g.to_dict() / g.to_json() / PropertyGraph.from_dict(d)   # exact round-trip
g.stats()
```

> **Note:** there is **no `edge(eid)` accessor** in 1.0.0rc3. See Developer Guide §6.

**EdgeState:** `demonstrated` · `hypothesized` · `not_assessable` (monotonic upgrade).


## Evidence Confidence — **Implemented / Stable**

```python
from glasscage.evidence_confidence import EvidenceClass, from_state, tag, legend

EvidenceClass.VERIFIED | MEASURED | DEMONSTRATED | OBSERVED
            | EXPERIMENTAL | ESTIMATED | HYPOTHESIZED | PENDING_EXTERNAL_VALIDATION

EvidenceClass.MEASURED.at_most(EvidenceClass.ESTIMATED)   # -> ESTIMATED  (clamp)
from_state("demonstrated")                                 # -> DEMONSTRATED
```


## Redaction — **Implemented / Stable**

```python
from glasscage import redaction
redaction.redact_text(s)          # -> (redacted, count); [REDACTED:<8hex>] tokens
redaction.redact_all(findings)
redaction.contains_secret(s)
redaction.encryption_available()  # crypto extra present?
redaction.encrypt_dir(path, pw)   # raises ConfigError if extra absent (no fake cipher)
```


## Probes & Tiers — **Implemented / Stable**

```python
from glasscage.probes import Probe, register, REGISTRY, canary_verdict, detect_secret, CANARY_INJECT
from glasscage.tal import Tier, TargetCapabilities, parse_tier   # Tier.L0..L3
```

## Statistics — **Implemented / Stable**
```python
from glasscage.stats import wilson, TrialRunner, aggregate
point, lo, hi = wilson(successes, trials)      # 95% Wilson interval
```

## Errors / Config / Logging — **Implemented / Stable**
```python
from glasscage.errors import (GlasscageError, ConfigError, TargetError,
                              AdapterError, GraphError, PluginError)
from glasscage.config import validate_target_config, validate_trials
from glasscage.logging_setup import configure, get_logger
```

## Plugins — **Implemented / Stable**
```python
from glasscage.plugins import load_plugins, PLUGIN_API_VERSION   # "1.0"
```

## Adapters — **Pending External Validation**
```python
from glasscage.adapters import REGISTRY            # native/fake/garak/pyrit/promptfoo/deepteam/fuzzyai
from glasscage.adapters.base import ExternalToolAdapter, AdapterResult, ADAPTER_API_VERSION
from glasscage import adapter_validation
adapter_validation.validate_adapters({"garak": "real_output.jsonl"})
```
Parsers are **conformant to fixtures only**; no genuine tool output has been ingested.

## Experimental
`benchmark` (Experimental corpus, n=109) · `validation` · `judge` (needs `llm` extra) ·
`genetic` · `mutation`.

## Deprecated (removal next major)
`posture`, `coverage`, `chain`, `trust` legacy modules (`use_aakg=False` only);
`scoring` grade.
