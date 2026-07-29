# Attack Narratives & Assessment Story

A **reporting layer** over the AI Attack Knowledge Graph. It performs no analysis,
creates no paths, adds no nodes/edges, and introduces no scoring. It selects among the
attack paths the pipeline already produced and renders them as prose that a human can
read and audit.

Modules: `glasscage/aakg/narrative.py` (model + strategies), `story.py` (13-section
engagement story), `views.py` (five audience lenses).

## Attack Narratives

Eight **strategies**, each a filter/ranking over paths that already exist:

| Strategy | Selection rule (over existing paths only) |
|---|---|
| Highest Impact Path | strongest state, then most valuable terminal asset, then likelihood |
| Lowest Effort Path | fewest hops, then strongest state |
| Most Likely Path | highest path likelihood |
| Data Exfiltration | terminal node is Secrets or Database |
| Tool Abuse | path contains an `invokes` edge into a Tool |
| Privilege Escalation | path contains a hop into a higher trust zone |
| Memory Poisoning | path traverses a Memory node |
| MCP Compromise | path traverses an MCP node |

If **no existing path** matches a strategy, the narrative is not written. The output is
exactly: `Not demonstrated. No existing graph path matches this strategy; no path was
synthesized. [Not Supported by Current Evidence]`

### Every transition cites
node ids (`src` → `dst`), the graph edge id, evidence ids, confidence, and the
demonstrated / hypothesized / not-assessable state. Example:

```
2. model invokes planner — hypothesized, not shown on-target
   - nodes `LLM:model` -> `Planner:planner` · edge `LLM:model-[invokes]->Planner:planner`
     · evidence no evidence id (structural edge) · confidence n/a · [Hypothesized]
```

### Deduplication
Several strategies commonly resolve to the *same* path (the shortest path is often also
the highest impact). Rendering it once per strategy would duplicate the report without
adding information, so identical paths are rendered **once**, listing the strategies
that selected them.

## Assessment Story
Thirteen sections, each independently evidence-classified: Assessment Overview,
Reconnaissance Summary, Key Findings, Attack Progression, Trust Boundary Crossings,
Blast Radius, Business Impact, Root Cause Analysis, Evidence Summary, Prioritized
Remediation, Residual Risk, Verification Checklist, Lessons Learned.

## Audience views
`executive`, `security`, `developer`, `incident_response`, `compliance` — all render
from the **same** `StoryModel` + `NarrativeModel` objects. Use `--views all` (or name
specific audiences) to write `<out>_view_<audience>.md`.

## Evidence discipline (enforced, not advisory)
* A narrative's class is **clamped to its weakest transition**. A path with one
  hypothesized hop is Hypothesized overall, even if every other hop is Demonstrated.
* A path narrative can never exceed **Demonstrated** — `Measured`/`Verified` require
  evidence of a different kind (corpus measurement, custody hash) and are reserved for
  the sections that actually have it.
* Tests assert every cited node/edge exists in the graph and every state matches the
  graph edge verbatim.

## Honest limitations

1. **Structural edges carry no evidence id.** Flow edges (`crosses`/`invokes`/
   `accesses`) are recorded with provenance but evidence hashes attach to *findings*.
   Narratives therefore print `no evidence id (structural edge)` rather than invent
   one. Finding-level evidence remains in the Evidence Ledger.
2. **Business Impact is qualitative.** The graph knows asset *types* (Secrets/Database/
   Filesystem) but GLASSCAGE has no asset-criticality or valuation input. No monetary
   or criticality rating is asserted — you must rate the assets against your own
   crown-jewel inventory. Classified `[Estimated]`.
3. **Residual Risk is not a number.** There is no calibration data to support a
   post-remediation risk figure, so the story reports which paths remain unaddressed
   and explicitly refuses to compute a residual score.
4. **Root Cause is limited to `enables` edges.** Where no finding carries one, the
   section says "Not demonstrated." rather than speculate.
5. **No network IOCs.** The Incident Response view can only offer GLASSCAGE's own probe
   markers (canaries) and evidence hashes; GLASSCAGE observes no host/network telemetry.
   The view states this instead of fabricating indicators.
6. **Narratives inherit every upstream limitation.** They are a rendering of the graph.
   If the underlying assessment is unvalidated against real targets, a fluent narrative
   does not make it true. Read the evidence classes.

## Not changed
SARIF output and replay bundles are untouched by this layer, by design.
