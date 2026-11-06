# GLASSCAGE Tutorials — 1.0.0rc3

Hands-on, in order. **Every command below was executed against this release**; the
described outputs are what the tool actually produces. Tutorials 1–5 are safe and
need no network or authorization.


## Tutorial 1 — Your first assessment (2 minutes)

```bash
python -m glasscage --demo --out /tmp/first
```

Writes `/tmp/first.md`, `.html`, `.json`, `_aakg.json`, `_evidence/`.

```bash
head -30 /tmp/first.md
```

**What you're seeing:** an evidence legend, an executive summary with the **Indicative
Risk Index** (labelled `[Estimated]` — uncalibrated), and findings counts split into
demonstrated / hypothesized / not assessable.

**Key lesson:** the mock is an **L0** target. Agentic probes report **NOT ASSESSABLE** —
GLASSCAGE refuses to guess about capabilities the target does not expose.


## Tutorial 2 — Seeing agentic analysis work (L2)

```bash
python -m glasscage --harness --schema samples/function_schema.json --out /tmp/l2
grep -A6 "Attack Narratives" /tmp/l2.md | head -20
```

The built-in reference agent exposes planner/memory/tool traces, so agentic probes can
**confirm impact** and produce `demonstrated` graph edges.

**Key lesson — and the most important caveat in this documentation:** the harness is a
**deterministic test fixture written alongside the probes**. It proves the *machinery*
works. It says **nothing** about efficacy against a real model. Never present harness
results as evidence about a real system.


## Tutorial 3 — Reading the knowledge graph

```bash
python - <<'PY'
import json
g = json.load(open('/tmp/l2_aakg.json'))
print("nodes:", len(g["nodes"]), "edges:", len(g["edges"]))
from collections import Counter
print("edge states:", Counter(e["state"] for e in g["edges"]))
for e in g["edges"][:3]:
    print(f'  {e["src"]} -[{e["etype"]}/{e["state"]}]-> {e["dst"]}')
PY
```

**Key lesson:** every conclusion in every report is derived from this one graph. The
`state` field (`demonstrated`/`hypothesized`/`not_assessable`) is the epistemic
backbone — **a path is only as strong as its weakest edge.**


## Tutorial 4 — Proving secrets never leak into artifacts

The reference agent deliberately leaks a secret when the disclosure probe fires.

```bash
python -m glasscage --harness --har --out /tmp/red
grep -rl "sk-REF00011122233344455" /tmp/red* ; echo "matches above (expect none)"
grep -rho "\[REDACTED:[a-f0-9]\{8\}\]" /tmp/red.md | head -2
```

No artifact contains the raw secret; redaction tokens prove masking occurred.

```bash
# Consent flag retains it (sandboxed hosts only)
python -m glasscage --harness --store-raw --out /tmp/raw
grep -rl "sk-REF00011122233344455" /tmp/raw* | head -2
```

**Key lesson:** redaction is **default-on**; the custody hash is computed on the
**original** before redaction, so integrity survives sanitisation. `--store-raw` is a
deliberate, logged consent action.


## Tutorial 5 — Statistics and determinism

```bash
python -m glasscage --harness --trials 5 --seed 1 --out /tmp/stats
python -c "
import json; d=json.load(open('/tmp/stats.json'))
for f in d['findings'][:3]:
    if f.get('trials_run'):
        print(f\"{f['probe_name']:28} {f['success_rate']} CI[{f['ci_low']},{f['ci_high']}]\")
"
```

**Key lesson:** Wilson intervals quantify **sampling** uncertainty across trials. They
say nothing about whether the corpus or target is representative. The benchmark's
"reproducibility" figure measures **detector determinism on fixed strings** — not
target repeatability, which GLASSCAGE has never measured.


## Tutorial 6 — Audience views

```bash
python -m glasscage --harness --schema samples/function_schema.json --views all --out /tmp/v
ls /tmp/v_view_*.md
head -18 /tmp/v_view_executive.md
```

Five lenses over the **same** models. Compare `executive` (business language) with
`security` (full citations) — same evidence, different abstraction.

**Key lesson:** the `compliance` view states that unassessed areas are **not** passing;
the `incident_response` view admits it produces **no network IOCs**. Views inherit
evidence classes — they cannot upgrade a claim.


## Tutorial 7 — Honest adapter status

```bash
python -m glasscage --validate-adapters --out /tmp/adapters
```

Output shows `Genuine-validated: 0 · Pending External Validation: 5`.

**Key lesson:** parsers conform to author-written fixtures; **no genuine tool output
has ever been ingested.** GLASSCAGE reports this honestly instead of implying
orchestration. Supply real output to upgrade a framework to `Measured`:

```bash
python -m glasscage --validate-adapters --genuine-output garak=/path/real.report.jsonl --out /tmp/a2
```


## Tutorial 8 — MCP configuration review

```bash
python -m glasscage --mcp-manifest samples/mcp_manifest.json --out /tmp/mcp
```

You should see an MCP07 finding for a tool whose URL parameter references
`169.254.169.254` (cloud metadata).

```bash
# rug-pull: has an approved manifest drifted?
python -m glasscage --mcp-manifest samples/mcp_manifest.json \
  --mcp-baseline samples/mcp_manifest_baseline.json --out /tmp/rug
```

**Key lesson:** this is **static configuration review**. GLASSCAGE parses the manifest
JSON; it **never contacts an MCP server** (verified: zero network calls in `mcp.py`).
The finding evidences a defect **in the manifest**. Runtime MCP testing is **Roadmap**.


## Tutorial 9 — Writing a plugin probe

```bash
cat plugins_example/example_probe.py
python -m glasscage --demo --plugins plugins_example --allow-plugins --out /tmp/plug
```

Without `--allow-plugins` the run is **refused** (exit 2) with a trust warning.

**Key lesson:** declare `name`, `owasp_id`, `min_tier`. Tier gating is inherited free —
below-tier targets auto-return NOT ASSESSABLE. Plugins run **unsandboxed** with your
privileges; load only code you trust. See `docs/PLUGIN_SDK.md`.


## Tutorial 10 — A realistic engagement

```bash
python -m glasscage --arch-template > arch.json
# Edit arch.json — answer ONLY what you know to be true.
# Declared controls are TRUSTED, NOT VERIFIED: a wrong "yes" lowers your risk index.

python -m glasscage --config targets.json --authorized \
  --schema tools.json --architecture arch.json \
  --trials 5 --seed 1 --rate 2 \
  --views all --sarif --replay --audit-log custody.log \
  --out engagement-01

python -c "
import json; d=json.load(open('engagement-01.json'))
print('story sections:', len(d['story']['sections']))
print('narrative strategies:', len(d['narratives']))
"
```

**Then do the work GLASSCAGE cannot do for you:**
1. Open the **Verification Checklist** in the Assessment Story.
2. Reproduce every `demonstrated` finding by hand using its Reproduce tab.
3. Manually test every `hypothesized` path before reporting it.
4. Record `NOT ASSESSABLE` items as **unmeasured**, never as passing.
5. Quote **runtime coverage (7/13 = 0.54)**, not `coverage_ratio` — see
   [Report Interpretation §6](REPORT_GUIDE.md).

**Final lesson:** GLASSCAGE prioritizes and evidences. It does not adjudicate. Every
finding is a hypothesis until you confirm it.
