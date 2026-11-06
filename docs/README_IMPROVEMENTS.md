# README Improvements (release audit)

## Problems with the current README
1. **It reads as a stacked changelog**, not a front door. A first-time visitor sees
   stage-by-stage dev notes (rc3, then E5, then earlier stages) rather than "what is
   this / how do I run it / what are its limits".
2. **Overstated claims a skeptic will catch:**
   - "orchestrate/benchmark garak/PyRIT/Promptfoo" — these are **Pending External
     Validation** (no genuine tool output ingested). Current text implies working
     orchestration.
   - Coverage is presented without the runtime-vs-questionnaire caveat (true runtime
     coverage 7/13 = 0.54, not the headline `coverage_ratio`).
   - "Measured: P0.97 R0.91 F1.94" — true, but must be labelled Experimental corpus
     (n=109, single annotator) or it reads as a validated efficacy claim.
3. **No badges, no one-command quickstart at the top, no limitations section.**
4. **Placeholder URLs** inherited from `pyproject.toml` (`example.org`).

## Recommended replacement for the top of README.md
(Keep the historical stage notes lower down under a "Development history" heading.)


# GLASSCAGE

> Builds an evidence graph of what an attacker can reach in your LLM or agentic
> application — and refuses to claim more than it proved.

**Runtime coverage: 7 of 13 OWASP LLM categories** (see limitations). **Not a garak
replacement** — garak has more probes; use both. Zero runtime dependencies. 189 tests.

⚠️ **Authorized use only.** Run only against systems you own or have written permission
to test.

## Install
```bash
pip install .            # from source (Python >= 3.10)
```

## Try it in 30 seconds (no target needed)
```bash
python -m glasscage --demo --out report          # built-in mock (L0)
python -m glasscage --harness --views all --out report   # built-in L2 reference agent
```
Open `report.md`. Full walkthrough: `docs/FIRST_RUN.md`.

## What it does
Probes an authorized target, records evidence, and builds an **AI Attack Knowledge
Graph** from which it derives attack paths, trust boundaries, blast radius, coverage,
remediation, and **evidence-gated attack narratives** — every claim cited to graph
nodes/edges and clamped to its weakest hop.

## Honest limitations (read before relying on output)
- **Efficacy is not independently validated** — agentic results come from a built-in
  deterministic harness. Treat findings as hypotheses.
- **Coverage accounting overstates runtime testing** — quote 7/13 (0.54), not
  `coverage_ratio`.
- **MCP support is configuration review only** — no MCP server is contacted.
- **External-tool adapters are Pending External Validation.**
- **The risk index is an uncalibrated heuristic.**

Full detail: `docs/USER_GUIDE.md` §6 and `docs/VALIDATION.md`.

## Documentation
Start at [`README.md`](README.md).


## After pasting, also:
- Add badges once CI/URLs are real (build status, license, python versions).
- Replace `example.org` links.
- Move the rc3/E-stage notes under `## Development history`.
