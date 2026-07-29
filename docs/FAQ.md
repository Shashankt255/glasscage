# FAQ

**Q. Has GLASSCAGE been tested against real language models?**
Not independently, as of rc3. All agentic "demonstrated" results come from a built-in
deterministic reference harness. Treat findings as hypotheses. See [VALIDATION.md](VALIDATION.md).

**Q. Why only 21 probes when garak has 120+?**
Different goals. garak is a probe library optimised for breadth; GLASSCAGE is a
consequence engine that models what a finding *reaches*. Use garak for breadth; use
GLASSCAGE for reachability and evidence-gated narratives. They compose — GLASSCAGE can
ingest garak output.

**Q. Is the Indicative Risk Index a real risk score?**
No. It is an **uncalibrated heuristic**, labelled `[Estimated]` in every report. Use it
to prioritize findings within one target, never as an absolute or cross-target measure.

**Q. My coverage says 0.85 / 0.54 — which is right?**
Quote **0.54** (runtime-tested, 7/13 categories). The higher number counts
questionnaire and configuration-review findings as "tested", which overstates runtime
testing. This is a known accounting defect. See [REPORT_GUIDE.md](REPORT_GUIDE.md).

**Q. Does GLASSCAGE test MCP servers?**
It reviews MCP **manifests** statically (tool poisoning, rug-pulls, SSRF-prone params).
It **never contacts an MCP server**. Runtime MCP is Roadmap.

**Q. Does it orchestrate garak / PyRIT / Promptfoo?**
It **parses their output**. Genuine tool output has not been ingested at scale
(Pending External Validation). Run `--validate-adapters` for the honest status.

**Q. Are the narratives written by an LLM?**
No. They are a deterministic renderer over the graph. Every clause cites node/edge/
evidence ids you can verify in the JSON. Strategies with no matching path print "Not
demonstrated." and stop.

**Q. What does NOT ASSESSABLE mean?**
The probe needed a capability the target does not expose (e.g. a planner trace on an L0
endpoint). It means **unmeasured**, not safe.

**Q. Is it safe to share a report?**
Default artifacts are redacted, but redaction is pattern-based and may miss novel secret
formats. **Review before sharing.** Never share `--store-raw` artifacts outside a
controlled environment.

**Q. Can plugins harm my machine?**
Yes — plugins are arbitrary, unsandboxed code that runs with your privileges. Only load
code you trust. See [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md).

**Q. Which Python versions are supported?**
3.10 and newer.

**Q. Is there a `--version` flag?**
Not in rc3. Use `python -c "import glasscage; print(glasscage.__version__)"`.

**Q. What is `refagent` / the harness?**
A deterministic L2 reference target for demos and tests. It is a **fixture**, not
evidence about any real system.
