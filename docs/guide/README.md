# GLASSCAGE Documentation — 1.0.0rc3

> **Release Candidate.** Every document below marks feature maturity
> (**Implemented** · **Experimental** · **Pending External Validation** · **Roadmap**)
> and states what GLASSCAGE *cannot* prove. Findings are hypotheses to confirm.

| # | Document | Audience |
|---|---|---|
| 1 | [User Guide](USER_GUIDE.md) | everyone — start here; core concepts, **maturity matrix**, **known limitations** |
| 2 | [Operator Manual](OPERATOR_MANUAL.md) | assessors — flags, authorization, evidence handling, engagement flow |
| 3 | [Administrator Guide](ADMINISTRATOR_GUIDE.md) | platform/security teams — deployment models, artifact policy, plugin governance, supply chain |
| 4 | [Developer Guide](DEVELOPER_GUIDE.md) | contributors — architecture rules, extension points, **known defects** |
| 5 | [API Reference](API_REFERENCE.md) | integrators — stable surface, per-symbol maturity |
| 6 | [Assessment Playbooks](ASSESSMENT_PLAYBOOKS.md) | consultants — 8 operator recipes; *methodology, not a code subsystem* |
| 7 | [Report Interpretation Guide](REPORT_INTERPRETATION.md) | readers of reports — how to read output, what you may **not** conclude |
| 8 | [Tutorials](TUTORIALS.md) | new users — 10 hands-on walkthroughs (every command verified against this release) |

## Three things to know before using GLASSCAGE

1. **Efficacy is unvalidated.** GLASSCAGE has never been evaluated against a real
   hosted model or agent framework. All agentic "demonstrated" results come from a
   built-in deterministic harness authored alongside the probes. **Treat every finding
   as a hypothesis.**
2. **`coverage_ratio` is currently overstated.** It counts questionnaire and
   configuration-review findings as "tested". **True runtime coverage is 7/13 = 0.54**;
   the tool may report `0.85`. Quote 0.54. (P0 blocker.)
3. **The Indicative Risk Index is an uncalibrated heuristic.** Use it to prioritize
   within one target, never as an absolute or comparable risk measure.

## Related
`../THREAT_MODEL.md` · `../EVIDENCE_CONFIDENCE.md` · `../NARRATIVES.md` ·
`../PLUGIN_SDK.md` · `../GRAPH_MODEL.md` · `../../SECURITY.md` · `../../VERSIONING.md`
