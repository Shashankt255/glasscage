# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""Engine: orchestrates the full assessment loop (GLASSCAGE v1.0).

recon(+schema) -> baseline probes -> adaptive/genetic attackers -> MCP + arch
-> enrich -> reproduction + evidence + chain-of-custody -> attack-surface graph
-> coverage -> per-finding CVSS -> aggregate scoring -> trust model -> exploit
chains -> dynamic posture score.
Backward compatible: all v1.0 stages are additive; results dict gains keys.
"""

from __future__ import annotations

from . import agent_probes as _agent  # noqa: F401  (import registers agent probes)
from . import architecture as arch_mod
from . import audit as audit_mod
from . import chain as chain_mod
from . import coverage as coverage_mod
from . import cvss as cvss_mod
from . import evidence as evidence_mod
from . import genetic as genetic_mod
from . import graph as graph_mod
from . import judge as judge_mod
from . import kb as kb_mod
from . import mcp as mcp_mod
from . import mutation as mutation_mod
from . import posture as posture_mod
from . import probes as probes_mod
from . import recon as recon_mod
from . import remediation, repro, report, scoring
from . import trust as trust_mod
from .models import Finding, ReconResult, Severity, Status


def _sev_from_score(s: float) -> Severity:
    if s >= 9:
        return Severity.CRITICAL
    if s >= 7:
        return Severity.HIGH
    if s >= 4:
        return Severity.MEDIUM
    if s >= 2:
        return Severity.LOW
    return Severity.INFO


class Engine:
    def __init__(self, target, selected_probes=None, mcp_manifest=None,
                 use_judge=False, evidence_dir=None, capture_evidence=True,
                 schema_tools=None, adaptive=False, adaptive_budget=8,
                 architecture_answers=None, genetic=False, genetic_budget=40,
                 build_chains=True, trials=1, seed=None, use_aakg=True,
                 store_raw=False):
        self.target = target
        self.probes = selected_probes if selected_probes is not None else probes_mod.all_probes()
        self.mcp_manifest = mcp_manifest
        self.use_judge = use_judge
        self.evidence_dir = evidence_dir
        self.capture_evidence = capture_evidence
        self.schema_tools = schema_tools or []
        self.adaptive = adaptive
        self.adaptive_budget = adaptive_budget
        self.architecture_answers = architecture_answers
        self.genetic = genetic
        self.genetic_budget = genetic_budget
        self.build_chains = build_chains
        self.trials = max(1, trials)
        self.seed = seed
        self.use_aakg = use_aakg
        self.store_raw = store_raw

    def run(self) -> dict:
        recon: ReconResult = recon_mod.run_recon(self.target)
        if self.schema_tools:
            recon.schema_tools = self.schema_tools

        findings: list[Finding] = []
        adaptive_success = False
        # Stage A: determine the target's capability tier (default L0).
        from .tal import TargetCapabilities, Tier
        caps = getattr(self.target, "capabilities", None) or TargetCapabilities()
        target_tier = caps.tier
        from .stats import TrialRunner
        runner = TrialRunner(trials=self.trials, seed=self.seed)

        if recon.reachable:
            for probe in self.probes:
                required = getattr(probe, "min_tier", Tier.L0)
                if target_tier < required:
                    # Stage A: honest NOT ASSESSABLE instead of an invalid pass/fail.
                    na = Finding(
                        probe_name=probe.name, title=(
                            f"NOT ASSESSABLE at {target_tier.name}: requires "
                            f"{required.name} ({required.label})"),
                        owasp_id=probe.owasp_id, category=probe.category,
                        status=Status.NOT_ASSESSABLE, severity=Severity.INFO,
                        confidence=0.0, dimension="informational",
                        assessed_tier=target_tier.name, required_tier=required.name,
                        prompt="(tier-gated)", response_excerpt="")
                    findings.append(na)
                    continue
                try:
                    for f in runner.run(probe, self.target, recon):
                        f.assessed_tier = target_tier.name
                        findings.append(f)
                except Exception as e:  # noqa: BLE001
                    recon.notes.append(f"probe {probe.name} crashed: {e}")
            if self.adaptive:
                try:
                    findings.extend(mutation_mod.run(self.target, self.adaptive_budget,
                                                     use_llm=self.use_judge))
                except Exception as e:  # noqa: BLE001
                    recon.notes.append(f"adaptive attacker crashed: {e}")
            if self.genetic:
                try:
                    findings.extend(genetic_mod.run(self.target, budget=self.genetic_budget,
                                                    use_llm=self.use_judge))
                except Exception as e:  # noqa: BLE001
                    recon.notes.append(f"genetic attacker crashed: {e}")

        if self.use_judge and judge_mod.available():
            for f in findings:
                if f.prompt and f.response_excerpt and f.status in (
                        Status.VULNERABLE, Status.INCONCLUSIVE):
                    v = judge_mod.judge(f.prompt, f.response_excerpt)
                    if v is not None:
                        f.confidence = round((f.confidence + v["confidence"]) / 2, 2)

        if self.mcp_manifest:
            findings.extend(mcp_mod.analyze_manifest(self.mcp_manifest))
        if self.architecture_answers is not None:
            findings.extend(arch_mod.assess(self.architecture_answers))

        adaptive_success = any(
            f.status is Status.VULNERABLE and f.probe_name in ("adaptive-attacker", "genetic-attacker")
            for f in findings)

        # enrichment + custody + evidence
        remediation.apply_all(findings)
        kb_mod.enrich_all(findings)
        from . import taxonomy as taxonomy_mod
        taxonomy_mod.enrich_all(findings)   # D1: CWE/CAPEC/NIST mappings
        repro.build_all(findings, self.target)
        for f in findings:
            if f.prompt or f.response_excerpt:
                f.raw_request = f.raw_request or f.prompt
                f.raw_response = f.raw_response or f.response_excerpt
                f.timestamp = f.timestamp or audit_mod.now_iso()
                f.evidence_hash = audit_mod.sha256(f.raw_request, f.raw_response)
        # P0-1: redact secret-shaped content BEFORE any persistence (evidence/report/
        # json/har). The evidence_hash above proves the original, so chain of custody
        # is preserved. Raw is kept only with explicit consent (store_raw).
        if not self.store_raw:
            from . import redaction as redaction_mod
            redaction_mod.redact_all(findings)
        if self.capture_evidence:
            evidence_mod.capture_all(findings, self.evidence_dir)

        # scoring pipeline
        graph = graph_mod.build_graph(recon, self.mcp_manifest)
        recon.notes.append(graph_mod.summary_line(graph))
        cov = coverage_mod.build(findings, self.probes)
        scope_confirmed = bool([t for t in recon.schema_tools if t.get("side_effect")])
        cvss_mod.apply_all(findings, scope_confirmed=scope_confirmed)
        for f in findings:
            if f.status in (Status.VULNERABLE, Status.INCONCLUSIVE):
                f.severity = _sev_from_score(f.cvss_score)
        summary = scoring.score(findings, recon, cov)

        # v1.0/Stage E: trust model, exploit paths, dynamic posture, blast radius.
        # Stage E5: the AAKG is the single source of truth - posture, coverage, and
        # remediation are computed from the graph when enabled.
        aakg_stats, blast, remediation_priorities = None, None, None
        if self.use_aakg:
            from .aakg import build as aakg_build, paths as aakg_paths
            from .aakg import trust_graph as aakg_trust, blast as aakg_blast
            from .aakg import coverage as aakg_cov, posture as aakg_posture
            from .aakg import remediation as aakg_rem
            graph_obj = aakg_build.build_graph(
                recon, findings, self.mcp_manifest, self.architecture_answers,
                target_tier=target_tier.name, ts=audit_mod.now_iso())
            trust_model = aakg_trust.analyze(graph_obj)
            chains = aakg_paths.build_paths(graph_obj) if self.build_chains else []
            blast = aakg_blast.summary(graph_obj)
            cov = aakg_cov.compute(graph_obj)          # graph-native coverage overrides
            posture = aakg_posture.compute(graph_obj, cov)
            remediation_priorities = aakg_rem.prioritize(graph_obj)
            aakg_stats = graph_obj.stats()
            self._graph_obj = graph_obj
        else:
            trust_model = trust_mod.build(recon, self.mcp_manifest, self.architecture_answers)
            chains = chain_mod.build(findings, trust_model) if self.build_chains else []
            posture = posture_mod.compute(findings, recon, trust_model, chains, cov,
                                          adaptive_success)
        summary["posture_score"] = posture["posture_score"]
        summary["risk_index"] = posture["risk_index"]

        arch_summary = arch_mod.summary(findings) if self.architecture_answers is not None else None
        from . import stats as stats_mod
        stats_report = stats_mod.reproducibility_report(findings)
        na = sum(1 for f in findings if f.status is Status.NOT_ASSESSABLE)
        tier_info = {"target_tier": target_tier.name, "target_tier_label": target_tier.label,
                     "not_assessable": na, "trials": self.trials,
                     "capabilities": caps.to_dict()}
        summary["target_tier"] = target_tier.name
        summary["not_assessable_count"] = na
        summary["trials"] = self.trials
        # Reporting layer (renderer only; consumes the analysis above, adds none).
        narratives, story_obj = None, None
        if self.use_aakg and getattr(self, "_graph_obj", None) is not None:
            from .aakg import narrative as narr_mod, story as story_mod
            _results_for_story = {
                "posture": posture, "coverage": cov, "chains": chains,
                "trust": trust_model, "blast": blast,
                "remediation_priorities": remediation_priorities,
                "recon": recon, "tier": tier_info,
            }
            narratives = narr_mod.build_all(self._graph_obj, chains)
            story_obj = story_mod.build_story(self._graph_obj, _results_for_story,
                                              self.target.name)
            self._narratives, self._story = narratives, story_obj

        return {"recon": recon, "findings": findings, "summary": summary,
                "graph": graph, "coverage": cov, "architecture": arch_summary,
                "trust": trust_model, "chains": chains, "posture": posture,
                "stats": stats_report, "tier": tier_info,
                "aakg": aakg_stats, "blast": blast,
                "remediation_priorities": remediation_priorities,
                "narratives": narratives, "story": story_obj}

    def report_markdown(self, results: dict) -> str:
        # Stage E5: graph-native report when the AAKG is available.
        graph_obj = getattr(self, "_graph_obj", None)
        if self.use_aakg and graph_obj is not None:
            from .aakg import report as aakg_report
            return aakg_report.to_markdown(graph_obj, results, self.target.name)
        return report.to_markdown(self.target.name, results["recon"], results["findings"],
                                  results["summary"], results.get("graph"),
                                  results.get("coverage"), results.get("architecture"),
                                  results.get("trust"), results.get("chains"),
                                  results.get("posture"))

    def report_html(self, results: dict) -> str:
        return report.to_html(self.target.name, results["recon"], results["findings"],
                              results["summary"], results.get("graph"),
                              results.get("coverage"), results.get("architecture"),
                              results.get("trust"), results.get("chains"),
                              results.get("posture"),
                              narratives=results.get("narratives"),
                              story=results.get("story"))
