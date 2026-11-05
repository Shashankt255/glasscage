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
from . import system_prompt_review as spr_mod
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
from . import remediation, report, repro, scoring
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
                 architecture_answers=None, model_card=None,
                 system_prompt_text=None,
                 genetic=False, genetic_budget=40,
                 build_chains=True, trials=1, seed=None, use_aakg=True,
                 store_raw=False, surface=None):
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
        self.model_card = model_card
        self.system_prompt_text = system_prompt_text
        self.genetic = genetic
        self.genetic_budget = genetic_budget
        self.build_chains = build_chains
        self.trials = max(1, trials)
        self.seed = seed
        self.use_aakg = use_aakg
        self.store_raw = store_raw
        # ADR 0002: optional Surface/ApplicationTarget to route probe traffic through.
        # None keeps the pre-existing single-target path exactly as it was.
        self.surface = surface
        # ADR 0029: categories that actually delivered a payload on this run. Populated
        # from exchange records in `_assess_surface`, never from probes or findings.
        self._delivered_categories: set[str] = set()

    def _report_identity(self) -> str:
        """What the report header names (ADR 0011, discharging ADR 0005's deferral).

        An application-level run names the application; a single-target run names the
        target, exactly as before. Per-finding provenance stays exact via `surface_id`
        and reproduction steps, so the header names the assessment subject while findings
        name their endpoints.
        """
        from .targets.application import ApplicationTarget
        if isinstance(self.surface, ApplicationTarget) and self.surface.base_url:
            return self.surface.base_url
        return self.target.name

    def _probe_targets(self):
        """Every object probes talk to, validated before any traffic (ADR 0011).

        Order is exactly `chat_surfaces_of()`'s output (INV-1): registration order,
        deduplicated, never sorted or re-ordered here. Every surface is validated up
        front so an ownership or governance refusal aborts the run before any surface is
        probed, preserving ADR 0005 across N surfaces.

        Capability tier and reproduction read these objects (ADR 0005), so they follow the
        driven target. Custody keeps reading `self.target`.
        """
        if self.surface is None:
            return [self.target]
        from .targets.compat import SurfaceTarget, chat_surfaces_of, verify_application_scope
        surfaces = chat_surfaces_of(self.surface)
        verify_application_scope(self.surface, surfaces)
        return [SurfaceTarget(s, origin=self.target) for s in surfaces]

    def _assess_surface(self, probe_target, recon, runner, target_tier, driven_kind,
                        out, Tier):
        """Run every probe and attacker against one surface (ADR 0011).

        Body unchanged from the single-surface loop; only the collection target and the
        recon it reads are per-surface. Attacker budgets are PER_SURFACE (INV-3).
        """
        from .targets.surface import SurfaceKind
        for probe in self.probes:
            # ADR 0006: applicability is checked BEFORE capability tier - being unable to
            # drive a surface at all is more fundamental than lacking a capability on it.
            # Probes that declare nothing are read as CHAT-only, so plugins keep working.
            kinds = getattr(probe, "surface_kinds", (SurfaceKind.CHAT,))
            if driven_kind not in kinds:
                out.append(Finding(
                    probe_name=probe.name, title=(
                        f"NOT ASSESSABLE on a {driven_kind.value} surface: probe "
                        f"drives {', '.join(k.value for k in kinds)}"),
                    owasp_id=probe.owasp_id, category=probe.category,
                    status=Status.NOT_ASSESSABLE, severity=Severity.INFO,
                    confidence=0.0, dimension="informational",
                    assessed_tier=target_tier.name,
                    required_tier=getattr(probe, "min_tier", Tier.L0).name,
                    prompt="(surface-gated)", response_excerpt=""))
                continue
            required = getattr(probe, "min_tier", Tier.L0)
            if target_tier < required:
                # Stage A: honest NOT ASSESSABLE instead of an invalid pass/fail.
                out.append(Finding(
                    probe_name=probe.name, title=(
                        f"NOT ASSESSABLE at {target_tier.name}: requires "
                        f"{required.name} ({required.label})"),
                    owasp_id=probe.owasp_id, category=probe.category,
                    status=Status.NOT_ASSESSABLE, severity=Severity.INFO,
                    confidence=0.0, dimension="informational",
                    assessed_tier=target_tier.name, required_tier=required.name,
                    prompt="(tier-gated)", response_excerpt=""))
                continue
            # ADR 0029: bracket the probe with the transport's own exchange log. Only the
            # transports append here, and only after a response exists, so the slice below
            # is exactly what this probe put on the wire. A probe that raises before
            # sending adds nothing; a scope refusal raises inside `send` before any record
            # is written; a refused connection records `status` 0. Read after the
            # try/except so a probe that crashes *after* delivering still counts what it
            # actually delivered.
            _exch = getattr(probe_target, "exchanges", None)
            _before = len(_exch) if _exch is not None else 0
            try:
                for f in runner.run(probe, probe_target, recon):
                    f.assessed_tier = target_tier.name
                    out.append(f)
            except Exception as e:
                recon.notes.append(f"probe {probe.name} crashed: {e}")
            if _exch is not None and any(coverage_mod.is_delivered(x)
                                         for x in _exch[_before:]):
                self._delivered_categories.add(probe.owasp_id)
        # ADR 0017: the attackers are prompt-shaped - both drive through `target.send()` -
        # so they are CHAT-only, exactly as a probe declaring `surface_kinds = (CHAT,)`.
        # They were invoked regardless of the driven kind, which on a REST surface meant a
        # refused PromptAction, a finding carrying a chat-shaped prompt, and an
        # AttributeError out of reproduction. Gated here rather than in the attacker
        # modules so the applicability rule stays in the one place ADR 0006 put it.
        if self.adaptive:
            if driven_kind is not SurfaceKind.CHAT:
                out.append(self._surface_gated(
                    "adaptive-attacker", "LLM01", "Adaptive Mutation Attack",
                    driven_kind, target_tier))
            else:
                try:
                    out.extend(mutation_mod.run(probe_target, self.adaptive_budget,
                                                use_llm=self.use_judge))
                except Exception as e:
                    recon.notes.append(f"adaptive attacker crashed: {e}")
        if self.genetic:
            if driven_kind is not SurfaceKind.CHAT:
                out.append(self._surface_gated(
                    "genetic-attacker", "LLM01", "Genetic Attack Engine",
                    driven_kind, target_tier))
            else:
                try:
                    out.extend(genetic_mod.run(probe_target, budget=self.genetic_budget,
                                               use_llm=self.use_judge))
                except Exception as e:
                    recon.notes.append(f"genetic attacker crashed: {e}")

    @staticmethod
    def _surface_gated(name, owasp_id, category, driven_kind, target_tier) -> Finding:
        """The ADR 0006 NOT ASSESSABLE shape, for an attacker rather than a probe.

        Same fields and the same `(surface-gated)` prompt the probe loop above emits, so
        reproduction, reporting and the graph treat it identically. Reported rather than
        skipped silently: an operator who passed `--adaptive` must be able to see that it
        did not run.
        """
        return Finding(
            probe_name=name, title=(
                f"NOT ASSESSABLE on a {driven_kind.value} surface: attacker "
                "drives chat"),
            owasp_id=owasp_id, category=category,
            status=Status.NOT_ASSESSABLE, severity=Severity.INFO,
            confidence=0.0, dimension="informational",
            assessed_tier=target_tier.name, required_tier=target_tier.name,
            prompt="(surface-gated)", response_excerpt="")

    @staticmethod
    def _merge_recons(recons):
        """Run-level recon (ADR 0011). One surface returns its own object unchanged.

        `reachable` is true if any surface was; list fields are order-preserving unions;
        notes concatenate so every unreachable surface stays named (INV-4). `schema_tools`
        is run-level and identical on each, so the first is authoritative.
        """
        if len(recons) == 1:
            return recons[0]
        merged = ReconResult()
        merged.reachable = any(r.reachable for r in recons)
        for field_name in ("model_hints", "guardrail_signals", "tool_surface", "notes"):
            seen: dict = {}
            for r in recons:
                for v in getattr(r, field_name):
                    seen.setdefault(v, None)
            setattr(merged, field_name, list(seen))
        merged.schema_tools = recons[0].schema_tools if recons else []
        merged.refusal_style = next((r.refusal_style for r in recons
                                     if r.refusal_style is not None), None)
        merged.latency_ms = next((r.latency_ms for r in recons
                                  if r.latency_ms is not None), None)
        return merged

    @staticmethod
    def _run_tier(probe_targets, TargetCapabilities):
        """Run-level capability tier: the weakest surface's (ADR 0011).

        A run is only as assessable as its least capable surface. One surface returns its
        own tier, so the legacy path is unchanged.
        """
        pairs = [(getattr(pt, "capabilities", None) or TargetCapabilities())
                 for pt in probe_targets]
        weakest = min(pairs, key=lambda c: c.tier)
        return weakest.tier, weakest

    def run(self) -> dict:
        # ADR 0011: every resolved CHAT surface is driven, in `chat_surfaces_of()` order,
        # all validated before any traffic.
        probe_targets = self._probe_targets()
        self._delivered_categories = set()   # ADR 0029: per-run, reset on every run()

        from .stats import TrialRunner
        from .tal import TargetCapabilities, Tier
        from .targets.surface import SurfaceKind
        runner = TrialRunner(trials=self.trials, seed=self.seed)

        findings: list[Finding] = []
        adaptive_success = False
        surface_recons: list[ReconResult] = []
        surface_batches: list[tuple] = []   # (probe_target, findings produced on it)

        for probe_target in probe_targets:
            # ADR 0011: one ReconResult per surface. Probes read `tool_surface` and
            # `model_hints` while assessing and three derive findings entirely from
            # recon, so a merged fingerprint would let one endpoint drive another's
            # verdicts. `schema_tools` is run-level (INV-2) and identical for each.
            recon: ReconResult = recon_mod.run_recon(probe_target)
            if self.schema_tools:
                recon.schema_tools = self.schema_tools
            surface_recons.append(recon)

            # Stage A: capability tier of the target actually driven (ADR 0005).
            caps = getattr(probe_target, "capabilities", None) or TargetCapabilities()
            target_tier = caps.tier
            # ADR 0006: which surface kind is being driven. Legacy runs drive a single
            # chat endpoint, so CHAT is the default when no surface is bound.
            _driven_surface = getattr(probe_target, "surface", None)
            driven_kind = (_driven_surface.kind if _driven_surface is not None
                           else SurfaceKind.CHAT)

            batch: list[Finding] = []
            if not recon.reachable and _driven_surface is not None:
                recon.notes.append(f"surface {_driven_surface.id}: not reachable")
            if recon.reachable:
                self._assess_surface(probe_target, recon, runner, target_tier,
                                     driven_kind, batch, Tier)
            # ADR 0004/0011: attribute this surface's findings to the surface that
            # produced them, before the next surface runs.
            if _driven_surface is not None:
                for f in batch:
                    f.surface_id = _driven_surface.id
            surface_batches.append((probe_target, batch))
            findings.extend(batch)

        # ADR 0011: run-level recon. A single surface yields its own object unchanged, so
        # the legacy path is byte-identical.
        recon = self._merge_recons(surface_recons)
        target_tier, caps = self._run_tier(probe_targets, TargetCapabilities)

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
        if self.model_card is not None:
            from . import model_card_review as mcr_mod
            findings.extend(mcr_mod.analyze(self.model_card))
        if self.system_prompt_text:
            findings.extend(spr_mod.analyze(self.system_prompt_text))

        adaptive_success = any(
            f.status is Status.VULNERABLE and f.probe_name in ("adaptive-attacker", "genetic-attacker")
            for f in findings)

        # enrichment + custody + evidence
        remediation.apply_all(findings)
        kb_mod.enrich_all(findings)
        from . import taxonomy as taxonomy_mod
        taxonomy_mod.enrich_all(findings)   # D1: CWE/CAPEC/NIST mappings
        # ADR 0005/0011: each surface's findings cite the target that produced them.
        # `build_all` skips findings that already carry steps, so the final call covers
        # MCP and architecture evidence only.
        for _pt, _batch in surface_batches:
            repro.build_all(_batch, _pt)
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
            from .aakg import blast as aakg_blast
            from .aakg import build as aakg_build
            from .aakg import coverage as aakg_cov
            from .aakg import paths as aakg_paths
            from .aakg import posture as aakg_posture
            from .aakg import remediation as aakg_rem
            from .aakg import trust_graph as aakg_trust
            graph_obj = aakg_build.build_graph(
                recon, findings, self.mcp_manifest, self.architecture_answers,
                target_tier=target_tier.name, ts=audit_mod.now_iso())
            trust_model = aakg_trust.analyze(graph_obj)
            chains = aakg_paths.build_paths(graph_obj) if self.build_chains else []
            blast = aakg_blast.summary(graph_obj)
            _techniques_run = cov["techniques_run"]
            cov = aakg_cov.compute(graph_obj)          # graph-native coverage overrides
            # ADR 0011: `techniques_run` counts distinct techniques executed - a property
            # of the assessment process, not of the evidence graph. The graph excludes
            # passed findings, so it can only know which techniques produced graph-eligible
            # evidence, never how many ran. Preserve the run-level count computed above.
            cov["techniques_run"] = _techniques_run
            posture = aakg_posture.compute(graph_obj, cov)
            remediation_priorities = aakg_rem.prioritize(graph_obj)
            aakg_stats = graph_obj.stats()
            self._graph_obj = graph_obj
        else:
            trust_model = trust_mod.build(recon, self.mcp_manifest, self.architecture_answers)
            chains = chain_mod.build(findings, trust_model) if self.build_chains else []
            posture = posture_mod.compute(findings, recon, trust_model, chains, cov,
                                          adaptive_success)
        # ADR 0029: attached AFTER posture is computed, so the measurement cannot reach
        # the score even accidentally - `posture_score` and `risk_index` are already fixed
        # by this line. Attached on both branches: a run-derived measurement is meaningful
        # with or without the graph.
        _custody_ok = all(
            len(getattr(t, "exchanges", ()) or ()) == len(getattr(t.audit, "entries", ()) or ())
            for t in probe_targets if getattr(t, "audit", None) is not None)
        cov["run_measured_coverage"] = coverage_mod.run_measured(
            self._delivered_categories, custody_complete=_custody_ok)
        cov["run_coverage_ratio"] = cov["run_measured_coverage"]["run_coverage_ratio"]

        summary["posture_score"] = posture["posture_score"]
        summary["risk_index"] = posture["risk_index"]

        arch_summary = arch_mod.summary(findings) if self.architecture_answers is not None else None
        from . import stats as stats_mod
        stats_report = stats_mod.reproducibility_report(findings)
        na = sum(1 for f in findings if f.status is Status.NOT_ASSESSABLE)
        # ADR 0011: attacker budgets are PER_SURFACE (INV-3); report the effective total
        # so the cost of driving N surfaces is visible rather than discovered.
        n_surfaces = len(probe_targets)
        tier_info = {"target_tier": target_tier.name, "target_tier_label": target_tier.label,
                     "not_assessable": na, "trials": self.trials,
                     "capabilities": caps.to_dict(),
                     "surfaces_driven": n_surfaces,
                     "attacker_budget_contract": "PER_SURFACE",
                     "effective_adaptive_budget": (self.adaptive_budget * n_surfaces
                                                   if self.adaptive else 0),
                     "effective_genetic_budget": (self.genetic_budget * n_surfaces
                                                  if self.genetic else 0)}
        summary["target_tier"] = target_tier.name
        summary["not_assessable_count"] = na
        summary["trials"] = self.trials
        # Reporting layer (renderer only; consumes the analysis above, adds none).
        narratives, story_obj = None, None
        if self.use_aakg and getattr(self, "_graph_obj", None) is not None:
            from .aakg import narrative as narr_mod
            from .aakg import story as story_mod
            _results_for_story = {
                "posture": posture, "coverage": cov, "chains": chains,
                "trust": trust_model, "blast": blast,
                "remediation_priorities": remediation_priorities,
                "recon": recon, "tier": tier_info,
            }
            narratives = narr_mod.build_all(self._graph_obj, chains)
            story_obj = story_mod.build_story(self._graph_obj, _results_for_story,
                                              self._report_identity())
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
            return aakg_report.to_markdown(graph_obj, results, self._report_identity())
        return report.to_markdown(self._report_identity(), results["recon"], results["findings"],
                                  results["summary"], results.get("graph"),
                                  results.get("coverage"), results.get("architecture"),
                                  results.get("trust"), results.get("chains"),
                                  results.get("posture"))

    def report_html(self, results: dict) -> str:
        return report.to_html(self._report_identity(), results["recon"], results["findings"],
                              results["summary"], results.get("graph"),
                              results.get("coverage"), results.get("architecture"),
                              results.get("trust"), results.get("chains"),
                              results.get("posture"),
                              narratives=results.get("narratives"),
                              story=results.get("story"))
