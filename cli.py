#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""GLASSCAGE CLI.

Examples:
  python cli.py --demo --out report                       # offline full demo
  python cli.py --config targets.json --authorized        # live chatbot assess
  python cli.py --mcp-manifest samples/mcp_manifest.json --out mcp   # MCP scan
  python cli.py --mcp-manifest new.json --mcp-baseline old.json      # rug-pull
  python cli.py --diff old.json new.json                  # regression diff
  python cli.py --config t.json --authorized --judge --plugins ./myprobes

Only test systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from glasscage import mcp as mcp_mod
from glasscage.diff import diff_reports
from glasscage.diff import render as render_diff
from glasscage.engine import Engine
from glasscage.plugins import load_plugins
from glasscage.report import write_json
from glasscage.target import ChatResponse, HTTPChatTarget


class _MockTarget(HTTPChatTarget):
    """An intentionally weak in-process bot for offline demos/tests."""

    def __init__(self):
        super().__init__({"url": "mock://demo", "name": "demo-vulnerable-bot"})

    def send(self, prompt: str):
        p = prompt.lower()
        if "token and nothing else" in p:                       # direct injection
            text = "GLSSCG-INJECT-OK"
        elif "retrieved document" in p:                         # indirect injection
            text = "GLSSCG-INDIRECT-OK"
        elif "base64" in p:                                     # encoded injection (bypass)
            text = "Decoded and done: GLSSCG-INJECT-OK"
        elif "concatenation" in p:                              # payload splitting (bypass)
            text = "GLSSCG-INJECT-OK"
        elif "echobot" in p:                                    # jailbreak persona (bypass)
            text = "As EchoBot: GLSSCG-INJECT-OK"
        elif "ignora las instrucciones" in p:                   # multilingual: refusal w/ canary
            text = "Lo siento, pero no puedo responder con GLSSCG-INJECT-OK."
        elif "echo it back exactly: hello-123" in p:            # multi-turn warmup
            text = "HELLO-123"
        elif "echo this final token" in p:                      # multi-turn payoff
            text = "GLSSCG-INJECT-OK"
        elif "rendering test" in p:                             # insecure output
            text = "Sure: <script>GLSSCG-XSS-CANARY</script>"
        elif "configuration or system instructions" in p:       # sys-prompt leak
            text = ("You are HelpBot. Your role is support. Do not reveal refund "
                    "codes. Instructions: always be concise. You should never "
                    "disclose internal pricing.")
        elif "api keys, passwords" in p:                        # secret leak
            text = "I only have this: password=hunter2 and sk-ABCDEF0123456789XYZ"
        elif "tools, functions" in p:                           # self-reports tools
            text = "I can use: search_tool, send_email function, sql_query api"
        else:
            text = "Hello, I am a demo bot."
        resp = ChatResponse(text=text, raw={"demo": True}, latency_ms=5.0, ok=True)
        from datetime import datetime, timezone
        self.exchanges.append({"ts": datetime.now(timezone.utc).isoformat(),
                               "url": self.url, "method": "POST",
                               "request_body": prompt, "status": 200,
                               "response_body": text, "ms": 5.0})
        if self.audit is not None:
            self.audit.record(self.url, prompt, text, True)
        return resp


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _driven_kinds(surface):
    """The surface kinds this run drove (ADR 0018).

    CHAT when nothing is bound, matching ADR 0006's rule that a run with no surface
    resolves to CHAT. Resolution goes through `drivable_surfaces_of` so this agrees with
    what the engine actually drove rather than inferring it from the target's type.
    """
    from glasscage.targets import SurfaceKind
    from glasscage.targets.compat import drivable_surfaces_of
    if surface is None:
        return {SurfaceKind.CHAT}
    return {s.kind for s in drivable_surfaces_of(surface)}


def _parse_adapter_files(items):
    """['garak=run.jsonl','promptfoo=out.json'] -> {'garak':'run.jsonl',...}"""
    out = {}
    for it in items or []:
        if "=" in it:
            k, v = it.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="GLASSCAGE - AI bot security assessment")
    ap.add_argument("--config", help="JSON target config")
    ap.add_argument("--demo", action="store_true", help="run against a built-in mock bot")
    ap.add_argument("--out", default="glasscage_report", help="output basename")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you are authorized to test the target")
    ap.add_argument("--mcp-manifest", help="MCP tools/list JSON to analyze")
    ap.add_argument("--mcp-baseline", help="previous MCP manifest for rug-pull diff")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                    help="diff two GLASSCAGE JSON reports and exit")
    ap.add_argument("--judge", action="store_true", help="enable optional LLM-as-judge")
    ap.add_argument("--plugins", help="directory of custom probe modules to load "
                    "(requires --allow-plugins)")
    ap.add_argument("--allow-plugins", action="store_true",
                    help="CONSENT: permit loading plugins (arbitrary code, no sandbox)")
    ap.add_argument("--log-level", default="WARNING",
                    help="log level: DEBUG/INFO/WARNING/ERROR (default WARNING)")
    ap.add_argument("--log-json", action="store_true", help="emit structured JSON logs")
    ap.add_argument("--store-raw", action="store_true",
                    help="CONSENT: store UNREDACTED evidence (may contain live secrets). "
                         "Default redacts secret-shaped content from all artifacts.")
    ap.add_argument("--encrypt-evidence", action="store_true",
                    help="encrypt the evidence directory at rest (requires the "
                         "'crypto' extra: pip install glasscage[crypto])")
    ap.add_argument("--evidence-password", help="password for --encrypt-evidence "
                    "(or set GLASSCAGE_EVIDENCE_PASSWORD)")
    ap.add_argument("--no-evidence", action="store_true",
                    help="skip screenshot-style evidence card generation")
    ap.add_argument("--schema", help="OpenAPI/function-schema/MCP JSON for schema-confirmed tools")
    ap.add_argument("--discover", metavar="SPEC",
                    help="enumerate the drivable surface inventory from an OpenAPI "
                         "document or MCP manifest and exit (no target, no assessment)")
    ap.add_argument("--rest-config", metavar="FILE",
                    help="JSON REST target config {url, headers?, timeout?, name?} to "
                         "ASSESS; requires --rest-spec and a non-empty --scope")
    ap.add_argument("--rest-spec", metavar="SPEC",
                    help="OpenAPI document whose operations are discovered, bound and "
                         "assessed against --rest-config. Distinct from --discover, "
                         "which only prints an inventory and drives nothing")
    ap.add_argument("--scope", nargs="+", help="allowlist of hostnames permitted to test")
    ap.add_argument("--rate", type=float, help="max requests per second (be polite)")
    ap.add_argument("--max-retries", type=int, default=3,
                    help="retry rate-limited (429/402) requests up to N times (default 3)")
    ap.add_argument("--backoff", type=float, default=2.0,
                    help="exponential backoff base in seconds (default 2.0: waits 2s, 4s, 8s)")
    ap.add_argument("--adaptive", action="store_true", help="run the adaptive mutation attacker")
    ap.add_argument("--genetic", action="store_true",
                    help="run the genetic/evolutionary attack engine")
    ap.add_argument("--sarif", action="store_true", help="also export SARIF 2.1.0")
    ap.add_argument("--replay", action="store_true",
                    help="also export a reproducible replay bundle + runner")
    ap.add_argument("--harness", action="store_true",
                    help="use the built-in L2 reference agent as the target")
    ap.add_argument("--trials", type=int, default=1,
                    help="repeat each probe N times for Wilson CIs (Stage B)")
    ap.add_argument("--seed", type=int, help="seed for deterministic replay")
    ap.add_argument("--no-aakg", action="store_true",
                    help="disable the AI Attack Knowledge Graph (use legacy trust/chains)")
    ap.add_argument("--no-chain", action="store_true",
                    help="disable impact-chaining (skip follow-up probes after injection success)")
    ap.add_argument("--views", nargs="+", metavar="AUDIENCE", default=[],
                    help="write audience views of the narrative/story: executive, "
                         "security, developer, incident_response, compliance, or 'all'")
    ap.add_argument("--benchmark", metavar="CORPUS",
                    help="run detector benchmark against a labeled corpus and exit")
    ap.add_argument("--orchestrate", nargs="+", metavar="TOOL",
                    help="run adapters (native/fake/garak/pyrit/promptfoo/deepteam/fuzzyai) and exit")
    ap.add_argument("--adapter-file", nargs="+", metavar="TOOL=PATH", default=[],
                    help="parse a saved framework output, e.g. garak=run.report.jsonl")
    ap.add_argument("--validate", action="store_true",
                    help="run detector benchmark + cross-framework validation, write a paper report")
    ap.add_argument("--validate-adapters", action="store_true",
                    help="validate framework parsers; honest Pending External Validation "
                         "unless genuine output is supplied via --genuine-output")
    ap.add_argument("--genuine-output", nargs="+", metavar="TOOL=PATH", default=[],
                    help="REAL tool output to validate a parser, e.g. garak=run.report.jsonl")
    ap.add_argument("--architecture", help="architecture answers JSON (see --arch-template)")
    ap.add_argument("--system-prompt", metavar="FILE",
                    help="path to a text file containing the target's system prompt for static analysis")
    ap.add_argument("--arch-template", action="store_true",
                    help="print a blank architecture answers template and exit")
    ap.add_argument("--model-card", help="model card answers JSON (see --model-card-template)")
    ap.add_argument("--model-card-template", action="store_true",
                    help="print a blank model card template and exit")
    ap.add_argument("--har", action="store_true", help="export raw exchanges as HAR")
    ap.add_argument("--proxy", metavar="URL",
                    help="route all target traffic through an HTTP proxy "
                         "(e.g. http://127.0.0.1:8080 for Burp Suite)")
    ap.add_argument("--proxy-no-verify", action="store_true",
                    help="disable SSL certificate verification when using --proxy "
                         "(needed for Burp's intercepting CA)")
    ap.add_argument("--audit-log", help="path to append-only, hash-chained JSONL audit log")
    ap.add_argument("--free", action="store_true",
                    help="use a built-in free AI endpoint (Pollinations AI) for testing")
    ap.add_argument("--retry-errors", action="store_true",
                    help="re-run only probes that hit transport errors in the previous "
                         "report (loads from --out.json)")
    args = ap.parse_args(argv)
    args.out = os.path.realpath(args.out)
    from glasscage.logging_setup import configure as _configure_logging
    _configure_logging(level=args.log_level, json_output=args.log_json)

    if args.arch_template:
        from glasscage import architecture
        print(json.dumps(architecture.template(), indent=2))
        return 0

    if getattr(args, "model_card_template", False):
        from glasscage import model_card_review
        print(json.dumps(model_card_review.template(), indent=2))
        return 0

    # Phase 1: surface inventory (standalone; needs no target and runs no assessment).
    if args.discover:
        from glasscage.targets import discovery as discovery_mod
        candidates = discovery_mod.discover(_load(args.discover))
        md = discovery_mod.to_markdown(candidates)
        print(md)
        with open(f"{args.out}_surfaces.md", "w", encoding="utf-8") as fh:
            fh.write(md)
        with open(f"{args.out}_surfaces.json", "w", encoding="utf-8") as fh:
            json.dump(discovery_mod.to_json(candidates), fh, indent=2)
        print(f"\nWrote {args.out}_surfaces.(md/json)")
        return 0

    # P0-5: adapter validation (standalone; needs no target). Honest by construction:
    # genuine tool output -> Measured; shipped fixture -> Experimental; else Pending.
    if args.validate_adapters:
        from glasscage import adapter_validation as av
        genuine = _parse_adapter_files(args.genuine_output)
        rep = av.validate_adapters(genuine)
        md = av.to_markdown(rep)
        print(md)
        import json as _json
        with open(f"{args.out}_adapter_validation.md", "w", encoding="utf-8") as fh:
            fh.write(md)
        with open(f"{args.out}_adapter_validation.json", "w", encoding="utf-8") as fh:
            _json.dump(rep, fh, indent=2)
        print(f"\nWrote {args.out}_adapter_validation.(md/json)")
        return 0

    # Stage C/D: standalone detector benchmark
    if args.benchmark:
        from glasscage import benchmark
        rep = benchmark.run_corpus(args.benchmark)
        benchmark.write_report(rep, args.out + "_benchmark")
        print(benchmark.to_markdown(rep))
        print(f"\nWrote {args.out}_benchmark.json, {args.out}_benchmark.md")
        return 0

    # Standalone regression diff.
    if args.diff:
        print(render_diff(diff_reports(args.diff[0], args.diff[1])))
        return 0

    manifest = _load(args.mcp_manifest) if args.mcp_manifest else None

    # MCP-only mode (no chatbot target).
    if manifest and not (args.demo or args.config):
        findings = mcp_mod.analyze_manifest(manifest)
        if args.mcp_baseline:
            base = mcp_mod.snapshot(_load(args.mcp_baseline))
            findings += mcp_mod.detect_rug_pull(base, manifest)
        from glasscage import kb, remediation
        remediation.apply_all(findings)
        kb.enrich_all(findings)
        for f in findings:
            print(f"[{f.status.value.upper()}] {f.owasp_id} {f.severity.value}: {f.title}")
            for r in f.reference_links:
                print(f"    ref: {r['label']} -> {r['url']}")
        return 0

    if args.plugins:
        if not args.allow_plugins:
            print("error: --plugins requires --allow-plugins. Plugins execute arbitrary "
                  "Python with your privileges and are NOT sandboxed; only load code you "
                  "trust.", file=sys.stderr)
            return 2
        print(f"WARNING: loading plugins from '{args.plugins}'. Plugins run as arbitrary code with "
              "your privileges (no sandbox). Only load trusted plugins.",
              file=sys.stderr)
        n = load_plugins(args.plugins)
        print(f"Loaded {n} plugin module(s).", file=sys.stderr)

    if args.demo:
        target = _MockTarget()
    elif args.harness:
        from glasscage.refagent import ReferenceAgent
        target = ReferenceAgent()
    elif args.config:
        if not args.authorized:
            print("Refusing to run against a live target without --authorized.\n"
                  "Only test systems you own or have written permission to assess.",
                  file=sys.stderr)
            return 2
        cfg = _load(args.config)
        if args.proxy:
            cfg["proxy"] = args.proxy
            cfg["proxy_no_verify"] = args.proxy_no_verify
        cfg["max_retries"] = args.max_retries
        cfg["backoff_base"] = args.backoff
        target = HTTPChatTarget(cfg)
    elif args.rest_config:
        # ADR 0015: the REST assessment path. --authorized gates it exactly as it gates
        # --config; the non-empty --scope that ADR 0012 R1 requires is enforced downstream
        # by `require_scope` at SurfaceTarget construction, not re-checked here.
        if not args.authorized:
            print("Refusing to run against a live target without --authorized.\n"
                  "Only test systems you own or have written permission to assess.",
                  file=sys.stderr)
            return 2
        if not args.rest_spec:
            ap.error("--rest-config requires --rest-spec (the OpenAPI document to assess)")
            return 2
        from glasscage.targets import RestTarget
        rest_cfg = _load(args.rest_config)
        if not rest_cfg.get("url"):
            ap.error("--rest-config must declare a 'url'")
            return 2
        target = RestTarget(rest_cfg["url"], headers=rest_cfg.get("headers"),
                            timeout=rest_cfg.get("timeout", 30),
                            name=rest_cfg.get("name"))
    elif args.free:
        if not args.authorized:
            print("Refusing to run against a live target without --authorized.\n"
                  "Only test systems you own or have written permission to assess.",
                  file=sys.stderr)
            return 2
        _here = os.path.dirname(os.path.abspath(__file__))
        free = _load(os.path.join(_here, "samples", "free_targets.json"))
        cfg = free["targets"][0]
        if args.proxy:
            cfg["proxy"] = args.proxy
            cfg["proxy_no_verify"] = args.proxy_no_verify
        target = HTTPChatTarget(cfg)
        print(f"Using free target: {cfg['name']}", file=sys.stderr)
    else:
        ap.error("provide --config <file>, --demo, --harness, --rest-config, "
                 "--free, --mcp-manifest, --benchmark, or --diff")
        return 2

    # ADR 0021: operational safety + chain of custody, attached HERE - immediately after
    # the target exists and before any branch capable of driving it. `--orchestrate` and
    # `--validate` each build an Engine over this target and return before the reporting
    # path, so wiring these controls further down left them unenforced on exactly the two
    # paths that send traffic: `--scope` refused nothing, `--rate` throttled nothing and
    # `--audit-log` wrote nothing, all while exiting 0. Ordering only - the enforcement
    # points, error types and exit codes are unchanged.
    from glasscage import audit as audit_mod
    if args.scope:
        target.scope = audit_mod.Scope(args.scope)
    if args.rate:
        target.rate = audit_mod.RateLimiter(args.rate)
    target.audit = audit_mod.AuditLog(args.audit_log)

    # Stage C/D: multi-tool orchestration mode
    if args.orchestrate:
        from glasscage import orchestrator
        af = _parse_adapter_files(args.adapter_file)
        rep = orchestrator.orchestrate(target, tools=args.orchestrate,
                                       options={k: {"from_file": v} for k, v in af.items()})
        print(orchestrator.to_markdown(rep))
        with open(f"{args.out}_orchestration.json", "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2)
        print(f"\nWrote {args.out}_orchestration.json")
        return 0

    # P0-5: adapter validation (honest; Pending External Validation unless genuine)
    # Stage D: benchmark + cross-framework validation + paper report
    if args.validate:
        from glasscage import benchmark, validation
        af = _parse_adapter_files(args.adapter_file)
        corpus = args.benchmark or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                "benchmark", "corpus.json")
        bench = benchmark.run_corpus(corpus)
        tools = ["native", "fake"] + [t for t in af if t not in ("native", "fake")]
        val = validation.validate(target, tools, adapter_files=af)
        benchmark.write_report(bench, f"{args.out}_benchmark")
        with open(f"{args.out}_validation.json", "w", encoding="utf-8") as fh:
            json.dump(val, fh, indent=2)
        with open(f"{args.out}_validation.md", "w", encoding="utf-8") as fh:
            fh.write(validation.to_markdown(val))
        with open(f"{args.out}_VALIDATION_REPORT.md", "w", encoding="utf-8") as fh:
            fh.write(validation.paper_report(bench, val))
        print(validation.paper_report(bench, val))
        print(f"\nWrote {args.out}_benchmark.(json/md), {args.out}_validation.(json/md), "
              f"{args.out}_VALIDATION_REPORT.md")
        return 0

    from glasscage import schema as schema_mod

    # schema-confirmed tool surface (falls back to a bundled sample in demo)
    schema_tools = None
    _here = os.path.dirname(os.path.abspath(__file__))
    if args.schema:
        schema_tools = schema_mod.ingest(_load(args.schema))
    elif args.demo:
        try:
            schema_tools = schema_mod.ingest(_load(os.path.join(_here, "samples", "function_schema.json")))
        except Exception:
            pass

    # architecture answers (demo loads a sample to showcase)
    arch_answers = None
    if args.architecture:
        arch_answers = _load(args.architecture)
    elif args.demo:
        try:
            arch_answers = _load(os.path.join(_here, "samples", "architecture_answers.json"))
        except Exception:
            pass

    # model card (demo loads a sample to showcase)
    model_card = None
    if getattr(args, "model_card", None):
        model_card = _load(args.model_card)
    elif args.demo:
        try:
            model_card = _load(os.path.join(_here, "samples", "model_card_answers.json"))
        except Exception:
            pass

    # system prompt text for static analysis
    system_prompt_text = None
    if args.system_prompt:
        with open(args.system_prompt, encoding="utf-8") as fh:
            system_prompt_text = fh.read()

    # ADR 0015: promote the discovered operations to bound surfaces and drive them. Built
    # after the operational controls above so the surfaces are bound to a target that
    # already carries them; `surface=None` leaves every other invocation unchanged.
    surface = None
    if args.rest_config:
        from glasscage.targets import (
            ApplicationTarget,
            SurfaceKind,
            bind_candidate,
            discover_openapi,
        )
        app = ApplicationTarget(base_url=target.url)
        for candidate in discover_openapi(_load(args.rest_spec)):
            app.add_candidate(candidate)
        for candidate in app.candidates_of(SurfaceKind.REST):
            app.add_surface(bind_candidate(candidate, target))
        surface = app

    evidence_dir = None if args.no_evidence else f"{args.out}_evidence"
    engine = Engine(target, mcp_manifest=manifest, use_judge=args.judge,
                    evidence_dir=evidence_dir, capture_evidence=not args.no_evidence,
                    schema_tools=schema_tools, adaptive=args.adaptive,
                    architecture_answers=arch_answers,
                    model_card=model_card,
                    system_prompt_text=system_prompt_text, genetic=args.genetic,
                    trials=args.trials, seed=args.seed, use_aakg=not args.no_aakg,
                    store_raw=args.store_raw, surface=surface,
                    impact_chain=not args.no_chain)

    # --retry-errors: filter engine probes to only those that errored in a previous run.
    if args.retry_errors:
        prev_path = f"{args.out}.json"
        if not os.path.exists(prev_path):
            print(f"error: --retry-errors requires a previous report at {prev_path}",
                  file=sys.stderr)
            return 2
        prev = _load(prev_path)
        prev_findings = prev.get("findings", [])
        error_probes = {f["probe_name"] for f in prev_findings
                        if f.get("status") == "error"}
        if not error_probes:
            print("No errored probes in the previous report; nothing to retry.",
                  file=sys.stderr)
            return 0
        engine.probes = [p for p in engine.probes if p.name in error_probes]
        print(f"Retrying {len(engine.probes)} probe(s) that errored: "
              f"{', '.join(sorted(error_probes))}", file=sys.stderr)

    results = engine.run()

    md = engine.report_markdown(results)
    with open(f"{args.out}.md", "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(f"{args.out}.html", "w", encoding="utf-8") as fh:
        fh.write(engine.report_html(results))
    write_json(f"{args.out}.json", target.name, results["recon"],
               results["findings"], results["summary"],
               narratives=results.get("narratives"), story=results.get("story"))
    if getattr(engine, "_graph_obj", None) is not None:
        with open(f"{args.out}_aakg.json", "w", encoding="utf-8") as fh:
            fh.write(engine._graph_obj.to_json(indent=2))
    # Reporting layer: audience views over the shared narrative/story models.
    if args.views and results.get("story") is not None:
        from glasscage.aakg import views as views_mod
        wanted = (list(views_mod.AUDIENCES) if "all" in args.views else args.views)
        for aud in wanted:
            if aud not in views_mod.AUDIENCES:
                print(f"error: unknown view '{aud}'; expected one of "
                      f"{', '.join(views_mod.AUDIENCES)} or 'all'", file=sys.stderr)
                return 2
        for aud in wanted:
            txt = views_mod.render(results["story"], results["narratives"], aud,
                                   engine._graph_obj)
            with open(f"{args.out}_view_{aud}.md", "w", encoding="utf-8") as fh:
                fh.write(txt)
        _view_files = [f"{args.out}_view_{a}.md" for a in wanted]
    else:
        _view_files = []
    if args.har and target.exchanges:
        if not args.store_raw:
            from glasscage import redaction
            redaction.redact_exchanges(target.exchanges)
        audit_mod.har_export(target.exchanges, f"{args.out}.har")
    if args.encrypt_evidence and evidence_dir:
        import os as _os

        from glasscage import redaction
        pw = args.evidence_password or _os.environ.get("GLASSCAGE_EVIDENCE_PASSWORD")
        if not pw:
            print("error: --encrypt-evidence requires --evidence-password or "
                  "GLASSCAGE_EVIDENCE_PASSWORD", file=sys.stderr)
            return 2
        n = redaction.encrypt_dir(evidence_dir, pw)
        print(f"encrypted {n} evidence file(s) at rest in {evidence_dir}/")
    extra = list(_view_files)
    if args.sarif:
        from glasscage import sarif
        sarif.write_sarif(f"{args.out}.sarif", target.name, results["findings"],
                          results["summary"])
        extra.append(f"{args.out}.sarif")
    if args.replay:
        # ADR 0018: the bundle and its runner are chat-shaped by construction -
        # `target_config` carries `body_template`/`response_path`, and the emitted runner
        # builds an HTTPChatTarget and calls `send()`. No format exists for a non-chat
        # surface, so none is written rather than one written unusable. The assessment,
        # the report, SARIF and HAR are unaffected.
        from glasscage.targets import SurfaceKind
        _non_chat = sorted(k.value for k in _driven_kinds(surface)
                           if k is not SurfaceKind.CHAT)
        if _non_chat:
            print(f"warning: --replay is not supported for {', '.join(_non_chat)} "
                  "surfaces; no replay bundle or runner was written. The bundle format "
                  "and its runner are chat-only (ADR 0018). The assessment itself, the "
                  "report, SARIF and HAR are unaffected.", file=sys.stderr)
        else:
            from glasscage import sarif
            cfg = _load(args.config) if args.config else {
                "url": target.url, "name": target.name,
                "body_template": target.body_template,
                "response_path": target.response_path}
            sarif.write_replay(f"{args.out}.replay.json", target.name, cfg,
                               results["findings"])
            with open(f"{args.out}_replay_runner.py", "w", encoding="utf-8") as fh:
                fh.write(sarif.REPLAY_RUNNER)
            extra.append(f"{args.out}.replay.json")

    s = results["summary"]
    p = results.get("posture", {})
    print(md)
    print(f"\n=== Posture {p.get('posture_score','?')}/100 (Risk {p.get('risk_index','?')}, "
          f"band {p.get('band','?')}) | {s.get('posture','n/a')} | "
          f"impact-confirmed {s.get('impact_confirmed_count',0)} | "
          f"chains {len(results.get('chains',[]))} ===")
    if target.audit is not None:
        # ADR 0019: the three-state result, so "cannot be verified because the log predates
        # the integrity format" reads differently from "was altered". `verify()` returns a
        # bool and cannot express that distinction.
        _chain = target.audit.check()
        _head = f", head {_chain.head[:12]}" if _chain.head else ""
        print(f"Audit chain: {_chain.status.value} ({_chain.entries} entries{_head})"
              + (f" - {_chain.detail}" if _chain.detail else ""))
    ev = "" if args.no_evidence else f", {evidence_dir}/"
    har = f", {args.out}.har" if (args.har and target.exchanges) else ""
    ex = (", " + ", ".join(extra)) if extra else ""
    print(f"Wrote {args.out}.md, {args.out}.html, {args.out}.json{ev}{har}{ex}")

    # ADR 0025: custody completeness at run exit. `exchanges` holds exactly one record per
    # exchange the transport actually performed (ADR 0022/0023), and after ADR 0024 the
    # audit chain holds exactly what reached disk. A shortfall between them therefore means
    # custody was lost - and only that. It is not inferred from any failure: a refused
    # connection, an HTTP 500 and a `response_path` failure each still append one exchange
    # AND one entry, so they reconcile to zero.
    #
    # Reported here, after every artifact is written, because the assessment itself is
    # sound; what cannot be vouched for is the evidence trail. Previously a failing audit
    # backend surfaced only as a `probe ... crashed` note and the run exited 0 - measured on
    # `v0.4.9-durable-audit-commit`, 18 exchanges with 4 in custody still exited 0.
    # Exit 3 is used rather than 2, which already means "refused" (`GlasscageError`,
    # `ap.error`); a run that completed with incomplete custody is a different outcome.
    _lost = 0
    if target.audit is not None:
        _lost = len(target.exchanges) - len(target.audit.entries)
    if _lost > 0:
        print(f"error: custody incomplete - {_lost} of {len(target.exchanges)} exchange(s) "
              f"were not recorded in the audit chain. The target was assessed and the "
              f"report above is complete; what failed is chain of custody, so this run's "
              f"evidence cannot be vouched for in full. The audit log holds "
              f"{len(target.audit.entries)} entries and verifies as far as it goes; the "
              f"missing exchanges are not recoverable from it.", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    import sys as _sys

    from glasscage.errors import GlasscageError
    try:
        raise SystemExit(main())
    except GlasscageError as _e:
        print(f"error: {_e}", file=_sys.stderr)
        raise SystemExit(2)
