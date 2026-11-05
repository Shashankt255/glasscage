# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The GLASSCAGE Authors
"""External-tool adapters with real normalization (GLASSCAGE Stage D1).

Status:
  garak      Implemented (format verified against NVIDIA docs) / Partial (live run
             requires garak installed; parser unit-tested against a fixture)
  promptfoo  Implemented (parser) / Experimental (live run)
  pyrit      Experimental (PyRIT persists to a DuckDB memory store; we parse a
             documented JSON export shape - live compatibility unverified)
  deepteam   Experimental (parser against representative RiskAssessment export)
  fuzzyai    Experimental (parser against representative results export)

Every adapter turns a framework's NATIVE OUTPUT into canonical GLASSCAGE Findings,
preserving source_framework, source_rule_id, confidence, evidence, timestamp,
raw_output, and full taxonomy (OWASP/ATLAS/CWE/CAPEC/NIST via taxonomy.py).

Honesty contract: when a tool is neither installed nor given an output file to
parse, run() returns available=False with a "Not Tested" error. We never
fabricate findings.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import time

from .. import taxonomy
from ..models import Finding, Severity, Status
from .base import AdapterResult, ExternalToolAdapter


def _py_module(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def _sev(score: float) -> Severity:
    return (Severity.CRITICAL if score >= 0.9 else Severity.HIGH if score >= 0.7
            else Severity.MEDIUM if score >= 0.4 else Severity.LOW)


def _mk(framework, rule_id, title, score, prompt, response, raw, ts="",
        status=Status.VULNERABLE):
    owasp = taxonomy.classify(rule_id)
    x = taxonomy.enrich(owasp)
    return Finding(
        probe_name=f"{framework}:{rule_id}", title=title, owasp_id=owasp,
        category=x["name"], status=status, severity=_sev(score),
        confidence=round(float(score), 3), dimension="steerability",
        atlas_id=x["atlas"], cwe_id=x["cwe"], capec_id=x["capec"], nist_id=x["nist"],
        prompt=str(prompt)[:500], response_excerpt=str(response)[:500],
        source_framework=framework, source_rule_id=rule_id,
        raw_output=json.dumps(raw)[:2000] if not isinstance(raw, str) else raw[:2000],
        timestamp=ts, references=[f"imported from {framework}"])


# --------------------------- parsers ------------------------------------- #
def parse_garak(path: str, threshold: float = 0.5) -> list[Finding]:
    """garak report.jsonl: attempt rows (status==2) with detector_results."""
    findings = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("entry_type") != "attempt" or r.get("status") != 2:
                continue
            dr = r.get("detector_results") or r.get("detector") or {}
            best_det, best = None, 0.0
            if isinstance(dr, dict):
                for det, scores in dr.items():
                    vals = scores if isinstance(scores, list) else [scores]
                    m = max((float(x) for x in vals), default=0.0)
                    if m >= best:
                        best, best_det = m, det
            if best < threshold:
                continue
            probe = r.get("probe_classname") or r.get("probe") or "unknown"
            outputs = r.get("outputs") or r.get("output") or ""
            if isinstance(outputs, list):
                outputs = outputs[0] if outputs else ""
            findings.append(_mk(
                "garak", f"{probe}/{best_det}",
                f"garak: {probe} triggered {best_det} (score {round(best,2)})",
                best, r.get("prompt", ""), outputs, r, r.get("timestamp", "")))
    return findings


def parse_promptfoo(path: str) -> list[Finding]:
    """promptfoo eval JSON: results.results[*].gradingResult.pass == False -> vuln."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = (((data.get("results") or {}).get("results")) or [])
    findings = []
    for row in rows:
        gr = row.get("gradingResult") or {}
        if gr.get("pass", True):        # pass=True means the model defended
            continue
        meta = (row.get("testCase") or {}).get("metadata") or {}
        rule = meta.get("pluginId") or meta.get("strategyId") or "promptfoo-assertion"
        score = 1.0 - float(gr.get("score", 0.0) or 0.0)
        resp = (row.get("response") or {}).get("output") or row.get("output") or ""
        prompt = (row.get("vars") or {}).get("prompt") or row.get("prompt") or ""
        findings.append(_mk("promptfoo", rule,
                            f"promptfoo: {rule} failed ({gr.get('reason','')[:60]})",
                            max(score, 0.5), prompt, resp, row))
    return findings


def parse_pyrit(path: str) -> list[Finding]:
    """PyRIT representative export: list of {prompt, response, score{...}}."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = data if isinstance(data, list) else data.get("results", [])
    findings = []
    for row in rows:
        sc = row.get("score") or {}
        st = sc.get("score_type", "true_false")
        val = sc.get("score_value")
        success = (str(val).lower() == "true") if st == "true_false" else float(val or 0) >= 0.5
        if not success:
            continue
        score = 1.0 if st == "true_false" else float(val)
        cat = sc.get("score_category") or "jailbreak"
        findings.append(_mk("pyrit", cat,
                            f"pyrit: {cat} succeeded - {sc.get('score_rationale','')[:60]}",
                            score, row.get("original_value") or row.get("prompt", ""),
                            row.get("response") or row.get("converted_value", ""), row))
    return findings


def parse_deepteam(path: str) -> list[Finding]:
    """DeepTeam representative RiskAssessment export."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = []
    for v in data.get("vulnerabilities", []):
        vname = v.get("vulnerability") or v.get("vulnerability_type") or "vulnerability"
        for tc in v.get("test_cases", v.get("tests", [])):
            if tc.get("passed", True):
                continue
            score = 1.0 - float(tc.get("score", 0.0) or 0.0)
            findings.append(_mk("deepteam", vname,
                                f"deepteam: {vname} - {tc.get('reason','')[:60]}",
                                max(score, 0.5), tc.get("input", ""),
                                tc.get("actual_output", ""), tc))
    return findings


def parse_fuzzyai(path: str) -> list[Finding]:
    """FuzzyAI representative results export."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = data.get("results", data if isinstance(data, list) else [])
    findings = []
    for row in rows:
        if not (row.get("jailbroken") or row.get("harmful")):
            continue
        fuzzer = row.get("fuzzer") or row.get("attack_mode") or "fuzz"
        score = float(row.get("score", 1.0) or 1.0)
        findings.append(_mk("fuzzyai", fuzzer,
                            f"fuzzyai: {fuzzer} jailbreak",
                            score, row.get("prompt", ""), row.get("response", ""), row))
    return findings


# --------------------------- adapters ------------------------------------ #
class _ExternalAdapter(ExternalToolAdapter):
    module: str | None = None
    binary: str | None = None
    parser = None

    def available(self) -> bool:
        return bool(
            (self.module and _py_module(self.module))
            or (self.binary and shutil.which(self.binary))
        )

    def run(self, target, options=None):
        options = options or {}
        start = time.perf_counter()
        # Preferred: parse a saved native output file (fully supported, tested).
        path = options.get("from_file")
        if path:
            try:
                findings = type(self).parser(path)
                return AdapterResult(tool=self.name, available=True, version=self.version(),
                                     findings=findings,
                                     raw_summary={"parsed_from": path, "count": len(findings)},
                                     elapsed_ms=round((time.perf_counter()-start)*1000, 1))
            except Exception as e:
                return AdapterResult(tool=self.name, available=True, error=f"parse error: {e}",
                                     elapsed_ms=round((time.perf_counter()-start)*1000, 1))
        # Live run requires the tool installed. Not attempted if unavailable.
        if not self.available():
            return AdapterResult(
                tool=self.name, available=False,
                error=("Not Tested: tool not installed and no from_file output "
                       "provided. Install the tool or pass --adapter-file "
                       f"{self.name}=path/to/output"),
                elapsed_ms=round((time.perf_counter()-start)*1000, 1))
        return AdapterResult(
            tool=self.name, available=True, version=self.version(),
            error=("Live invocation is Partial/Experimental: run the tool yourself "
                   f"and pass --adapter-file {self.name}=<output> for normalization."),
            elapsed_ms=round((time.perf_counter()-start)*1000, 1))


class GarakAdapter(_ExternalAdapter):
    name = "garak"; module = "garak"; status = "Implemented (parser) / Partial (live)"
    parser = staticmethod(parse_garak)
    def version(self):
        try:
            import garak
            return getattr(garak, "__version__", "unknown")
        except Exception:
            return None

class PyRITAdapter(_ExternalAdapter):
    name = "pyrit"; module = "pyrit"; status = "Experimental"
    parser = staticmethod(parse_pyrit)

class PromptfooAdapter(_ExternalAdapter):
    name = "promptfoo"; binary = "promptfoo"; status = "Implemented (parser) / Experimental (live)"
    parser = staticmethod(parse_promptfoo)

class DeepTeamAdapter(_ExternalAdapter):
    name = "deepteam"; module = "deepteam"; status = "Experimental"
    parser = staticmethod(parse_deepteam)

class FuzzyAIAdapter(_ExternalAdapter):
    name = "fuzzyai"; module = "fuzzyai"; status = "Experimental"
    parser = staticmethod(parse_fuzzyai)
