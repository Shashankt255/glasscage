"""Tests for CBH enrichment wiring in kb.py."""
from glasscage.kb import enrich, enrich_all
from glasscage.models import Finding, Severity, Status


def _make_finding(owasp_id="LLM01", title="Prompt injection via canary", status=Status.VULNERABLE):
    return Finding(
        probe_name="direct-injection",
        title=title,
        owasp_id=owasp_id,
        category="Prompt Injection",
        status=status,
        severity=Severity.HIGH,
    )


def test_enrich_adds_web_attack_chains():
    f = _make_finding(owasp_id="LLM01")
    enrich(f)
    assert hasattr(f, "web_attack_chains")
    assert len(f.web_attack_chains) > 0


def test_enrich_adds_severity_calibration_when_match():
    f = _make_finding(title="/.git/config reachable on prod webapp")
    enrich(f)
    assert getattr(f, "cbh_severity_calibration", None) == "CRITICAL"


def test_enrich_no_severity_calibration_when_no_match():
    f = _make_finding(title="totally unique finding name xyz123")
    enrich(f)
    assert getattr(f, "cbh_severity_calibration", None) is None


def test_enrich_adds_disclosed_examples_for_llm01():
    f = _make_finding(owasp_id="LLM01")
    enrich(f)
    examples = getattr(f, "cbh_disclosed_examples", [])
    assert len(examples) > 0
    assert all("name" in ex and "source" in ex for ex in examples)


def test_enrich_disclosed_examples_max_3():
    f = _make_finding(owasp_id="LLM01")
    enrich(f)
    examples = getattr(f, "cbh_disclosed_examples", [])
    assert len(examples) <= 3


def test_enrich_no_disclosed_examples_for_unmapped_owasp():
    f = _make_finding(owasp_id="LLM10")
    enrich(f)
    assert getattr(f, "cbh_disclosed_examples", None) is None


def test_enrich_does_not_override_existing_severity():
    f = _make_finding(title="/.git/config reachable on prod webapp")
    f.severity = Severity.LOW
    enrich(f)
    assert f.severity == Severity.LOW
    assert getattr(f, "cbh_severity_calibration", None) == "CRITICAL"


def test_enrich_all_processes_multiple():
    findings = [_make_finding(owasp_id="LLM01"), _make_finding(owasp_id="LLM02")]
    enrich_all(findings)
    assert all(hasattr(f, "web_attack_chains") for f in findings)
