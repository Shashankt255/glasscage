"""Tests for CBH hunt strategy and risk weight enrichment in kb.py."""
from glasscage.kb import _MAX_HUNT_HINTS, _hunt_hints_for, _risk_weight_for, enrich
from glasscage.models import Finding, Severity, Status


def _make_finding(owasp_id="LLM01", status=Status.VULNERABLE):
    return Finding(
        probe_name="test-probe",
        title="Test finding",
        owasp_id=owasp_id,
        category="Test",
        status=status,
        severity=Severity.MEDIUM,
    )


def test_vulnerable_finding_gets_hunt_hints():
    f = _make_finding("LLM01", Status.VULNERABLE)
    enrich(f)
    assert hasattr(f, "cbh_hunt_hints")
    assert len(f.cbh_hunt_hints) > 0


def test_passed_finding_no_hunt_hints():
    f = _make_finding("LLM01", Status.PASSED)
    enrich(f)
    assert not getattr(f, "cbh_hunt_hints", None)


def test_hunt_hints_are_dicts_with_skill_name():
    f = _make_finding("LLM01", Status.VULNERABLE)
    enrich(f)
    for hint in f.cbh_hunt_hints:
        assert "skill_name" in hint
        assert isinstance(hint["skill_name"], str)


def test_hunt_hints_max_three():
    hints = _hunt_hints_for("LLM01")
    assert len(hints) <= _MAX_HUNT_HINTS


def test_risk_weight_is_number_when_matched():
    f = _make_finding("LLM01", Status.VULNERABLE)
    enrich(f)
    assert hasattr(f, "cbh_risk_weight")
    assert isinstance(f.cbh_risk_weight, float)
    assert 0 < f.cbh_risk_weight <= 1.0


def test_risk_weight_absent_when_no_match():
    f = _make_finding("UNKNOWN99", Status.VULNERABLE)
    enrich(f)
    assert not getattr(f, "cbh_risk_weight", None)


def test_hunt_hints_absent_when_no_match():
    f = _make_finding("UNKNOWN99", Status.VULNERABLE)
    enrich(f)
    assert not getattr(f, "cbh_hunt_hints", None)


def test_risk_weight_helper_returns_float():
    w = _risk_weight_for("MCP07")
    assert w is not None
    assert isinstance(w, float)
    assert 0 < w <= 1.0


def test_risk_weight_helper_none_for_unknown():
    w = _risk_weight_for("BOGUS")
    assert w is None
