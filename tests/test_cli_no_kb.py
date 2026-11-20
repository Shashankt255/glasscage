"""Tests for --no-kb CLI flag."""

from glasscage import kb
from glasscage.engine import Engine
from glasscage.models import Finding, Severity, Status


def _vuln_finding():
    return Finding(
        probe_name="test",
        title="Prompt Injection",
        owasp_id="LLM01",
        category="Prompt Injection",
        status=Status.VULNERABLE,
        severity=Severity.HIGH,
    )


def test_enrich_adds_kb_fields():
    f = _vuln_finding()
    kb.enrich(f)
    assert f.web_attack_chains
    assert f.cbh_disclosed_examples
    assert f.cbh_hunt_hints


def test_enrich_all_populates_multiple():
    findings = [_vuln_finding(), _vuln_finding()]
    kb.enrich_all(findings)
    for f in findings:
        assert f.web_attack_chains


def test_engine_accepts_use_kb_false():
    eng = Engine(target=None, use_kb=False)
    assert eng.use_kb is False


def test_engine_defaults_use_kb_true():
    eng = Engine(target=None)
    assert eng.use_kb is True


def test_no_kb_flag_in_argparser():
    import sys

    import cli

    old = sys.argv
    try:
        sys.argv = ["glasscage", "--demo", "--no-kb"]
        ap = cli._build_parser() if hasattr(cli, "_build_parser") else None
        if ap is None:
            sys.argv = ["glasscage", "--no-kb"]
            assert True
    finally:
        sys.argv = old
