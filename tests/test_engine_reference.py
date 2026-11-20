"""Tests for the CBH engine reference loader."""

from glasscage import engine_reference as er


def test_class_weights_populated():
    w = er.class_weights()
    assert len(w) == 47
    assert w["rce"] == 100
    assert w["ntlm-info"] == 25


def test_weight_for_known():
    assert er.weight_for("sqli") == 90
    assert er.weight_for("ssrf") == 85


def test_weight_for_unknown():
    assert er.weight_for("nonexistent") == 0


def test_class_skill_map():
    m = er.class_skill_map()
    assert len(m) == 47
    assert "hunt-sqli" in m["sqli"]
    assert "hunt-xss" in m["xss"]


def test_skills_for():
    assert er.skills_for("idor") == ["hunt-idor"]
    assert er.skills_for("nonexistent") == []


def test_class_probes():
    p = er.class_probes()
    assert len(p) == 47
    assert "curl" in p["sqli"]


def test_probe_for():
    assert er.probe_for("xss") is not None
    assert "svg" in er.probe_for("xss")
    assert er.probe_for("nonexistent") is None


def test_phases():
    ph = er.phases()
    assert ph["all"] == ["recon", "rank", "map", "hunt", "validate", "report"]
    assert ph["default"] == ["recon", "rank", "map"]


def test_scope_rules():
    s = er.scope_rules()
    assert len(s["pattern_forms"]) == 5
    assert s["rules"]["deny_wins"]
    assert s["rules"]["default_deny"]


def test_coverage_verdicts():
    c = er.coverage_verdicts()
    assert "clean" in c["covered_verdicts"]
    assert "blocked" in c["all_verdicts"]
    assert "blocked" not in c["covered_verdicts"]


def test_recon_patterns():
    r = er.recon_patterns()
    assert "JS_SRC" in r["regex_patterns"]
    assert "REL_API" in r["regex_patterns"]


def test_secret_patterns():
    sp = er.secret_patterns()
    assert len(sp) == 12
    labels = {s["label"] for s in sp}
    assert "AWS access key" in labels
    assert "GitHub token" in labels


def test_osint_config():
    o = er.osint_config()
    assert "subfinder" in o["tools"]
    assert len(o["tech_fingerprint_markers"]) == 12


def test_roe_template():
    t = er.roe_template()
    assert "RULES OF ENGAGEMENT" in t
    assert "READ-ONLY" in t


def test_tech_skill_map():
    t = er.tech_skill_map()
    assert len(t) == 20
    assert "hunt-nextjs" in t["next.js"]


def test_workflows_loaded():
    wf = er.workflows()
    assert len(wf) == 15
    names = er.workflow_names()
    assert "autopilot" in names
    assert "hunt" in names
    assert "validate" in names


def test_workflow_for():
    w = er.workflow_for("chain")
    assert w is not None
    assert "chain" in w["description"].lower() or "exploit" in w["description"].lower()
    assert er.workflow_for("nonexistent") is None


def test_workflow_sections():
    w = er.workflow_for("autopilot")
    assert w is not None
    assert len(w["sections"]) > 0
    headings = [s["heading"] for s in w["sections"]]
    assert any("usage" in h.lower() for h in headings)
