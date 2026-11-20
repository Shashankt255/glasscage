from glasscage import disclosed_reports


def test_reports_returns_36():
    assert len(disclosed_reports.reports()) == 36


def test_each_has_required_keys():
    for r in disclosed_reports.reports():
        assert "vuln_class" in r
        assert "cited_examples" in r
        assert "patterns" in r


def test_report_for_xss():
    r = disclosed_reports.report_for("xss")
    assert r is not None
    assert r["vuln_class"] == "xss"


def test_report_for_nonexistent():
    assert disclosed_reports.report_for("nonexistent") is None


def test_cited_examples_for_xss():
    ex = disclosed_reports.cited_examples_for("xss")
    assert len(ex) > 0


def test_patterns_for_sqli():
    pats = disclosed_reports.patterns_for("sqli")
    assert len(pats) > 0


def test_all_vuln_classes_unique():
    classes = [r["vuln_class"] for r in disclosed_reports.reports()]
    assert len(classes) == len(set(classes))


def test_no_hash_prefix_in_names():
    for r in disclosed_reports.reports():
        for e in r["cited_examples"]:
            assert not e.get("name", "").startswith("#"), f"hash prefix in {r['vuln_class']}: {e['name']}"
        for p in r["patterns"]:
            assert not p.get("name", "").startswith("#"), f"hash prefix in {r['vuln_class']}: {p['name']}"
