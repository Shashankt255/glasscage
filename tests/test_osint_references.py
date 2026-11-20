from glasscage.osint_references import (
    categories,
    category_by_id,
    dork_corpus,
    identity_providers,
    probe_wordlists,
    recon_tools,
    secret_patterns,
    secret_validators,
    sector_notes,
    subdomain_takeover_fingerprints,
)


def test_categories_count():
    assert len(categories()) == 15


def test_category_ids_unique():
    ids = [c["id"] for c in categories()]
    assert len(ids) == len(set(ids))


def test_category_by_id_found():
    c = category_by_id("dork-corpus")
    assert c is not None
    assert c["name"] == "Google & GitHub Dork Corpus"


def test_category_by_id_missing():
    assert category_by_id("nonexistent") is None


def test_dork_corpus_has_groups():
    dc = dork_corpus()
    assert dc is not None
    assert len(dc["dork_groups"]) >= 9
    assert len(dc["github_dorks"]) >= 10


def test_secret_patterns_count():
    sp = secret_patterns()
    assert len(sp) >= 25
    for p in sp:
        assert "name" in p
        assert "severity" in p
        assert "regex" in p


def test_secret_pattern_severities():
    valid = {"critical", "high", "medium", "low"}
    for p in secret_patterns():
        assert p["severity"] in valid


def test_probe_wordlists_has_swagger():
    pw = probe_wordlists()
    assert pw is not None
    assert len(pw["swagger_paths"]) >= 20


def test_probe_wordlists_has_graphql():
    pw = probe_wordlists()
    assert len(pw["graphql_paths"]) >= 10


def test_probe_wordlists_has_ports():
    pw = probe_wordlists()
    assert len(pw["high_risk_ports"]) >= 30


def test_identity_providers():
    providers = identity_providers()
    assert len(providers) >= 5
    names = {p["name"] for p in providers}
    assert "Microsoft Entra (Azure AD)" in names
    assert "Okta" in names


def test_sector_notes_coverage():
    sectors = sector_notes()
    assert len(sectors) >= 7
    names = {s["sector"] for s in sectors}
    assert "Healthcare" in names
    assert "Finance" in names
    assert "ICS/SCADA" in names


def test_subdomain_takeover_fingerprints():
    fp = subdomain_takeover_fingerprints()
    assert len(fp) >= 20
    providers = {f["provider"] for f in fp}
    assert "AWS S3" in providers
    assert "GitHub Pages" in providers


def test_secret_validators():
    sv = secret_validators()
    assert len(sv) >= 8
    providers = {v["provider"] for v in sv}
    assert "AWS" in providers
    assert "GitHub" in providers


def test_recon_tools():
    tools = recon_tools()
    assert len(tools) >= 10
    cats = {t["category"] for t in tools}
    assert "Subdomain enumeration" in cats
    assert "Vulnerability scanning" in cats


def test_every_category_has_source_file():
    for c in categories():
        assert "source_file" in c
        assert c["source_file"].endswith(".md")
