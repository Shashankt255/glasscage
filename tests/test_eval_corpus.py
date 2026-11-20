"""Tests for the CBH eval corpus and CVE index loader."""
from glasscage import eval_corpus


def test_portswigger_labs_nonempty():
    labs = eval_corpus.portswigger_labs()
    assert len(labs) > 0


def test_portswigger_labs_have_key():
    for lab in eval_corpus.portswigger_labs():
        assert "key" in lab


def test_portswigger_labs_combines_normal_and_hard():
    labs = eval_corpus.portswigger_labs()
    assert len(labs) == 15  # 9 normal + 6 hard


def test_juice_shop_challenges_nonempty():
    challenges = eval_corpus.juice_shop_challenges()
    assert len(challenges) == 3


def test_juice_shop_required_keys():
    for c in eval_corpus.juice_shop_challenges():
        assert "key" in c
        assert "objective" in c


def test_fp_cases_count():
    cases = eval_corpus.fp_cases()
    assert len(cases) == 10


def test_fp_cases_required_keys():
    for c in eval_corpus.fp_cases():
        assert "key" in c
        assert "class" in c
        assert "ground" in c
        assert c["ground"] in ("safe", "vulnerable")


def test_cve_gaps_nonempty():
    gaps = eval_corpus.cve_gaps()
    assert len(gaps) > 0


def test_cve_gap_for_known():
    gap = eval_corpus.cve_gap_for("CVE-2026-42897")
    assert gap is not None
    assert gap["vendor"] == "Microsoft"
    assert "Exchange" in gap["vulnerability"]


def test_cve_gap_for_unknown():
    assert eval_corpus.cve_gap_for("CVE-9999-99999") is None


def test_cve_gaps_required_keys():
    for g in eval_corpus.cve_gaps():
        assert "date_added" in g
        assert "cve" in g
        assert "vendor" in g
        assert "product" in g
        assert "vulnerability" in g
