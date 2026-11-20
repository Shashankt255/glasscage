from glasscage import verification_labs


def test_labs_count():
    assert len(verification_labs.labs()) == 13


def test_labs_have_required_keys():
    for lab in verification_labs.labs():
        assert "name" in lab
        assert "title" in lab
        assert "body" in lab


def test_lab_for_found():
    lab = verification_labs.lab_for("juice-shop-2026-05-15")
    assert lab is not None
    assert "Juice Shop" in lab["title"]


def test_lab_for_not_found():
    assert verification_labs.lab_for("nonexistent") is None


def test_labs_for_class_jwt():
    results = verification_labs.labs_for_class("jwt")
    assert len(results) >= 1
    assert any("jwt" in c for r in results for c in r["vuln_classes"])


def test_lab_apps_non_empty():
    apps = verification_labs.lab_apps()
    assert len(apps) == 7
    assert all("name" in a and "files" in a for a in apps)


def test_all_names_unique():
    names = [l["name"] for l in verification_labs.labs()]
    assert len(names) == len(set(names))


def test_vuln_classes_are_lists():
    for lab in verification_labs.labs():
        assert isinstance(lab["vuln_classes"], list)
