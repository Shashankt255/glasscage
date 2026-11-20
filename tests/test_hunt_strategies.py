from glasscage import hunt_strategies


def test_strategies_returns_83():
    result = hunt_strategies.strategies()
    assert len(result) == 83


def test_required_keys():
    for s in hunt_strategies.strategies():
        assert "name" in s
        assert "description" in s
        assert "sections" in s


def test_strategy_for_xss():
    s = hunt_strategies.strategy_for("hunt-xss")
    assert s is not None
    assert s["name"] == "hunt-xss"
    assert len(s["sections"]) > 0


def test_strategy_for_nonexistent():
    assert hunt_strategies.strategy_for("nonexistent") is None


def test_strategies_for_class_sqli():
    results = hunt_strategies.strategies_for_class("sqli")
    assert len(results) >= 1
    assert all("sqli" in r["name"].lower() for r in results)


def test_report_counts_nonnegative():
    for s in hunt_strategies.strategies():
        assert isinstance(s["report_count"], int)
        assert s["report_count"] >= 0


def test_strategies_for_class_case_insensitive():
    a = hunt_strategies.strategies_for_class("XSS")
    b = hunt_strategies.strategies_for_class("xss")
    assert len(a) == len(b) > 0


def test_all_names_unique():
    names = [s["name"] for s in hunt_strategies.strategies()]
    assert len(names) == len(set(names))
