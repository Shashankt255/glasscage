from glasscage.engine_modules import command_for, commands, module_for, modules


def test_modules_non_empty():
    assert len(modules()) == 9


def test_module_has_required_keys():
    for m in modules():
        assert "name" in m
        assert "functions" in m
        assert "body" in m


def test_module_for_scope():
    m = module_for("scope")
    assert m is not None
    assert m["name"] == "scope"
    assert len(m["body"]) > 0


def test_module_for_nonexistent():
    assert module_for("nonexistent") is None


def test_all_module_names_unique():
    names = [m["name"] for m in modules()]
    assert len(names) == len(set(names))


def test_commands_non_empty():
    assert len(commands()) == 15


def test_command_for_autopilot():
    c = command_for("autopilot")
    assert c is not None
    assert "autonomous" in c["description"].lower()


def test_command_for_nonexistent():
    assert command_for("nonexistent") is None


def test_all_command_names_unique():
    names = [c["name"] for c in commands()]
    assert len(names) == len(set(names))


def test_engine_module_has_functions():
    m = module_for("recon")
    assert m is not None
    assert len(m["functions"]) > 5


def test_command_has_body():
    for c in commands():
        assert len(c["body"]) > 0
