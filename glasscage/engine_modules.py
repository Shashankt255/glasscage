import json
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "data"
_MODULES = None
_COMMANDS = None


def _load_modules():
    global _MODULES
    if _MODULES is None:
        with open(_DIR / "cbh_engine_modules.json") as f:
            _MODULES = json.load(f)["modules"]
    return _MODULES


def _load_commands():
    global _COMMANDS
    if _COMMANDS is None:
        with open(_DIR / "cbh_commands.json") as f:
            _COMMANDS = json.load(f)["commands"]
    return _COMMANDS


def modules():
    return _load_modules()


def module_for(name):
    return next((m for m in _load_modules() if m["name"] == name), None)


def commands():
    return _load_commands()


def command_for(name):
    return next((c for c in _load_commands() if c["name"] == name), None)
