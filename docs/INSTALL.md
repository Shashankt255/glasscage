# Installation Guide

GLASSCAGE is pure Python with **zero runtime dependencies**. If you have Python 3.10+
you can run it.

## Requirements

| Requirement | Value |
|---|---|
| Python | **3.10 or newer** |
| OS | Windows 10+, Linux, macOS |
| Runtime dependencies | **none** (standard library only) |
| Disk | < 10 MB for the package |

Check your Python:

```bash
python --version      # or: python3 --version
```

Expected: `Python 3.10.x` or higher. If lower, install a newer Python from
python.org (Windows/macOS) or your package manager (Linux).

## 1. Create a virtual environment (recommended)

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Windows (cmd)
```cmd
py -m venv .venv
.\.venv\Scripts\activate.bat
```

You should see `(.venv)` at the start of your prompt.

## 2. Install

### From source (current distribution method)
```bash
git clone <your-repo-url> glasscage
cd glasscage
pip install .
```

For a development install (editable, plus dev tools):
```bash
pip install -e ".[dev]"
```

> **Note on PyPI:** if/when a published package is available, `pip install glasscage`
> will work. As of rc3 the supported path is install-from-source.

## 3. Optional extras

Extras enable optional features. They are **not** required for core assessment.

| Extra | Enables | Install |
|---|---|---|
| `llm` | LLM-as-judge (`--judge`), LLM-assisted mutation | `pip install ".[llm]"` |
| `yaml` | YAML target/architecture configs | `pip install ".[yaml]"` |
| `rich` | prettier CLI output | `pip install ".[rich]"` |
| `dev` | pytest, ruff, mypy, build | `pip install ".[dev]"` |

### Encrypted evidence — install `cryptography` directly

Evidence-at-rest encryption (`--encrypt-evidence`) requires the `cryptography` package.

> **Accuracy note (rc3):** there is currently **no `crypto` extra declared** in
> `pyproject.toml`, so `pip install glasscage[crypto]` will not work. Install the
> dependency directly instead:

```bash
pip install cryptography
```

Verify it is available:
```bash
python -c "from glasscage import redaction; print(redaction.encryption_available())"
# expected: True
```

If `cryptography` is absent, GLASSCAGE **refuses** to encrypt rather than shipping a
weak homemade cipher — an honest failure, not a silent one.

## 4. Plugin installation

Plugins are directories of Python probe modules. There is nothing to "install" — you
point GLASSCAGE at the directory at run time, and you must explicitly consent:

```bash
python -m glasscage --demo --plugins ./my-plugins --allow-plugins --out report
```

Without `--allow-plugins` the run is refused. See [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md).
Plugins run as **arbitrary, unsandboxed code with your privileges** — only load code
you trust.

## 5. Verify the installation

```bash
python -m glasscage --demo --out /tmp/verify
```

Expected: the run completes and writes `verify.md`, `verify.html`, `verify.json`,
`verify_aakg.json`, and a `verify_evidence/` directory. If you see those files, you are
ready. Run the test suite (dev install) to be thorough:

```bash
python -m unittest discover -s tests -q
# expected: "Ran 189 tests ... OK"
```

## Common installation failures

| Symptom | Cause | Fix |
|---|---|---|
| `python: command not found` | Python not on PATH | use `python3`, or reinstall Python with "Add to PATH" |
| `pip install glasscage[crypto]` → no matching distribution | no `crypto` extra exists (rc3) | `pip install cryptography` directly (see §3) |
| `ModuleNotFoundError: glasscage` | not installed, or wrong venv | activate the venv; `pip install .` |
| `SyntaxError` on import | Python < 3.10 | install Python 3.10+ |
| `error: externally-managed-environment` | system Python (PEP 668) | use a venv (§1) |
| Encryption "not available" | `cryptography` missing | `pip install cryptography` |
| Windows: script activation blocked | PowerShell execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
