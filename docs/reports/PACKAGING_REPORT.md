# Packaging Report — 1.0.0rc1

## Distribution
- `pyproject.toml` (setuptools backend): metadata, keywords, classifiers, project URLs,
  Apache-2.0 license, `requires-python >=3.10`.
- **Zero runtime dependencies** (stdlib only). Optional extras: `llm` (anthropic),
  `yaml` (pyyaml), `rich`, `dev` (pytest/ruff/mypy/build).
- Console entry point `glasscage = cli:main`; also `python -m glasscage`.
- `py.typed` marker ships type information.
- `package-data` includes `adapters/fixtures/*` for adapter parser conformance.

## Build
`python -m build` produces sdist + wheel (CI `lint-type-build` job).

## Reproducibility
No pinned network installs required for the core; deterministic behavior with `--seed`.

## Remaining
- Publish to an index (TestPyPI → PyPI) — release step, not done here.
- SBOM generation — Roadmap.
