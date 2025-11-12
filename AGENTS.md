# AGENTS.md

## Commands
- Setup: `python -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
- Run demo: `python demo.py`
- Lint: `ruff .`; Format: `black .` (or `black --check .` in CI)
- Test: `pytest` (all), `pytest -k <test_name>` (by name), or `pytest <path/to/test_file.py>::<test_name>` (single test)

## Style Guide
- Imports: stdlib → third‑party → local, alphabetical, blank line between groups; avoid `import *`.
- Formatting: 4‑space indent, max line length 88, black‑compatible.
- Types: annotate public functions/methods; use `bytes`, `int` hints.
- Naming: classes `PascalCase`; functions/vars `snake_case`; constants `UPPER_SNAKE`; private helpers start with `_`.
- Docs: docstrings for all public callables; use f‑strings.
- Error handling: raise `ValueError`/`TypeError` for bad arguments; define custom exceptions only when needed.
- Tests: place under `tests/`, name files `test_*.py`, use pytest fixtures for setup.

## Repository Rules
- No `.cursor`/`.cursorrules` or Copilot instructions in this repo.
