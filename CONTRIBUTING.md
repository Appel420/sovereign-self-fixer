# Contributing

## Working locally

- Use Python 3.13.
- Install dev dependencies with `pip install -e ".[dev]"`.
- Run `ruff check selffixerai/ skills/ tests/`.
- Run `pytest tests/ -v`.
- Run `python -m build`.

## Changes

- Keep changes focused and production-safe.
- Update tests when behavior changes.
- Avoid committing secrets or generated artifacts.
