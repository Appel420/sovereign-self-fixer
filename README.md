# Sovereign Self-Fixer

Sovereign Self-Fixer is a Python service that monitors its own source, stores encrypted state, and keeps a tamper-evident audit trail while running a lightweight static scan.

## What it includes

- Encrypted file and key storage
- Tamper-evident state locking
- Static analysis for unsafe Python patterns
- Mode-aware runtime profiles for ghost, hybrid, and online operation
- Automatic file restoration from encrypted backups when a target goes missing
- In-memory and persisted turn history
- Structured notifications
- A module entry point via `python -m selffixerai`

## Requirements

- Python 3.13 recommended
- `cryptography`

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
python -m selffixerai
```

Set `SOVEREIGN_MODE` to `ghost`, `hybrid`, or `online` to select the runtime profile.
Use `SOVEREIGN_BASE_DIR` to control where memory, state, and backups are stored.

## Test

```bash
pytest tests -v
ruff check selffixerai/ skills/ tests/
python -m build
```

## Project layout

- `selffixerai/` - core package
- `selffixerai/security/` - encryption and tamper locking
- `selffixerai/analysis/` - static scanning
- `selffixerai/memory/` - persistent memory store
- `skills/` - supporting runtime skills
- `tests/` - automated tests
