# Sovereign Self-Fixer

Sovereign Self-Fixer is a local-first Python service for self-integrity monitoring, encrypted state, tamper-evident evidence, and authority-bound repair operations.

## PQC authority boundary

Version 0.4 adds an explicit PQC authority layer using the current `liboqs-python` binding:

- **ML-DSA-87** for signing authority records and capability leases.
- **ML-KEM-768** for the persisted post-quantum encapsulation identity.
- Encrypted AES-256-GCM backups for rotated private key material.
- Atomic `0600` key persistence.
- Bounded capability leases with a maximum lifetime of 15 minutes.
- Hash-chained SCAR evidence with strict sequence verification.
- Fail-closed authorization for key rotation and capability issuance.
- No unauthenticated arbitrary-signing endpoint.
- No silent classical fallback when the PQC authority profile is requested.

`liboqs-python` is the official Python wrapper for liboqs and imports as `oqs`. It exposes `Signature` and `KeyEncapsulation`; this project pins the wrapper to `0.16.0` for deterministic integration.

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

The PQC runtime requires the liboqs native dependency. `liboqs-python` can use a system installation or build the matching liboqs release automatically when the wrapper is first imported.

## Run

```bash
python -m selffixerai
```

Set `SOVEREIGN_MODE` to `ghost`, `hybrid`, or `online` for the existing runtime profiles.
Use `SOVEREIGN_BASE_DIR` to control local state and backup storage.

## Authority example

```python
from pathlib import Path
from selffixerai.authority import SelfFixerAuthority

authority = SelfFixerAuthority(
    Path("./sovereign-state"),
    backup_key=bytes.fromhex("00" * 32),
)

lease = authority.issue_capability(
    project_id="sovereignty",
    component="self-fixer",
    operation="FILE_REPAIR",
    scope=["src/example.py"],
    evidence_hash="precomputed-evidence-hash",
    ttl_seconds=60,
    authorization={
        "operation": "CAPABILITY_ISSUE",
        "expires_at": "2099-01-01T00:00:00Z",
        "policy_epoch": 1,
    },
)

authority.verify_capability(lease)
```

For production, the backup key must come from the authorized local secret/TPM boundary; do not commit it to source control or place it in application configuration files.

## Tests and checks

```bash
pytest tests -v
ruff check selffixerai/ skills/ tests/
python -m build
```

## Existing project layout

- `selffixerai/` — core package
- `selffixerai/security/` — encryption and tamper locking
- `selffixerai/analysis/` — static scanning
- `selffixerai/memory/` — persistent memory store
- `selffixerai/crypto/` — named profiles and PQC primitives
- `selffixerai/authority.py` — signed capability and key lifecycle boundary
- `skills/` — supporting runtime skills
- `tests/` — automated tests
