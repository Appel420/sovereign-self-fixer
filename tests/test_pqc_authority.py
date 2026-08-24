from __future__ import annotations

from pathlib import Path

import pytest

from selffixerai.authority import AuthorityError, SelfFixerAuthority


pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def authorization(operation: str) -> dict[str, object]:
    from datetime import datetime, timedelta, timezone

    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    return {
        "operation": operation,
        "expires_at": expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "policy_epoch": 1,
    }


def test_identity_is_ml_dsa_and_ml_kem(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    identity = authority.public_identity()

    assert identity["signature_algorithm"] == "ML-DSA-87"
    assert identity["kem_algorithm"] == "ML-KEM-768"
    assert identity["public_key"]
    assert identity["kem_public_key"]


def test_capability_is_signed_and_verifiable(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    lease = authority.issue_capability(
        project_id="sovereignty",
        component="self-fixer",
        operation="FILE_REPAIR",
        scope=["src/a.py"],
        evidence_hash="abc123",
        ttl_seconds=60,
        authorization=authorization("CAPABILITY_ISSUE"),
    )

    authority.verify_capability(lease)


def test_capability_ttl_is_bounded(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    lease = authority.issue_capability(
        project_id="sovereignty",
        component="self-fixer",
        operation="FILE_REPAIR",
        scope=["src/a.py"],
        evidence_hash="abc123",
        ttl_seconds=999999,
        authorization=authorization("CAPABILITY_ISSUE"),
    )

    from datetime import datetime, timezone

    issued = datetime.fromisoformat(lease["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(lease["expires_at"].replace("Z", "+00:00"))
    assert (expires - issued).total_seconds() <= 900


def test_rotation_requires_authorization(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    old_id = authority.identity["key_id"]

    with pytest.raises(AuthorityError):
        authority.rotate("test", {})

    assert authority.identity["key_id"] == old_id


def test_rotation_persists_encrypted_backup(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    old_id = authority.identity["key_id"]

    result = authority.rotate(
        "scheduled rotation",
        authorization("KEY_ROTATION"),
    )

    assert result["key_id"] != old_id
    backup = tmp_path / "backups" / f"{old_id}.ssf"
    assert backup.exists()
    assert backup.read_bytes().startswith(b"SSF1")


def test_ledger_detects_tampering(tmp_path: Path) -> None:
    authority = SelfFixerAuthority(tmp_path, b"x" * 32)
    authority.issue_capability(
        project_id="sovereignty",
        component="self-fixer",
        operation="FILE_REPAIR",
        scope=["src/a.py"],
        evidence_hash="abc123",
        ttl_seconds=60,
        authorization=authorization("CAPABILITY_ISSUE"),
    )

    ledger = tmp_path / "ledger" / "scar.jsonl"
    raw = ledger.read_text(encoding="utf-8")
    ledger.write_text(raw.replace("FILE_REPAIR", "UNAUTHORIZED"), encoding="utf-8")

    with pytest.raises(AuthorityError):
        authority.ledger.verify()
