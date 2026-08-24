"""Authority-bound self-fixer state and capability leases.

This module does not expose an unauthenticated signing primitive. Every
capability is explicit, bounded by an expiry, chained to a ledger sequence,
and signed by the current ML-DSA-87 identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_bytes
from .crypto.pqc import b64d, b64e, generate_identity, sign, verify

MAX_LEASE_SECONDS = 900
BACKUP_AAD = b"SOVEREIGN-SELF-FIXER-KEY-BACKUP-v1"


class AuthorityError(RuntimeError):
    """Raised when an authority invariant fails."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


class SCARLedger:
    """Hash-chained JSONL evidence ledger with strict sequence checking."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def verify(self) -> None:
        previous = "GENESIS"
        expected = 1
        for event in self._events():
            if event.get("sequence") != expected:
                raise AuthorityError("SCAR sequence gap or replay detected")
            if event.get("previous_event_hash") != previous:
                raise AuthorityError("SCAR previous hash mismatch")
            unsigned = dict(event)
            event_hash = unsigned.pop("event_hash", None)
            calculated = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
            if calculated != event_hash:
                raise AuthorityError("SCAR event hash mismatch")
            previous = event_hash
            expected += 1

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.verify()
        events = self._events()
        previous = events[-1]["event_hash"] if events else "GENESIS"
        event = {
            "sequence": len(events) + 1,
            "timestamp": utc_now(),
            "event_type": event_type,
            "previous_event_hash": previous,
            "payload": payload,
        }
        event["event_hash"] = hashlib.sha256(canonical_bytes(event)).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return event

    @property
    def sequence(self) -> int:
        return len(self._events())


class SelfFixerAuthority:
    """Local authority boundary for the self-fixer."""

    def __init__(self, base_dir: Path, backup_key: bytes) -> None:
        if len(backup_key) != 32:
            raise ValueError("backup_key must be exactly 32 bytes")
        self.base_dir = base_dir
        self.keys_dir = base_dir / "keys"
        self.backups_dir = base_dir / "backups"
        self.ledger = SCARLedger(base_dir / "ledger" / "scar.jsonl")
        self.identity_path = self.keys_dir / "identity.json"
        self.backup_key = backup_key
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.identity = self._load_or_create_identity()

    def _load_or_create_identity(self) -> dict[str, Any]:
        if self.identity_path.exists():
            identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
            if identity.get("signature_algorithm") != "ML-DSA-87":
                raise AuthorityError("identity is not ML-DSA-87")
            if identity.get("kem_algorithm") != "ML-KEM-768":
                raise AuthorityError("identity is not ML-KEM-768")
            return identity
        identity = generate_identity()
        _atomic_write(self.identity_path, canonical_bytes(identity))
        self.ledger.append("IDENTITY_GENESIS", {"key_id": identity["key_id"]})
        return identity

    def public_identity(self) -> dict[str, Any]:
        return {
            "key_id": self.identity["key_id"],
            "signature_algorithm": self.identity["signature_algorithm"],
            "kem_algorithm": self.identity["kem_algorithm"],
            "public_key": self.identity["public_key"],
            "kem_public_key": self.identity["kem_public_key"],
        }

    def _backup(self, identity: dict[str, Any]) -> str:
        nonce = secrets.token_bytes(12)
        plaintext = canonical_bytes(identity)
        ciphertext = AESGCM(self.backup_key).encrypt(nonce, plaintext, BACKUP_AAD)
        path = self.backups_dir / f"{identity['key_id']}.ssf"
        _atomic_write(path, b"SSF1" + nonce + ciphertext)
        return path.name

    def _authorization(self, authorization: dict[str, Any], operation: str) -> None:
        if authorization.get("operation") != operation:
            raise AuthorityError("authorization operation mismatch")
        expires_at = authorization.get("expires_at")
        if not isinstance(expires_at, str) or _timestamp(expires_at) < time.time():
            raise AuthorityError("authorization expired or missing")

    def rotate(self, reason: str, authorization: dict[str, Any]) -> dict[str, Any]:
        self._authorization(authorization, "KEY_ROTATION")
        old = self.identity
        backup = self._backup(old)
        new = generate_identity()
        _atomic_write(self.identity_path, canonical_bytes(new))
        self.identity = new
        event = self.ledger.append(
            "KEY_ROTATION",
            {
                "reason": reason,
                "old_key_id": old["key_id"],
                "new_key_id": new["key_id"],
                "backup": backup,
            },
        )
        return {"status": "rotated", "key_id": new["key_id"], "sequence": event["sequence"]}

    def issue_capability(
        self,
        *,
        project_id: str,
        component: str,
        operation: str,
        scope: list[str],
        evidence_hash: str,
        ttl_seconds: int,
        authorization: dict[str, Any],
    ) -> dict[str, Any]:
        self._authorization(authorization, "CAPABILITY_ISSUE")
        if ttl_seconds < 1:
            raise AuthorityError("capability TTL must be positive")
        ttl = min(ttl_seconds, MAX_LEASE_SECONDS)
        issued = time.time()
        expires = issued + ttl
        issued_at = datetime.fromtimestamp(issued, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_at = datetime.fromtimestamp(expires, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        unsigned = {
            "lease_id": secrets.token_hex(16),
            "project_id": project_id,
            "component": component,
            "operation": operation,
            "scope": sorted(set(scope)),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "policy_epoch": int(authorization.get("policy_epoch", 0)),
            "sequence": self.ledger.sequence + 1,
            "evidence_hash": evidence_hash,
            "signer_key_id": self.identity["key_id"],
        }
        record = dict(unsigned)
        record["signature"] = sign(self.identity, unsigned)
        self.ledger.append("CAPABILITY_ALLOW", record)
        return record

    def verify_capability(self, lease: dict[str, Any]) -> None:
        if lease.get("signer_key_id") != self.identity["key_id"]:
            raise AuthorityError("capability was not signed by current identity")
        if _timestamp(lease["expires_at"]) < time.time():
            raise AuthorityError("capability expired")
        signature = lease.get("signature")
        if not isinstance(signature, str):
            raise AuthorityError("capability signature missing")
        unsigned = dict(lease)
        unsigned.pop("signature", None)
        if not verify(self.identity["public_key"], unsigned, signature):
            raise AuthorityError("capability signature invalid")
        if lease["sequence"] > self.ledger.sequence:
            raise AuthorityError("capability sequence is outside the ledger")
        self.ledger.verify()
