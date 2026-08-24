"""Post-quantum identity primitives backed by liboqs-python.

The package name is ``liboqs-python`` and its import name is ``oqs``.
This module deliberately fails closed when the requested PQC mechanisms are
not available; it never silently substitutes a classical primitive.
"""

from __future__ import annotations

import base64
import secrets
from typing import Any

import oqs

from .canonical import canonical_bytes

SIGNATURE_ALGORITHM = "ML-DSA-87"
KEM_ALGORITHM = "ML-KEM-768"


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def generate_identity() -> dict[str, Any]:
    """Generate a new ML-DSA-87 signing identity and ML-KEM-768 KEM key."""
    if SIGNATURE_ALGORITHM not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"{SIGNATURE_ALGORITHM} is not enabled in liboqs")
    if KEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError(f"{KEM_ALGORITHM} is not enabled in liboqs")

    with oqs.Signature(SIGNATURE_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        kem_public_key = kem.generate_keypair()
        kem_secret_key = kem.export_secret_key()

    return {
        "key_id": secrets.token_hex(16),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "kem_algorithm": KEM_ALGORITHM,
        "public_key": b64e(public_key),
        "secret_key": b64e(secret_key),
        "kem_public_key": b64e(kem_public_key),
        "kem_secret_key": b64e(kem_secret_key),
    }


def sign(identity: dict[str, Any], record: dict[str, Any]) -> str:
    """Sign a canonical authority record with the current ML-DSA key."""
    with oqs.Signature(
        SIGNATURE_ALGORITHM,
        secret_key=b64d(identity["secret_key"]),
    ) as signer:
        return b64e(signer.sign(canonical_bytes(record)))


def verify(
    public_key: str,
    record: dict[str, Any],
    signature: str,
) -> bool:
    """Verify an ML-DSA signature over a canonical authority record."""
    with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:
        return verifier.verify(
            canonical_bytes(record),
            b64d(signature),
            b64d(public_key),
        )
