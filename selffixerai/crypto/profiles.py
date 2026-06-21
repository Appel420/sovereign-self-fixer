"""Named sovereign crypto profiles.

Profiles map a logical security posture to concrete algorithm selections.
Services must request a profile by name and use *only* the algorithms it
specifies.  Ad-hoc algorithm selection outside of a named profile is not
permitted.

Algorithm identifiers
---------------------
symmetric : ``"chacha20poly1305"`` | ``"aes256gcm"``
    Primary authenticated-encryption primitive.

primary_hash : ``"sha3_512"`` | ``"sha256"``
    High-assurance hash used for integrity and chaining.

signing : ``"ed25519"`` | ``"ml-dsa-87"``
    Signature scheme for manifests, checkpoints, and seals.
    ``"ml-dsa-87"`` requires the optional ``oqs-python`` dependency.

kem : ``"none"`` | ``"ml-kem-768"``
    Key-encapsulation mechanism for hybrid key exchange.
    ``"ml-kem-768"`` requires the optional ``oqs-python`` dependency.
    Ghost mode sets this to ``"none"`` because there is no remote party.

allow_pqc : bool
    Whether post-quantum primitives may be loaded.  False in ghost mode
    to keep the dependency surface minimal and deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class CryptoProfile:
    name: str
    symmetric: str
    primary_hash: str
    signing: str
    kem: str
    allow_pqc: bool


PROFILES: dict[str, CryptoProfile] = {
    # ------------------------------------------------------------------
    # sovereign-offline — ghost mode; no network, no PQC, minimal surface
    # ------------------------------------------------------------------
    "sovereign-offline": CryptoProfile(
        name="sovereign-offline",
        symmetric="chacha20poly1305",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="none",
        allow_pqc=False,
    ),
    # ------------------------------------------------------------------
    # sovereign-hybrid — local-first; PQC KEM for cloud key exchange
    # ------------------------------------------------------------------
    "sovereign-hybrid": CryptoProfile(
        name="sovereign-hybrid",
        symmetric="chacha20poly1305",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="ml-kem-768",
        allow_pqc=True,
    ),
    # ------------------------------------------------------------------
    # sovereign-online — connected; AES-256-GCM for HW-accelerated paths
    # ------------------------------------------------------------------
    "sovereign-online": CryptoProfile(
        name="sovereign-online",
        symmetric="aes256gcm",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="ml-kem-768",
        allow_pqc=True,
    ),
}


def get_profile(name: str) -> CryptoProfile:
    """Return the named profile or raise ``ValueError``."""
    if name not in PROFILES:
        raise ValueError(f"Unknown crypto profile: {name!r}. Valid: {sorted(PROFILES)}")
    return PROFILES[name]


def hash_bytes(data: bytes, algo: str = "sha3_512") -> str:
    """Hash *data* using the algorithm identifier from a crypto profile.

    Supported values for *algo*: ``"sha3_512"``, ``"sha256"``, ``"sha3_256"``.
    """
    _supported = {
        "sha3_512": hashlib.sha3_512,
        "sha256": hashlib.sha256,
        "sha3_256": hashlib.sha3_256,
    }
    if algo not in _supported:
        raise ValueError(f"Unsupported hash algorithm: {algo!r}. Supported: {sorted(_supported)}")
    return _supported[algo](data).hexdigest()
