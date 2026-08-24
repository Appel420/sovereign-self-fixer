"""Named sovereign crypto profiles."""

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
    "sovereign-offline": CryptoProfile(
        name="sovereign-offline",
        symmetric="chacha20poly1305",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="none",
        allow_pqc=False,
    ),
    "sovereign-hybrid": CryptoProfile(
        name="sovereign-hybrid",
        symmetric="chacha20poly1305",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="ml-kem-768",
        allow_pqc=True,
    ),
    "sovereign-online": CryptoProfile(
        name="sovereign-online",
        symmetric="aes256gcm",
        primary_hash="sha3_512",
        signing="ed25519",
        kem="ml-kem-768",
        allow_pqc=True,
    ),
    "sovereign-pqc-authority": CryptoProfile(
        name="sovereign-pqc-authority",
        symmetric="chacha20poly1305",
        primary_hash="sha3_512",
        signing="ml-dsa-87",
        kem="ml-kem-768",
        allow_pqc=True,
    ),
}


def get_profile(name: str) -> CryptoProfile:
    if name not in PROFILES:
        raise ValueError(f"Unknown crypto profile: {name!r}. Valid: {sorted(PROFILES)}")
    return PROFILES[name]


def hash_bytes(data: bytes, algo: str = "sha3_512") -> str:
    supported = {
        "sha3_512": hashlib.sha3_512,
        "sha256": hashlib.sha256,
        "sha3_256": hashlib.sha3_256,
    }
    if algo not in supported:
        raise ValueError(f"Unsupported hash algorithm: {algo!r}. Supported: {sorted(supported)}")
    return supported[algo](data).hexdigest()
