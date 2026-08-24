"""Authenticated authorization gate for privileged operations.

No privileged operation executes on an unsigned or expired authorization
object. The authorization must carry a signature verifiable by the
Sovereignty AI Gate public key, an expiry, and a matching operation.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class AuthorizationError(Exception):
    pass


class ExpiredAuthorizationError(AuthorizationError):
    pass


@dataclass(slots=True)
class AuthorizationDecision:
    allowed: bool
    operation: str
    reason: str
    actor: str = "unknown"
    expires_at: float = 0.0


class AuthorizationGate:
    """Verify signed, expiring authorization before privileged work."""

    CLOCK_SKEW_SECONDS = 30

    def __init__(self, gate_public_key: bytes | None = None) -> None:
        self._public_key = (
            Ed25519PublicKey.from_public_bytes(gate_public_key)
            if gate_public_key
            else None
        )

    def set_public_key(self, public_key: bytes) -> None:
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(
        self,
        authorization: dict[str, Any] | None,
        operation: str,
        now: float | None = None,
    ) -> AuthorizationDecision:
        if not authorization:
            return AuthorizationDecision(False, operation, "authorization missing")

        if authorization.get("operation") != operation:
            return AuthorizationDecision(False, operation, "operation mismatch")

        expires_at = authorization.get("expires_at")
        if not isinstance(expires_at, (int, float)):
            return AuthorizationDecision(False, operation, "expires_at missing or invalid")

        current = time.time() if now is None else now
        if expires_at + self.CLOCK_SKEW_SECONDS < current:
            raise ExpiredAuthorizationError(
                f"authorization expired at {expires_at}, now {current}"
            )

        signature = authorization.get("signature")
        if not signature:
            return AuthorizationDecision(False, operation, "signature missing")

        if self._public_key is None:
            return AuthorizationDecision(
                False, operation, "gate public key not configured"
            )

        signed_payload = {
            k: v for k, v in authorization.items() if k != "signature"
        }
        try:
            self._public_key.verify(
                base64.b64decode(signature),
                self._canonical(signed_payload),
            )
        except (InvalidSignature, ValueError, TypeError):
            return AuthorizationDecision(False, operation, "invalid signature")

        return AuthorizationDecision(
            True,
            operation,
            "authorized",
            actor=str(authorization.get("actor", "unknown")),
            expires_at=float(expires_at),
        )

    def require(
        self,
        authorization: dict[str, Any] | None,
        operation: str,
        now: float | None = None,
    ) -> AuthorizationDecision:
        decision = self.verify(authorization, operation, now=now)
        if not decision.allowed:
            raise AuthorizationError(decision.reason)
        return decision

    @staticmethod
    def fingerprint(authorization: dict[str, Any]) -> str:
        payload = {k: v for k, v in authorization.items() if k != "signature"}
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
