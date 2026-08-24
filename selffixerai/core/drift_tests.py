"""Regression tests for drift enforcement and authorization."""

from __future__ import annotations

import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from selffixerai.core.authorization import (
    AuthorizationError,
    AuthorizationGate,
    ExpiredAuthorizationError,
)
from selffixerai.core.drift import DriftEnforcer, DriftSeverity


class TestDriftEnforcer(unittest.TestCase):
    def test_undeclared_vercel_drift_is_denied(self) -> None:
        enforcer = DriftEnforcer("ghost")
        env = {"VERCEL": "1", "VERCEL_ENV": "production", "VERCEL_URL": "app.vercel.app"}
        finding = enforcer.evaluate(env)
        self.assertEqual(finding.severity, DriftSeverity.UNDECLARED)
        self.assertEqual(finding.action, "deny")
        with self.assertRaises(PermissionError):
            enforcer.enforce(env)

    def test_self_hosted_matches_ghost(self) -> None:
        enforcer = DriftEnforcer("ghost")
        finding = enforcer.evaluate({"PATH": "/usr/bin"})
        self.assertEqual(finding.severity, DriftSeverity.NONE)
        self.assertEqual(finding.action, "allow")

    def test_online_mode_allows_cloud(self) -> None:
        enforcer = DriftEnforcer("online")
        env = {"VERCEL": "1"}
        finding = enforcer.evaluate(env)
        self.assertEqual(finding.action, "allow")


class TestAuthorizationGate(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes_raw()
        self.gate = AuthorizationGate(self.public)

    def _auth(self, operation: str, expires_in: int = 900) -> dict:
        import json

        payload = {
            "operation": operation,
            "actor": "sovereignty-ai-gate",
            "expires_at": time.time() + expires_in,
            "nonce": "test-nonce",
        }
        sig = self.private.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        import base64

        payload["signature"] = base64.b64encode(sig).decode()
        return payload

    def test_missing_authorization_denied(self) -> None:
        decision = self.gate.verify(None, "KEY_ROTATION")
        self.assertFalse(decision.allowed)
        with self.assertRaises(AuthorizationError):
            self.gate.require(None, "KEY_ROTATION")

    def test_expired_authorization_raises(self) -> None:
        auth = self._auth("KEY_ROTATION", expires_in=-10)
        with self.assertRaises(ExpiredAuthorizationError):
            self.gate.require(auth, "KEY_ROTATION", now=time.time())

    def test_forged_authorization_denied(self) -> None:
        auth = self._auth("KEY_ROTATION")
        auth["signature"] = "AAAA"  # not valid base64 of a real signature
        decision = self.gate.verify(auth, "KEY_ROTATION")
        self.assertFalse(decision.allowed)

    def test_valid_authorization_allowed(self) -> None:
        auth = self._auth("CAPABILITY_ISSUE")
        decision = self.gate.verify(auth, "CAPABILITY_ISSUE")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.actor, "sovereignty-ai-gate")

    def test_operation_mismatch_denied(self) -> None:
        auth = self._auth("KEY_ROTATION")
        decision = self.gate.verify(auth, "KEY_REVOCATION")
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
