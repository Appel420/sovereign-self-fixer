"""Declared-vs-observed deployment drift enforcement.

The invariant: declared runtime mode must match observed deployment evidence.
If the policy says self-hosted/ghost but the observed environment is a
managed cloud platform (e.g. Vercel), the mismatch is undeclared drift and
must fail closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DriftSeverity(str, Enum):
    NONE = "none"
    UNDECLARED = "undeclared"
    FORBIDDEN = "forbidden"


@dataclass(slots=True)
class DriftFinding:
    severity: DriftSeverity
    declared: str
    observed: str
    evidence: dict[str, Any] = field(default_factory=dict)
    action: str = "allow"


class DriftEnforcer:
    """Compare declared policy against observed deployment signals."""

    CLOUD_MARKERS: tuple[str, ...] = (
        "VERCEL",
        "VERCEL_ENV",
        "VERCEL_URL",
        "NETLIFY",
        "RAILWAY_ENVIRONMENT",
        "RENDER",
        "FLY_APP_NAME",
        "AWS_EXECUTION_ENV",
        "K_SERVICE",
        "FUNCTION_TARGET",
    )

    def __init__(self, declared_mode: str) -> None:
        self.declared_mode = (declared_mode or "ghost").strip().lower()

    def observe(self, environ: dict[str, str] | None = None) -> dict[str, Any]:
        env = environ if environ is not None else dict(os.environ)
        markers = {k: env[k] for k in self.CLOUD_MARKERS if k in env and env[k]}
        observed = "cloud" if markers else "self-hosted"
        return {"observed": observed, "markers": markers}

    def evaluate(self, environ: dict[str, str] | None = None) -> DriftFinding:
        observation = self.observe(environ)
        observed = observation["observed"]
        declared = self.declared_mode

        if declared in {"ghost", "hybrid"} and observed == "cloud":
            return DriftFinding(
                severity=DriftSeverity.UNDECLARED,
                declared=declared,
                observed=observed,
                evidence=observation,
                action="deny",
            )

        if declared == "online" and observed == "self-hosted":
            # Online mode without cloud markers is allowed but logged.
            return DriftFinding(
                severity=DriftSeverity.NONE,
                declared=declared,
                observed=observed,
                evidence=observation,
                action="allow_with_log",
            )

        if declared == observed or (declared == "online" and observed == "cloud"):
            return DriftFinding(
                severity=DriftSeverity.NONE,
                declared=declared,
                observed=observed,
                evidence=observation,
                action="allow",
            )

        return DriftFinding(
            severity=DriftSeverity.FORBIDDEN,
            declared=declared,
            observed=observed,
            evidence=observation,
            action="deny",
        )

    def enforce(self, environ: dict[str, str] | None = None) -> DriftFinding:
        finding = self.evaluate(environ)
        if finding.action == "deny":
            raise PermissionError(
                "undeclared deployment drift: "
                f"declared={finding.declared} observed={finding.observed} "
                f"markers={finding.evidence.get('markers', {})}"
            )
        return finding
