"""Sovereign Self-Fixer package."""

from __future__ import annotations

__version__ = "0.2.0"

from .analysis.deep_scanner import DeepScanner
from .core.self_fixer import SelfFixer
from .memory.repmhl import REPMHL
from .notifications import Notifier
from .security.encryption import EncryptionManager
from .security.tamper_lock import TamperHardLock
from .security.tpm import TPMManager

__all__ = [
    "__version__",
    "DeepScanner",
    "EncryptionManager",
    "Notifier",
    "REPMHL",
    "SelfFixer",
    "TamperHardLock",
    "TPMManager",
]
