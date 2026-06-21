"""TPM-aware environment sealing and attestation helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from .encryption import EncryptionManager


@dataclass(slots=True)
class TPMQuote:
    available: bool
    pcrs: dict[str, str]
    nonce: str
    digest: str
    raw_output: str = ""


class TPMManager:
    """Provide TPM-backed operations when hardware and tooling are available."""

    def __init__(self, working_dir: Path | None = None) -> None:
        self.working_dir = working_dir or Path.home() / ".local" / "share" / "sovereign-self-fixer"
        self.working_dir.mkdir(parents=True, exist_ok=True)
        self._available = self._detect_tpm_tools()

    @staticmethod
    def _detect_tpm_tools() -> bool:
        return shutil.which("tpm2_pcrread") is not None and (
            os.path.exists("/dev/tpmrm0") or os.environ.get("TPM2TOOLS_TCTI")
        )

    @property
    def available(self) -> bool:
        return self._available

    def read_pcrs(self, pcrs: tuple[int, ...] = (0, 7), hash_alg: str = "sha256") -> dict[str, str]:
        if not self.available:
            return {}

        selector = ",".join(str(pcr) for pcr in pcrs)
        result = subprocess.run(
            ["tpm2_pcrread", f"{hash_alg}:{selector}"],
            check=True,
            capture_output=True,
            text=True,
        )
        matches = re.findall(r"^\s*(\d+)\s*:\s*(0x[0-9a-fA-F]+)$", result.stdout, flags=re.MULTILINE)
        return {index: value for index, value in matches}

    def quote(self, pcrs: tuple[int, ...] = (7,)) -> TPMQuote:
        nonce = os.urandom(16).hex()
        pcr_map = self.read_pcrs(pcrs=pcrs)
        digest_source = json.dumps(pcr_map, sort_keys=True).encode("utf-8") or b"unavailable"
        digest = sha256(digest_source).hexdigest()
        return TPMQuote(
            available=self.available,
            pcrs=pcr_map,
            nonce=nonce,
            digest=digest,
            raw_output=json.dumps({"pcrs": pcr_map, "available": self.available}),
        )

    def seal_blob(self, data: bytes, label: str = "default") -> bytes:
        material = self._seal_material(label)
        manager = EncryptionManager(key_material=material)
        return manager.encrypt_bytes(data, associated_data=label.encode("utf-8"))

    def unseal_blob(self, blob: bytes, label: str = "default") -> bytes:
        material = self._seal_material(label)
        manager = EncryptionManager(key_material=material)
        return manager.decrypt_bytes(blob, associated_data=label.encode("utf-8"))

    def _seal_material(self, label: str) -> bytes:
        pcrs = json.dumps(self.read_pcrs(), sort_keys=True).encode("utf-8")
        machine = os.environ.get("HOSTNAME", "").encode("utf-8")
        return sha256(pcrs + machine + label.encode("utf-8")).digest()
