import asyncio
import logging
import shutil
from typing import Optional

class TPMManager:
    def __init__(self):
        self.available = shutil.which("tpm2_createprimary") is not None
        self.nv_index = 0x1500000
        self.expected_pcrs = [0, 1, 2, 7]

    async def is_tpm_present(self) -> bool:
        if not self.available:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "tpm2_getcap", "properties-fixed",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return proc.returncode == 0
        except Exception:
            return False

    async def store_hash_chain_in_nv(self, data: str) -> bool:
        if not await self.is_tpm_present():
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "tpm2_nvwrite", str(self.nv_index), "-i", "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.communicate(input=data.encode())
            return proc.returncode == 0
        except Exception:
            return False

    async def read_hash_chain_from_nv(self):
        if not await self.is_tpm_present():
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                "tpm2_nvread", str(self.nv_index),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip() if proc.returncode == 0 else None
        except Exception:
            return None