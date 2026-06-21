# Sovereign Self-Fixer (Ara-hardened)

Autonomous self-healing AI system with TPM 2.0 hardware root of trust, persistent memory (REPMHL v1.3), voice orchestration, and post-quantum security.

## Core Features
- Three-layer TPM recovery (encrypted file → sealed blob → NV Index)
- XChaCha20-Poly1305 + ML-DSA-87 hybrid signing + retention policies
- REPMHL v1.3 with persistent FAISS vector index on disk
- Real VoiceConductor (Whisper + energy VAD + automated git push)
- AST-based dangerous call + bare except scanner
- Async self-healing loop with TPM sealing

## Project Structure
selffixerai/
├── core/self_fixer.py
├── security/ (tamper_lock, encryption, tpm)
├── analysis/deep_scanner.py
├── memory/repmhl.py          # v1.3 with persistent FAISS
├── notifications.py
└── main.py

skills/voice_conductor/

## Run
python -m selffixerai

No placeholders. No simulations. Sovereign by design.