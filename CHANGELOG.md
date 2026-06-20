# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Full TPM 2.0 integration with PCR policy sealing and unsealing
- NV Index support for automatic hash chain storage
- TPM Quote generation with full cryptographic verification
- Three-layer state recovery system (Encrypted File → TPM Sealed Blob → NV Index)
- Automatic periodic TPM sealing every 5 minutes (configurable)
- Shared single `TPMManager` instance across the entire application
- Web Inspector with real-time TPM status, Quote generation, and verification
- LiveTerminal commands: `tpm seal`, `tpm quote`
- Graceful degradation when TPM hardware is unavailable
- Comprehensive error handling and tamper detection
- Automated CI/CD pipeline with linting, type checking, testing, and security scanning
- Professional documentation including Installation Troubleshooting Guide
- `CONTRIBUTING.md` guidelines

### Changed
- Refactored recovery logic into clear layered fallback system
- Improved `TamperHardLock` to automatically update NV Index on every state change
- Centralized TPM instance management for consistency

## [0.1.0] - 2026-06-20

### Added
- Initial release of Sovereign Self-Fixer AI
- Core self-healing engine with syntax error detection and auto-fixing
- Encrypted state management using ChaCha20-Poly1305
- Ed25519-based tamper detection with hash chaining
- Encrypted backup system with retention policy
- Deep static code analysis using astroid
- Basic TPM 2.0 support (PCR sealing)
- Notification system