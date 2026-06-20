# Sovereign Self-Fixer

Autonomous self-healing AI system with TPM 2.0 hardware root of trust, PCR policy sealing, NV Index storage, and remote attestation support.

## Features

- Self-healing code repair (syntax errors, unsafe patterns)
- TPM 2.0 integration:
  - PCR policy sealing/unsealing
  - NV Index hash chain storage
  - TPM Quote generation + cryptographic verification
- Three-layer state recovery (encrypted file → TPM sealed blob → NV Index)
- Automatic periodic TPM sealing
- Tamper detection with Ed25519 + hash chaining
- Encrypted backups with retention policy
- Deep static analysis
- ScarLog audit integration
- Web Inspector + LiveTerminal support
- Graceful shutdown and error handling

## Requirements

- Python 3.10+
- TPM 2.0 capable system (or `swtpm` for development)
- `tpm2-tools` installed

## Installation

```bash
git clone https://github.com/Appel420/sovereign-self-fixer.git
cd sovereign-self-fixer
pip install -e ".[dev]"
```

## Installation Troubleshooting

### Common Issues

**1. `tpm2-tools` not found**
- **Error**: `FileNotFoundError: [Errno 2] No such file or directory: 'tpm2_getcap'`
- **Solution**: Install tpm2-tools
  ```bash
  # Debian/Ubuntu
  sudo apt install tpm2-tools

  # Fedora
  sudo dnf install tpm2-tools

  # Arch
  sudo pacman -S tpm2-tools
  ```

**2. TPM device not accessible**
- **Error**: `TPM not present` or permission denied on `/dev/tpmrm0`
- **Solution**:
  ```bash
  sudo usermod -aG tss $USER
  newgrp tss
  ```
  Then log out and back in.

**3. `swtpm` not working in development**
- Make sure you export the TCTI:
  ```bash
  export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
  ```

**4. Missing Python dependencies**
- Run:
  ```bash
  pip install -e ".[dev]"
  ```

**5. Permission issues with TPM**
- On some systems you may need:
  ```bash
  sudo chmod 666 /dev/tpmrm0
  ```
  (Not recommended for production)

## Usage

```bash
python -m selffixerai
```

## Architecture

The system uses layered defense:
1. Encrypted state with hash chaining
2. TPM PCR policy protection
3. NV Index as tamper-evident anchor
4. Automatic recovery across all layers

## Security Model

- ChaCha20-Poly1305 encryption
- Ed25519 signatures for tamper detection
- TPM-backed sealing with PCR policies
- Automatic logging of sensitive operations to ScarLog

- sovereign-self-fixer/
├── .git/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── selffixerai/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py
│   ├── notifications.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   └── deep_scanner.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── backup_manager.py
│   │   └── self_fixer.py
│   └── security/
│       ├── __init__.py
│       ├── encryption.py
│       ├── tamper_lock.py
│       └── tpm.py
├── tests/
├── .ruff.toml
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE
