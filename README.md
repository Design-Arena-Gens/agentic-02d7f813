# Quantum CLI Encryptor

A secure command-line utility for Arch Linux that encrypts user-entered messages using the Australian National University Quantum Random Number Generator (QRNG) API, SHA-512 password hashing, and PBKDF2-based key derivation. The final ciphertext is always a 512-character hexadecimal string written to `<username>.txt`.

## Features

- Username sanitisation and safe file creation (`<username>.txt`)
- Optional quantum-generated strong passwords
- PBKDF2-HMAC-SHA512 key derivation with 150,000 iterations
- Quantum-sourced salt with `/dev/urandom` fallback
- Deterministic 512-character ciphertext via layered HMAC expansion
- Secure memory cleansing for passwords, salts, and ciphertext buffers
- Unit tests covering validation, hashing, file operations, and workflow integration

## Build

```bash
make
```

This produces the `quantum_cli` binary in the repository root.

## Usage

```bash
./quantum_cli
```

Interactive flow:

1. Enter an identifier for the output file (`<username>.txt`).
2. Type the message to encrypt.
3. Choose whether to supply your own strong password or generate one through the QRNG service.
4. The tool stores the plaintext briefly before replacing it with the encrypted 512-character string.

## Tests

```bash
make test
```

The suite validates SHA-512 output, PBKDF2 conformance, sanitisation rules, file handling, and an end-to-end encryption workflow.

## Dependencies

- Arch Linux toolchain with `gcc` and `make`
- `curl` (used to contact the ANU QRNG API)
- Network access for live quantum randomness; falls back to `/dev/urandom` if unavailable

All code links against the standard C library and does not require additional libraries.

## Security Notes

- Passwords and derived materials are zeroed after use to reduce residue in memory.
- Generated passwords satisfy length, case, digit, and symbol requirements.
- The QRNG salt is essential to the PBKDF2 process; ensure outbound HTTPS access for best entropy.
- Encrypted output is one-way and cannot be reversed without the original password and salt.

## License

MIT
