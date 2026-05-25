# csv-keys

Secure key storage for the CSV Protocol with BIP-39/BIP-44 support.

## Overview

`csv-keys` provides secure key storage and management for the CSV protocol, supporting multiple cryptographic algorithms and derivation paths.

## Features

- **bip44** — BIP-44 HD wallet derivation (enabled by default)
- **secp256k1** — Secp256k1 key support (Bitcoin, Ethereum)
- **ed25519** — Ed25519 key support (Solana, Sui)
- **bitcoin** — Bitcoin address derivation
- **wasm** — WebAssembly support
- **production** — Production-grade key derivation (Argon2)

## Keystore Backends

- **File-based**: Native filesystem storage
- **Memory-based**: In-memory storage (testing)
- **Browser storage**: IndexedDB browser storage (WASM)

## Security Notes

- Browser keystore PBKDF2-SHA256 derivation uses 600,000 iterations for newly written keys
- WASM random salt/nonce generation returns a crypto error when browser RNG is unavailable instead of panicking
- New browser encrypted storage keys use PBKDF2-SHA256 with 600,000 iterations
- Existing encrypted browser material written with older iteration counts should be migrated by decrypting with the old parameters and re-saving with the current manager

## Architecture Role

`csv-keys` provides:

- Key generation and storage
- HD wallet derivation (BIP-39/BIP-44)
- Multi-algorithm support (Secp256k1, Ed25519)
- Cross-platform storage (native, browser)

## Dependencies

- `bip39`: BIP-39 mnemonic generation
- `hdwallet`: BIP-44 HD derivation
- `secp256k1`: Secp256k1 cryptography
- `ed25519-dalek`: Ed25519 cryptography
- `argon2`: Password-based key derivation

## License

MIT OR Apache-2.0
