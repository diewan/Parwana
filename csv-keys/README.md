# csv-keys

Secure key storage for the CSV Protocol with BIP-39/BIP-44 support.

## Features

- **bip44** — BIP-44 HD wallet derivation (enabled by default)
- **secp256k1** — Secp256k1 key support
- **ed25519** — Ed25519 key support
- **bitcoin** — Bitcoin address derivation
- **wasm** — WebAssembly support
- **production** — Production-grade key derivation (Argon2)

## Keystore Backends

- File-based (native)
- Memory-based
- Browser storage (WASM)

## Security Notes

- Browser keystore PBKDF2-SHA256 derivation uses 600,000 iterations for newly written keys.
- WASM random salt/nonce generation returns a crypto error when browser RNG is unavailable instead of panicking.

## License

MIT OR Apache-2.0
