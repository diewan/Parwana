# csv-wallet

Unified wallet abstraction layer for CSV (Client-Side Validation) protocol.

## Overview

`csv-wallet` provides a unified, chain-agnostic wallet abstraction that consolidates wallet logic previously scattered across multiple crates (`csv-keys`, `csv-coordinator`, `csv-sdk`). It defines a common `Signer` trait that all chain adapters implement, enabling consistent signing operations across Ethereum, Solana, Sui, Aptos, and Bitcoin.

## Benefits

### Architecture Simplification

**Before (Fragmented):**

- Wallet logic duplicated across `csv-keys`, `csv-coordinator`, and `csv-sdk`
- Each chain adapter had its own wallet implementation
- CLI had to understand chain-specific wallet APIs
- Tight coupling between wallet logic and chain-specific code

**After (Unified):**

- Single source of truth for wallet operations in `csv-wallet`
- Chain adapters implement a common `Signer` trait
- CLI interacts with unified wallet interface
- Clear separation: wallet logic vs. chain-specific logic

### Debugging Improvements

**Before:**

- Debugging wallet issues required understanding multiple codebases
- Inconsistent error handling across wallet implementations
- Hard to trace signing operations across different chains

**After:**

- Single entry point for wallet debugging
- Consistent error types (`WalletError`) across all chains
- Tracing signing operations is straightforward
- Chain-specific implementations are isolated and testable

### Security Enhancements

**Before:**

- Key management logic scattered across crates
- Inconsistent secret key handling
- Risk of key exposure through inconsistent APIs

**After:**

- Centralized key management with `secrecy` crate for zeroization
- Consistent secret key handling across all chains
- Clear security boundaries in `SecretVec` usage
- Type-safe signing operations with proper error handling

## Module Relationships

```
csv-wallet (unified wallet abstraction)
    ├── csv-protocol (SignatureScheme, protocol types)
    ├── csv-hash (hash types for key derivation)
    ├── csv-keys (legacy key management, being phased out)
    └── secrecy (secure secret storage)

Chain Adapters (implement csv-wallet Signer trait)
    ├── csv-ethereum → EthereumSigner (Secp256k1)
    ├── csv-solana → SolanaSigner (Ed25519)
    ├── csv-sui → SuiSigner (Ed25519)
    ├── csv-aptos → AptosSigner (Ed25519)
    └── csv-bitcoin → BitcoinSigner (Secp256k1)

Runtime Layer
    ├── csv-runtime (uses chain adapters via Signer trait)
    └── csv-coordinator (wallet logic migrating to csv-wallet)

CLI Layer
    ├── csv-cli (currently uses csv-coordinator, migrating to csv-wallet)
    └── Will use unified Signer trait for all wallet operations
```

## Core Components

### Signer Trait

The `Signer` trait provides a unified interface for signing operations:

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Signature>;
    fn public_key(&self) -> &[u8];
    fn signature_scheme(&self) -> SignatureScheme;
    fn as_ref(&self) -> SignerRef;
    fn chain(&self) -> &str;
}
```

**Benefits:**

- Chain-agnostic signing interface
- Async support for hardware wallets
- Type-safe signature schemes
- Consistent error handling

### Signature Types

- **Signature**: Chain-agnostic signature wrapper with scheme metadata
- **SignatureScheme**: Enum defining supported schemes (Secp256k1, Ed25519)
- **SignerRef**: Lightweight reference to a signer (ID, chain, public key)

### MemorySigner

In-memory signer implementation for testing and development:

- Stores secret keys in `SecretVec` for security
- Implements all signature schemes
- Useful for integration testing

### WalletManager

High-level wallet management (planned):

- Mnemonic-based key derivation
- Multi-chain wallet support
- Secure key storage integration
- Transaction signing orchestration

## Migration Path

### Phase 1: Chain Adapter Integration (Complete)

- ✅ Ethereum adapter: `EthereumSigner`
- ✅ Solana adapter: `SolanaSigner`
- ✅ Sui adapter: `SuiSigner`
- ✅ Aptos adapter: `AptosSigner`
- ✅ Bitcoin adapter: `BitcoinSigner`

### Phase 2: Runtime Integration (In Progress)

- Migrate `csv-coordinator` wallet logic to `csv-wallet`
- Update `csv-runtime` to use unified Signer trait
- Maintain backward compatibility during transition

### Phase 3: CLI Integration (Pending)

- Update `csv-cli` wallet commands to use `csv-wallet`
- Replace direct `csv-coordinator` wallet calls
- Simplify CLI wallet command architecture

## Usage Example

### Chain Adapter Integration

```rust
use csv_wallet::{Signer, SignerRef};
use csv_ethereum::EthereumSigner;

// Create signer from private key
let signer = EthereumSigner::new(
    "my-signer-id".to_string(),
    private_key_bytes,
)?;

// Sign a message
let signature = signer.sign(message).await?;

// Get public key
let pub_key = signer.public_key();

// Get signer reference
let signer_ref = signer.as_ref();
```

### CLI Integration (Future)

```rust
// Before: Chain-specific wallet operations
let eth_wallet = csv_coordinator::wallet::ethereum::derive_funding_address(...);
let sol_wallet = csv_coordinator::wallet::solana::derive_funding_address(...);

// After: Unified wallet operations
let wallet = csv_wallet::WalletManager::from_mnemonic(mnemonic)?;
let eth_address = wallet.address("ethereum", derivation_path)?;
let sol_address = wallet.address("solana", derivation_path)?;
```

## Security Considerations

### Secret Key Handling

- All secret keys wrapped in `SecretVec` for zeroization
- No secret key exposure in logs or error messages
- Secure key derivation using BIP-32/BIP-39 standards

### Signature Schemes

- Type-safe signature scheme enforcement
- No scheme confusion between chains
- Consistent verification across all adapters

### Error Handling

- No sensitive data in error messages
- Consistent error types for proper error handling
- Secure error propagation without key leakage

## Testing

### Unit Tests

- Signer trait implementation tests for each chain
- Signature verification tests
- Error handling tests

### Integration Tests

- Cross-chain signing tests
- Wallet manager tests
- CLI integration tests (future)

### Security Tests

- Secret key zeroization tests
- Key derivation tests
- Signature scheme enforcement tests

## Future Enhancements

1. **Hardware Wallet Support**: Extend Signer trait for hardware wallets
2. **Multi-Signature**: Support for multi-signature wallets
3. **Key Rotation**: Secure key rotation mechanisms
4. **Recovery**: Wallet recovery procedures
5. **Audit Logging**: Comprehensive audit trail for wallet operations

## Dependencies

- `csv-protocol`: Protocol types and signature schemes
- `csv-hash`: Hash functions for key derivation
- `secrecy`: Secure secret storage with zeroization
- `async-trait`: Async trait support
- `hex`: Hex encoding/decoding

## License

MIT OR Apache-2.0

## Contributing

See main repository contributing guidelines.
