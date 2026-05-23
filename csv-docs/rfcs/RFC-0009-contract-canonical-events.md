# RFC-0009: Contract Canonical Events and ABI Constitution

**Status:** Proposed
**Author:** CSV Protocol Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC defines canonical event schemas for all smart contract implementations (Ethereum, Solana, Sui, Aptos) and establishes an ABI constitution that ensures cross-chain contract equivalence.

## Motivation

The current smart contracts have inconsistent event schemas across chains:

1. **Event schema inconsistency** — Different chains use different event names and structures
2. **No ABI constitution** — No formal specification of expected contract interfaces
3. **Cross-chain equivalence** — No way to verify that contracts on different chains implement the same protocol
4. **Deployment verification** — No mechanism to verify deployed bytecode matches reference

## Design

### 1. Canonical Event Schema

All chains MUST emit events matching the canonical schema:

```rust
// Canonical event names (matching csv-core/src/events.rs)
pub const EVENT_SANAD_CREATED: &str = "SanadCreated";
pub const EVENT_SANAD_CONSUMED: &str = "SanadConsumed";
pub const EVENT_CROSS_CHAIN_LOCK: &str = "CrossChainLock";
pub const EVENT_CROSS_CHAIN_MINT: &str = "CrossChainMint";
pub const EVENT_CROSS_CHAIN_REFUND: &str = "CrossChainRefund";
pub const EVENT_SANAD_TRANSFERRED: &str = "SanadTransferred";
pub const EVENT_NULLIFIER_REGISTERED: &str = "NullifierRegistered";
pub const EVENT_PROOF_ACCEPTED: &str = "ProofAccepted";
pub const EVENT_PROOF_REJECTED: &str = "ProofRejected";
pub const EVENT_REPLAY_DETECTED: &str = "ReplayDetected";
```

### 2. ABI Constitution

```
abi-constitution/
├── ethereum/
│   ├── CsvSeal.sol              # Reference contract
│   ├── CsvSeal.abi              # Canonical ABI
│   └── events.json              # Event schema
├── solana/
│   ├── csv-seal.ts              # Anchor IDL
│   └── events.json              # Event schema
├── sui/
│   ├── csv_seal.move            # Reference module
│   └── events.json              # Event schema
└── aptos/
    ├── csv_seal.move            # Reference module
    └── events.json              # Event schema
```

### 3. Cross-Chain Equivalence Test

```rust
#[test]
fn test_cross_chain_event_equivalence() {
    // Verify that the same logical event produces equivalent data
    // across all chain implementations
    let ethereum_event = parse_ethereum_event(eth_bytes);
    let solana_event = parse_solana_event(sol_bytes);
    let sui_event = parse_sui_event(sui_bytes);
    let aptos_event = parse_aptos_event(aptos_bytes);
    
    assert_eq!(ethereum_event.sanad_id, solana_event.sanad_id);
    assert_eq!(ethereum_event.sanad_id, sui_event.sanad_id);
    assert_eq!(ethereum_event.sanad_id, aptos_event.sanad_id);
}
```

### 4. Deployment Verification

```rust
pub struct ContractManifest {
    pub chain: ChainId,
    pub deployed_at: u64,
    pub bytecode_hash: Hash,
    pub abi_hash: Hash,
    pub events_hash: Hash,
    pub verified: bool,
}

impl ContractManifest {
    pub fn verify(&self, chain: &dyn ChainBackend) -> Result<bool, ProtocolError> {
        let deployed_bytecode = chain.get_contract_code(self.deployed_at)?;
        let deployed_hash = csv_tagged_hash("csv.contract.bytecode", &deployed_bytecode);
        Ok(deployed_hash == self.bytecode_hash)
    }
}
```

## Implementation

### Changes to `csv-contracts/`

- Standardize event names across all chain implementations
- Add event schema JSON files
- Add deployment verification scripts

### New Module: `csv-core/src/contract_events.rs`

- Canonical event name constants
- Event parsing utilities
- Cross-chain event equivalence verification

## Security Impact

- **Event consistency** — Canonical event schemas prevent misinterpretation
- **Contract verification** — Bytecode hash verification prevents unauthorized deployments
- **Cross-chain equivalence** — Ensures all chains implement the same protocol logic

## References

- Protocol Constitution Section 4 — Proof Encoding
- Protocol Constitution Section 12 — Finality and Inclusion Proofs
- `csv-contracts/ethereum/contracts/` — Ethereum contracts
- `csv-contracts/solana/contracts/` — Solana contracts
- `csv-contracts/sui/contracts/` — Sui contracts
- `csv-contracts/aptos/contracts/` — Aptos contracts
