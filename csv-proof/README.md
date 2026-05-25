# csv-proof

Proof bundle types, replay ID derivation, and cryptographic proof structures for CSV Protocol.

## Overview

`csv-proof` provides the proof bundle types and cryptographic proof structures used for cross-chain verification in the CSV protocol.

## Key Features

- **Proof bundles**: Complete proof bundle structures
- **Signature schemes**: Support for multiple signature schemes (Ed25519, Secp256k1, etc.)
- **Replay ID derivation**: Derivation of replay identifiers from proof data
- **Proof components**: DAG segments, inclusion proofs, finality proofs
- **Provenance tracking**: Proof origin and verification chain metadata
- **Certification**: Deterministic certification for reproducible verification

## Modules

- **proof**: Proof bundle types and structures
- **signature**: Signature scheme types and verification
- **replay**: Replay ID derivation
- **provenance**: Proof provenance metadata
- **certification**: Proof certification types

## Architecture Role

`csv-proof` is the proof layer that:
- Defines the structure of proof bundles
- Provides replay ID derivation for nullifier tracking
- Supports multiple signature schemes for different chains
- Enables provenance tracking for audit trails

## Dependencies

- `csv-hash`: Hash types and operations
- `csv-codec`: Canonical serialization
- `thiserror`: Error handling
- `serde`: Serialization

## Proof Bundle Structure

A proof bundle contains:
- **version**: Protocol version
- **transition_dag**: State transition DAG segment
- **signatures**: Authorizing signatures
- **signature_scheme**: Required signature scheme for verification
- **seal_ref**: Seal reference
- **anchor_ref**: Commitment anchor reference
- **inclusion_proof**: Merkle inclusion proof
- **finality_proof**: Finality proof
- **provenance**: Optional provenance metadata
- **certification**: Optional certification metadata

## Usage Example

```rust
use csv_proof::{proof::ProofBundle, SignatureScheme};

let proof = ProofBundle {
    version: 1,
    transition_dag: /* ... */,
    signatures: vec![/* ... */],
    signature_scheme: SignatureScheme::Ed25519,
    seal_ref: /* ... */,
    anchor_ref: /* ... */,
    inclusion_proof: /* ... */,
    finality_proof: /* ... */,
    provenance: None,
    certification: None,
};
```

## Signature Schemes

- **Ed25519**: Ed25519 signatures (Solana, etc.)
- **Secp256k1**: Secp256k1 signatures (Bitcoin, Ethereum, etc.)
- **BLS**: BLS signatures (future support)

## Design Principles

- **Extensibility**: Support for multiple signature schemes
- **Replay protection**: Derive replay IDs from proof data
- **Provenance**: Track proof origin and verification chain
- **Determinism**: Support reproducible verification

## License

MIT OR Apache-2.0
