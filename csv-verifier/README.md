# csv-verifier

Canonical proof verification for CSV Protocol.

## Overview

`csv-verifier` provides the canonical proof verification logic for the CSV protocol. It ensures consistent verification semantics across all protocol implementations.

## Key Features

- **Canonical verification**: Standardized proof verification logic
- **Verification context**: Context-aware verification
- **Anchor verification**: Commitment anchor validation
- **Signature verification**: Multi-scheme signature validation
- **Inclusion proof verification**: Merkle proof validation
- **Finality proof verification**: Finality evidence validation
- **ZkSeal seam**: Fail-closed Groth16 verification boundary for RFC §9.5

## Architecture Role

`csv-verifier` is the verification layer that:

- Provides the single source of truth for proof verification
- Ensures all implementations verify proofs identically
- Delegates cryptographic operations to appropriate libraries
- Enforces protocol verification rules

## Dependencies

- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof bundle types
- `csv-hash`: Hash types and operations
- `thiserror`: Error handling

## Verification Process

The verifier checks:

1. **Signature scheme**: Proof bundle signature matches source chain
2. **Anchor validity**: Commitment anchor is valid
3. **Inclusion proof**: Merkle proof is valid
4. **Finality proof**: Finality evidence is sufficient
5. **Replay protection**: Transfer has not been replayed
6. **Protocol invariants**: All protocol rules are satisfied

## ZkSeal Verification

The RFC §9.5 ZkSeal path is wired as a fail-closed seam in `anchors.rs`.
`verify_zk_seal_with_pairing` validates the `ZkSealProof` envelope, requires
`ProofSystem::Groth16`, binds it to a nonzero `ZkHeader { circuit_id }`, and
delegates acceptance to a `Groth16PairingVerifier`. The default
`verify_zk_seal_unavailable` path always returns an unavailable error, so no
ZK proof is accepted before a real pairing backend lands.

The prover follow-up is a zkVM path using SP1 or RISC Zero to prove the existing
`csv-verifier` / `csv-algebra` checks plus a source-consensus zk-light-client
circuit, then submit a Groth16-verifiable `ZkSealProof` at this seam.

## Usage Example

```rust
use csv_verifier::{CanonicalVerifier, VerificationContext};

let verifier = CanonicalVerifier::new();
let context = VerificationContext {
    chain_id: /* ... */,
    required_finality: /* ... */,
};

let result = verifier.verify(&proof_bundle, &context)?;
```

## Design Principles

- **Canonical**: Single verification logic for all implementations
- **Context-aware**: Verification depends on chain and finality requirements
- **Delegated**: Cryptographic operations delegated to specialized libraries
- **Protocol-enforcing**: Rejects proofs that violate protocol invariants

## License

MIT OR Apache-2.0
