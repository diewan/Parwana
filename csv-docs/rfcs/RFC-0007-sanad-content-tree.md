# RFC-0007: Sanad Content Tree with Selective Disclosure

**Status:** Proposed
**Author:** Parwana Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC introduces a merkleized content tree for Sanad payloads, enabling selective disclosure of Sanad fields while maintaining verifiable integrity. This supports privacy-preserving Sanad verification.

## Motivation

The current `Sanad` type stores all fields in a flat structure. This has privacy implications:

1. **Full disclosure** — Every verifier sees all Sanad fields
2. **No selective disclosure** — Cannot prove a field without revealing others
3. **No field-level integrity** — No way to prove a single field's validity independently

## Design

### 1. Sanad Content Tree

```rust
pub struct SanadContentTree {
    /// Root hash of the merkle tree containing all fields
    pub root: Hash,
    /// Field hashes in declaration order
    pub field_hashes: Vec<Hash>,
}

pub struct SanadField {
    pub name: &'static str,
    pub value: Vec<u8>,
    pub disclosed: bool,
}
```

### 2. Selective Disclosure Proof

```rust
pub struct SelectiveDisclosureProof {
    /// Fields being disclosed
    pub disclosed_fields: Vec<SanadField>,
    /// Merkle proof for each disclosed field
    pub merkle_proofs: Vec<MerkleProof>,
    /// Root hash (known to verifier)
    pub root: Hash,
}

impl SelectiveDisclosureProof {
    pub fn verify(&self, expected_root: Hash) -> bool {
        for (field, proof) in self.disclosed_fields.iter().zip(self.merkle_proofs.iter()) {
            let field_hash = csv_tagged_hash(
                format!("csv.sanad.field.{}", field.name).leak(),
                &field.value,
            );
            if !proof.verify(field_hash, self.root) {
                return false;
            }
        }
        true
    }
}
```

### 3. SanadEnvelope with Content Tree

```rust
pub struct SanadEnvelope {
    pub version: u32,
    pub schema_id: &'static str,
    pub sanad_id: Hash,
    pub payload_hash: Hash,      // Hash of content tree root
    pub merkle_root: Option<Hash>, // Optional content tree root
    pub disclosure_proof: Option<SelectiveDisclosureProof>,
}
```

### 4. Privacy Levels

| Level | Description |
|-------|-------------|
| L0 — Full Disclosure | All fields visible (current behavior) |
| L1 — Partial Disclosure | Some fields hidden, merkle proof provided |
| L2 — Zero-Knowledge | Fields proven without disclosure (future) |

## Implementation

### Changes to `csv-core/src/sanad.rs`

- Add `SanadContentTree` type
- Add `SelectiveDisclosureProof` type
- Add `SanadEnvelope.merkle_root` field
- Add `Sanad.to_content_tree()` method

### New Module: `csv-core/src/selective_disclosure.rs`

- `SelectiveDisclosureProof` implementation
- `build_disclosure_proof()` function
- `verify_disclosure_proof()` function

## Security Impact

- **Privacy preservation** — Selective disclosure reduces information leakage
- **Maintained integrity** — Merkle proofs ensure disclosed fields are authentic
- **Backward compatible** — L0 (full disclosure) remains the default

## References

- Protocol Constitution Section 13 — Sanads
- `csv-core/src/sanad.rs` — Current Sanad implementation
- `csv-core/src/merkle.rs` — Merkle tree implementation
