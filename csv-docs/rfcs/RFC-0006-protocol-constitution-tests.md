# RFC-0006: Protocol Constitution Test Suite

**Status:** Proposed
**Author:** CSV Protocol Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC establishes a formal test suite at `tests/protocol_constitution/` that validates all protocol invariants and constitution rules. These tests serve as executable specifications that must pass for any protocol change.

## Motivation

The protocol has 11 documented invariants and a detailed constitution, but no automated test suite that validates them. This creates a gap between documented rules and enforced behavior.

## Design

### 1. Test Structure

```
tests/protocol_constitution/
├── mod.rs                          # Test module entry point
├── invariant_1_seal_ids.rs         # Invariant 1: Real blockchain transactions
├── invariant_2_commitment_anchor.rs # Invariant 2: On-chain commitment before proof
├── invariant_3_consignment_validator.rs # Invariant 3: Validation before AppState
├── invariant_4_native_units.rs     # Invariant 4: u64 native units
├── invariant_5_transfer_state.rs   # Invariant 5: TransferState machine
├── invariant_6_seal_registry.rs    # Invariant 6: SealRegistry check
├── invariant_7_domain_separation.rs # Invariant 7: Domain separation
├── invariant_8_verification_result.rs # Invariant 8: meets_chain_thresholds
├── invariant_9_replay_cas.rs       # Invariant 9: Replay CAS semantics
├── invariant_10_signature_scheme.rs # Invariant 10: Chain-derived scheme
├── invariant_11_zk_verifier.rs     # Invariant 11: Real chain-anchored keys
├── serialization_rules.rs          # Constitution Section 2 — Serialization
├── hashing_rules.rs                # Constitution Section 3 — Hashing
├── proof_encoding_rules.rs         # Constitution Section 4 — Proof Encoding
├── seal_semantics_rules.rs         # Constitution Section 5 — Seal Semantics
├── replay_protection_rules.rs      # Constitution Section 6 — Replay Protection
├── versioning_rules.rs             # Constitution Section 7 — Versioning
├── domain_separation_rules.rs      # Constitution Section 8 — Domain Separation
└── governance_rules.rs             # Constitution Section 14 — Governance
```

### 2. Test Categories

Each test falls into one of three categories:

- **Property tests** — Automated property-based tests (proptest)
- **Golden tests** — Compare against known-good fixtures
- **Compile-fail tests** — Verify forbidden patterns don't compile

### 3. Test Execution

```bash
# Run all constitution tests
cargo test -p csv-core --test protocol_constitution

# Run specific invariant test
cargo test -p csv-core --test protocol_constitution invariant_7_domain_separation

# Run with proptest verbose output
PROPTREE_VERBOSITY=3 cargo test -p csv-core --test protocol_constitution
```

## Implementation

### New Test File: `tests/protocol_constitution/mod.rs`

```rust
#[cfg(test)]
mod invariant_1_seal_ids;

#[cfg(test)]
mod invariant_2_commitment_anchor;

// ... etc
```

### Key Test Examples

**Invariant 1 — Real Seal IDs:**
```rust
#[test]
fn test_seal_id_from_real_transaction() {
    // Verify that SealPoint::new() rejects synthetic IDs
    assert!(SealPoint::new(&[], None).is_err());
    assert!(SealPoint::new(&[0u8; 32], None).is_err());
}
```

**Invariant 7 — Domain Separation:**
```rust
#[test]
fn test_no_raw_hashing_in_protocol_paths() {
    // Compile-fail test: direct sha256 calls should not compile
    // in protocol code paths
}
```

**Invariant 8 — Verification Result:**
```rust
#[test]
fn test_meets_chain_thresholds_required() {
    let result = verifier.verify(&bundle).unwrap();
    assert!(result.meets_chain_thresholds(&capabilities));
}
```

## Security Impact

- **Executable specifications** — Invariants are tested, not just documented
- **Regression prevention** — Protocol changes must pass all invariant tests
- **Documentation alignment** — Tests serve as living documentation

## References

- `csv-docs/PROTOCOL_INVARIANTS.md` — 11 protocol invariants
- `csv-docs/PROTOCOL_CONSTITUTION.md` — Full protocol constitution
- `csv-core/tests/compile_fail/` — Existing compile-fail tests
