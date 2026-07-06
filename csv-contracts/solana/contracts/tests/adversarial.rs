//! Adversarial coverage map for the CSV Seal Solana program (RFC-0012 thin registry).
//!
//! The proof-root / Merkle-inclusion mint model this file used to target has been
//! removed (TRM-SOL-CTR-001). Under the thin-registry model, cross-chain validity is
//! decided OFF-CHAIN; the on-chain authenticity check is a verifier-signed §9.2
//! attestation, and replay protection is the uniqueness of the minted-sanad,
//! nullifier, and lock-event tombstone PDAs.
//!
//! The executable adversarial tests for the authentication primitives live in the
//! program crate itself and run under `cargo test` (host toolchain):
//! `programs/csv-seal/src/tests.rs`. They cover:
//!
//! | Attack                                   | Test                                                  |
//! |------------------------------------------|-------------------------------------------------------|
//! | Forged attestation (unknown verifier)    | `forged_signature_from_unknown_key_is_rejected`       |
//! | Cross-attestation signature replay       | `signature_over_a_different_digest_is_rejected`       |
//! | Signature malleability (high-s)          | `recover_rejects_high_s_malleable_signature`          |
//! | Threshold griefing via duplicate signer  | `duplicate_signatures_do_not_satisfy_two_of_n`        |
//! | Sub-threshold signature count            | `too_few_signatures_is_rejected` / `empty_signature_set_is_rejected` |
//! | Digest byte-layout drift from the ABI    | `mint_digest_matches_independent_sha256_over_287_byte_preimage`      |
//! | Silent field drop in the digest          | `mint_digest_is_field_sensitive`                      |
//!
//! On-chain replay attacks that require a bank/`litesvm` runtime — duplicate
//! `sanad_id` / `nullifier` / `lock_event_id` mint, and account close+reopen reuse —
//! are enforced structurally: each of `MintRecord`, `NullifierRecord`,
//! `LockEventRecord`, and `SettlementRecord` is created with Anchor `init` (which
//! fails if the PDA already exists) and is NEVER closed by any instruction, so a
//! repeated key or a closed-then-reopened account cannot mint again. Wiring a
//! `litesvm` harness to exercise these end-to-end is tracked as a follow-up.
