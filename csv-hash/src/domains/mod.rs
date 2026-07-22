//! Domain-separated hash types for Parwana
//!
//! This module provides domain-separated hash types for different
//! protocol contexts to prevent hash collisions across different use cases.
//! Migrated from csv-core/src/domains/mod.rs as part of hash-related modularization.

pub mod accountability;
pub mod aptos_anchor;
pub mod bitcoin_seal;
pub mod ethereum_mint;
pub mod genesis;
pub mod proof_bundle;
pub mod replay_registry;
pub mod sanad_id;
pub mod schema;
pub mod transfer_commitment;
pub mod transition;

// Re-export domain types for convenience
pub use accountability::{
    ACCOUNTABILITY_DOMAIN_TAGS, ActionIntentDomain, ActionMandateDomain, AssuranceProfileDomain,
    AuthorityReconstructionDomain, DisclosureCommitmentDomain, DisputeBundleDomain,
    EvidenceNodeDomain, ExecutionAttemptDomain, ExecutionReceiptDomain, GateProfileDomain,
    PreservationEnvelopeDomain, VerificationContextDomain,
};
pub use aptos_anchor::AptosAnchorDomain;
pub use bitcoin_seal::BitcoinSealDomain;
pub use ethereum_mint::EthereumMintDomain;
pub use genesis::GenesisDomain;
pub use proof_bundle::ProofBundleDomain;
pub use replay_registry::ReplayRegistryDomain;
pub use sanad_id::SanadIdDomain;
pub use schema::SchemaDomain;
pub use transfer_commitment::TransferCommitmentDomain;
pub use transition::TransitionDomain;
