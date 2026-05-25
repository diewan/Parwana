//! CSV Core — Runtime-Specific Modules
//!
//! This crate now contains only runtime-specific modules that have not yet been
//! migrated to specialized crates. Most protocol types have been moved to:
//! - `csv-protocol` — Protocol types and traits
//! - `csv-hash` — Hashing and cryptographic primitives
//! - `csv-proof` — Proof types and verification
//! - `csv-codec` — Serialization
//!
//! See `AGENTS.md` and `development/csv_migration_plan.md` for the migration plan.
//!
//! ## Remaining Modules
//!
//! The following modules are still in csv-core and need migration:
//! - `client` — Client-side validation engine
//! - `consignment` — Consignment wire format
//! - `transition` — State transitions
//! - `store` / `state_store` — Storage abstractions
//! - `recovery_engine` — Crash-safe recovery
//! - `trust_package` — Offline verification bootstrapping
//! - `validator` — Validation logic
//! - `mcp` — Agent-friendly types
//! - `performance` — Performance monitoring
//! - `adapter` — Adapter boundary
//! - `certification` — Proof certification
//! - `error` — Error types
//! - Various runtime health and provenance modules

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::let_and_return)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_map)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::unused_unit)]
#![allow(dead_code)]
#![allow(clippy::single_match)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::empty_line_after_outer_attr)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::needless_return)]
#![allow(unused_mut)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(unexpected_cfgs)]
#![allow(clippy::expect_used)] // Legacy shim: infallible canonical serialization

extern crate alloc;

// No-std compatible collections
pub mod collections;

// Re-exports
pub use csv_hash::chain_id::ChainId;
pub use csv_hash::commitment::Commitment;
pub use csv_hash::sanad::SanadId;
pub use csv_hash::{
    AptosAnchorDomain, BitcoinSealDomain, CSV_TAG_PREFIX, CommitmentHash, Domain, DomainCategory,
    DomainSeparatedHash, EthereumMintDomain, GenesisDomain, Hash, HashDomain, HashParseError,
    MerkleHash, MerkleProof, MerkleTree, NullifierHash, ProofBundleDomain, ReplayIdHash,
    ReplayRegistryDomain, SanadIdHash, SchemaDomain, SealHash, TransferCommitmentDomain,
    TransitionDomain, VerificationHash, csv_tagged_hash,
};
pub use csv_proof::commitments_ext::CommitmentScheme;

// Advanced commitment types
// pub mod commitments_ext; // DELETED - use csv_proof::commitments_ext

// Recovery engine (Phase 2)
pub mod recovery_engine;

// Compatibility modules (types live in csv-hash / csv-proof / csv-protocol)
// pub mod proof; // DELETED - use csv_proof::proof
// pub mod commitment; // DELETED - use csv_hash::commitment
// pub mod commit_mux; // DELETED - use csv_hash::commit_mux
// pub mod tagged_hash; // DELETED - use csv_hash::tagged_hash
// pub mod canonical; // DELETED - use csv_hash::canonical
// pub mod replay_registry; // Moved to csv-hash during migration
pub mod proof_pipeline;

// pub mod rpc;

// Agent-friendly types (AI agent support) - 🟡 BETA
pub mod mcp;

// State machine types (Phase 1: Consignment Wire Format) - 🟡 BETA
pub mod consignment;
// pub mod genesis; // DELETED - use csv_protocol::genesis
// pub mod state; // DELETED - use csv_protocol::state
pub mod transition;

// DAG types — canonical definitions in csv-hash
// pub mod dag; // DELETED - use csv_hash::dag
// pub mod signature; // DELETED - use csv_protocol::signature
/// Trust package primitives for offline verification bootstrapping.
pub mod trust_package;

// Phase 7: Contract hardening
// pub mod canonical_events; // DELETED - use csv_protocol::events
// pub mod abi_constitution; // DELETED - use csv_contract_bindings::abi_constitution
// pub mod deployment; // DELETED - use csv_contract_bindings::deployment

// Phase 6: Replay protection and finality
// pub mod replay_constitution; // Moved to csv-protocol during migration
// pub mod finality; // Moved to csv-protocol during migration
// pub mod chain_capabilities; // DELETED - use csv_protocol::finality::capabilities

// Trust package re-exports
pub use trust_package::{OfflineVerificationContext, TrustPackage, TrustPackageError};

/// Proof provenance metadata for forensic and deterministic verification.
pub mod proof_provenance;

// Startup-time config validation helpers to assert capability alignment.
// pub mod config_validation; // DELETED - depends on deleted chain_config

/// Runtime health and degraded-mode types used by runtime orchestration.
pub mod runtime_health;

// Restart-safe finality anchoring — canonical chain snapshot persistence.
// pub mod finality_anchor; // Moved to csv-protocol during migration

/// Protocol version compatibility matrix for version negotiation.
pub mod compatibility;

// Chain-specific finality grades (SolanaCommitmentGrade, EthereumFinalityStage).
// pub mod chain_specific; // Moved to csv-protocol during migration

/// Data authority tags — prevent explorer-authoritative state interpretation.
pub mod data_authority;

/// Persisted state transitions — atomic coupling of proofs and state changes.
pub mod persisted_transition;

/// Wallet capability separation and signing provider abstraction.
pub mod wallet_types;

// Error handling and traits - 🔒 STABLE
pub mod error;

// Chain operation traits (Production Guarantee Plan Phase 2) - 🔒 STABLE
// pub mod backend; // DELETED - use csv_protocol::backend

// Shared event schemas (Production Guarantee Plan Phase 6) - 🔒 STABLE
// pub mod events; // DELETED - use csv_protocol::events

// Cross-cutting (Phase 10) - 🟡 BETA
pub mod performance;
pub mod store;

// Client-side validation (Sprint 2)// Cross-chain transfer
pub mod client;
// pub mod commitment_chain; // DELETED - use csv_proof::commitment_chain
// pub mod cross_chain; // DELETED - use csv_protocol::cross_chain
pub mod state_store;
pub mod validator;
// pub mod seal_protocol; // DELETED - use csv_protocol::seal_protocol

// Multi-dimensional verification result types (Phase 1)
// pub mod verified; // DELETED - use csv_protocol::verified

// ZK proof infrastructure (Phase 5)
pub mod zk_proof;

// ===========================================================================
// Re-exports: Protocol Contract (🔒 STABLE + 🟡 BETA)
// ===========================================================================

// Protocol version, chain IDs, transfer status, error codes, capabilities
// DELETED - use csv_protocol::version
// pub use protocol_version::{
//     Capabilities, ErrorCode, PROTOCOL_VERSION, ProtocolVersion, SimplifiedTransferStatus,
//     SyncStatus, TransferStatus, builtin, simplified_to_full,
// };

// ===========================================================================
// Re-exports: Stable API (will not change without semver-major bump)
// ===========================================================================

#[cfg(feature = "std")]
pub use csv_hash::nullifier::OptimizedSealNullifier;
pub use csv_hash::nullifier::{DoubleSpendError, SealConsumption, SealNullifier};
pub use csv_hash::seal::{CommitAnchor, SealPoint};
pub use csv_protocol::proof_types::{FinalityProof, InclusionProof, ProofBundle};
pub use error::{ProtocolError, Result};

// ===========================================================================
// Re-exports: Beta API (may receive additive changes)
// ===========================================================================

// Advanced commitment types
pub use csv_proof::commitments_ext::{
    EnhancedCommitment, FinalityProofType, InclusionProofType, ProofMetadata,
};

// Agent-friendly types
pub use mcp::{
    AgentChainAdapterInfo, AgentCreateSealResult, AgentExportProofResult, AgentGetSanadsResult,
    AgentProtocolInfoResult, AgentRpcStatus, AgentSanadSummary, AgentSealStatus,
    AgentTransferResult, AgentTransferStatus, AgentVerifyProofResult, ErrorSuggestion, FixAction,
    HasErrorSuggestion, VerificationLevel, error_codes,
};

// Production hardening
// pub use hardening::{ // DELETED - use csv_protocol::invariants
//     BoundedQueue, CircuitBreaker, CircuitState, DEFAULT_CIRCUIT_MAX_FAILURES,
//     DEFAULT_CIRCUIT_RESET_TIMEOUT_SECS, DEFAULT_HEALTH_CHECK_TIMEOUT_SECS, DEFAULT_RPC_TIMEOUT_SECS,
//     MAX_CACHE_SIZE, MAX_REGISTRY_SIZE, MAX_SEAL_NULLIFIER_SIZE, MemoryLimits, TimeoutConfig,
// };

// Finality depths (protocol defaults)
// pub use protocol_version::FinalityDepths; // DELETED - use csv_protocol::version

// State machine (Phase 1)
pub use consignment::{CONSIGNMENT_VERSION, Consignment};
// pub use genesis::Genesis; // DELETED - use csv_protocol::genesis
// pub use state::{GlobalState, OwnedState, StateAssignment, StateRef}; // DELETED - use csv_protocol::state
pub use store::InMemorySealStore;
pub use transition::Transition;

// ===========================================================================
// Re-exports: Experimental API (feature-gated, may change)
// ===========================================================================

/// Experimental module — feature-gated behind `experimental`.
/// These APIs may change or be removed without notice.
#[cfg(feature = "experimental")]

/// Experimental module — feature-gated behind `experimental`.
/// These APIs may change or be removed without notice.
// #[cfg(feature = "experimental")]
// pub use vm::{
//     AluVmAdapter, DeterministicVM, MeteredVMAdapter, PassthroughVM, VMError, VMInputs, VMOutputs,
//     execute_transition,

// ===========================================================================
// Re-exports: Phase 3 (Pedersen Commitments) - feature-gated
// ===========================================================================

#[cfg(feature = "zk")]
pub use zk_proof::pedersen;
