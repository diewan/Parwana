//! CSV Core — Client-Side Validation for Cross-Chain Sanads
//!
//! This crate provides the foundational types and traits for the CSV protocol:
//!
//! - **[`Sanad`]** — A verifiable, single-use digital sanad (deed) that can be
//!   transferred cross-chain
//! - **[`struct@Hash`]** — A 32-byte cryptographic hash (SHA-256 based)
//! - **[`Commitment`]** — A binding between a sanad's state and its anchor
//!   on a blockchain
//! - **[`SealPoint`]** / **[`CommitAnchor`]** — References to consumed seals
//!   and published anchors
//! - **[`InclusionProof`]** / **[`FinalityProof`]** / **[`ProofBundle`]** —
//!   Cryptographic proofs that a sanad was locked on the source chain
//! - **[`SealProtocol`]** — The core seal protocol trait each chain backend implements
//! - **[`SignatureScheme`]** — Supported signing algorithms (secp256k1, ed25519)
//!
//! ## Stability Tiers
//!
//! Items in this crate are categorized into three tiers:
//!
//! ### 🔒 Stable API
//! The public re-exports at the top level of this module are **stable API**.
//! They will not change without a semver-major version bump.
//!
//! ### 🟡 Beta API
//! Modules like `consignment`, `genesis`, `schema`, `state`, `transition` are
//! maturing and may receive additive changes. Breaking changes require a minor
//! version bump with deprecation warnings.
//!
//! ### 🧪 Experimental API
//! Modules like `vm`, `mpc`, `rgb_compat` are experimental and feature-gated
//! behind the `experimental` Cargo feature. They may change or be removed
//! without notice.
//!
//! ## Protocol Contract
//!
//! The canonical protocol types (chain IDs, transfer status, error codes,
//! capability flags) live in [`protocol_version`]. These types MUST be mirrored
//! across all protocol consumers: CLI, TypeScript SDK, MCP server, Explorer, Wallet.
//!
//! ## Stability
//!
//! The types re-exported from this module are considered **stable API**.
//! They will not change without a semver-major version bump. Internal modules
//! (state machine, VM, MPC) may evolve as the protocol matures.

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

extern crate alloc;

// No-std compatible collections
pub mod collections;

// Re-exports
pub use csv_hash::commitment::Commitment;
pub use csv_hash::sanad::SanadId;
pub use csv_hash::chain_id::ChainId;
pub use commitments_ext::CommitmentScheme;
pub use csv_hash::{
    Hash, HashDomain, HashParseError, DomainCategory,
    SealHash, CommitmentHash, SanadIdHash, NullifierHash, ReplayIdHash,
    VerificationHash, MerkleHash,
    MerkleProof, MerkleTree,
    Domain, DomainSeparatedHash,
    csv_tagged_hash, CSV_TAG_PREFIX,
    AptosAnchorDomain, BitcoinSealDomain, EthereumMintDomain, GenesisDomain,
    ProofBundleDomain, ReplayRegistryDomain, SchemaDomain, TransferCommitmentDomain, TransitionDomain,
};

// Advanced commitment types
pub mod commitments_ext;

// Recovery engine (Phase 2)
pub mod recovery_engine;


// Compatibility modules (types live in csv-hash / csv-proof / csv-protocol)
pub mod proof {
    pub use csv_proof::proof::{
        FinalityProof, InclusionProof, ProofBundle, ReplayId, MAX_FINALITY_DATA, MAX_PROOF_BYTES,
        MAX_SIGNATURES_TOTAL_SIZE,
    };
    pub use csv_proof::proof_types::{
        CompositeProof, ExecutionProof, Proof, ProofCategory, ProofPhase, ReplayProof,
        TransitionProof, ZKProof,
    };
}
pub mod sanad;
pub mod seal {
    pub use csv_hash::seal::{
        CommitAnchor, SealPoint, MAX_ANCHOR_ID_SIZE, MAX_ANCHOR_METADATA_SIZE, MAX_SEAL_ID_SIZE,
    };
}
pub mod commitment {
    pub use csv_hash::commitment::{Commitment, COMMITMENT_VERSION};
}
pub mod commit_mux {
    pub use csv_hash::commit_mux::{CommitMux, MerkleBranchNode, MuxLeaf, MuxProof, ProtocolId};
}
pub mod tagged_hash {
    pub use csv_hash::tagged_hash::{
        csv_tagged_hash, tagged_hash, tagged_hash_str, TaggedHash, CSV_TAG_PREFIX,
    };
}
pub mod canonical {
    pub use csv_hash::canonical::{
        canonical_hash, from_canonical_cbor, from_canonical_cbor_full,
        from_canonical_cbor_with_checksum, to_canonical_cbor, to_canonical_cbor_with_checksum,
        to_canonical_cbor_with_tag, CanonicalError, CBOR_TAG_RANGE_END, CBOR_TAG_RANGE_START,
    };
    pub use csv_hash::canonical::cbor_tags;
}
pub mod replay_registry;
pub mod proof_pipeline;

// pub mod rpc;

// Protocol version and canonical contract (🔒 STABLE + 🟡 BETA)
pub mod protocol_version;

// Agent-friendly types (AI agent support) - 🟡 BETA
pub mod mcp;

// Lease management for cross-chain transfers
pub mod lease;

// Production hardening - 🔒 STABLE
pub mod hardening;

// State machine types (Phase 1: Consignment Wire Format) - 🟡 BETA
pub mod consignment;
pub mod genesis;
pub mod state;
pub mod transition;

// Deterministic VM (Phase 3) - MOVED: should be separate crate per implementation.md
#[cfg(feature = "experimental")]
pub mod vm;

// DAG types — canonical definitions in csv-hash
pub mod dag;
pub mod signature;
/// Trust package primitives for offline verification bootstrapping.
pub mod trust_package;

// Phase 7: Contract hardening
pub mod canonical_events;
pub mod abi_constitution;
pub mod deployment;

// Phase 8: Runtime hardening
pub mod failure_domains;
pub mod deterministic_recovery;

// Phase 6: Replay protection and finality
pub mod replay_constitution;
pub mod finality;
pub mod chain_capabilities;

// Re-exports for convenience
pub use canonical_events::*;
pub use abi_constitution::*;
pub use deployment::*;
pub use failure_domains::*;
pub use deterministic_recovery::*;
pub use replay_constitution::*;
pub use finality::*;
pub use chain_capabilities::*;

// Trust package re-exports
pub use trust_package::{
    OfflineVerificationContext, TrustPackage, TrustPackageError,
};

/// Proof provenance metadata for forensic and deterministic verification.
pub mod proof_provenance;

/// Startup-time config validation helpers to assert capability alignment.
pub mod config_validation;

/// Runtime health and degraded-mode types used by runtime orchestration.
pub mod runtime_health;

/// Restart-safe finality anchoring — canonical chain snapshot persistence.
pub mod finality_anchor;

/// Protocol version compatibility matrix for version negotiation.
pub mod compatibility;

/// Chain-specific finality grades (SolanaCommitmentGrade, EthereumFinalityStage).
pub mod chain_specific;

/// Data authority tags — prevent explorer-authoritative state interpretation.
pub mod data_authority;

/// Persisted state transitions — atomic coupling of proofs and state changes.
pub mod persisted_transition;


/// Wallet capability separation and signing provider abstraction.
pub mod wallet_types;

// Error handling and traits - 🔒 STABLE
pub mod error;

// Chain operation traits (Production Guarantee Plan Phase 2) - 🔒 STABLE
pub mod backend;

// Shared event schemas (Production Guarantee Plan Phase 6) - 🔒 STABLE
pub mod events;

// Cross-cutting (Phase 10) - 🟡 BETA
pub mod monitor;
pub mod performance;
pub mod store;

// Store re-exports for csv-store and csv-p2p
pub use store::{AnchorRecord, SanadRecord, SanadStore, SealRecord, SealStore, StoreError};

// Transfer lifecycle state machine - 🔒 STABLE
pub mod transfer_stage;

// Client-side validation (Sprint 2)// Cross-chain transfer
pub mod client;
pub mod commitment_chain;
pub mod cross_chain;
pub mod state_store;
pub mod validator;
pub mod seal_protocol;

// Chain configuration system
pub mod chain_config;

// Multi-dimensional verification result types (Phase 1)
pub mod verified;

// RGB protocol compatibility (Sprint 5) - 🧪 EXPERIMENTAL
#[cfg(feature = "experimental")]
pub mod rgb;

// Tapret verification (Sprint 0.5) - MOVED: chain-specific, should be in csv-bitcoin adapter
// #[cfg(feature = "tapret")]
// pub mod tapret_verify;

// ZK proof infrastructure (Phase 5)
pub mod zk_proof;

// Atomic swap / HTLSE (Phase 3)
pub mod atomic_swap;

// Stealth addresses (Phase 3.3)
pub mod stealth;

// ===========================================================================
// Re-exports: Protocol Contract (🔒 STABLE + 🟡 BETA)
// ===========================================================================

// Protocol version, chain IDs, transfer status, error codes, capabilities
pub use protocol_version::{
    Capabilities, ErrorCode, PROTOCOL_VERSION, ProtocolVersion, SimplifiedTransferStatus,
    SyncStatus, TransferStatus, builtin, simplified_to_full,
};

// ===========================================================================
// Re-exports: Stable API (will not change without semver-major bump)
// ===========================================================================

pub use error::{ProtocolError, Result};
pub use csv_proof::proof::{FinalityProof, InclusionProof, ProofBundle};
pub use csv_hash::seal::{CommitAnchor, SealPoint};
pub use sanad::{OwnershipProof, Sanad, SanadEnvelope, Schema, SCHEMA_VERSION};
pub use seal_protocol::SealProtocol;
pub use dag::{DAGNode, DAGSegment};

pub use signature::{
    Signature, SignatureScheme, parse_signatures_from_bytes, verify_signatures, PQ_DEFAULT_SCHEME,
};

// Errors and traits

// Chain operations (Production Guarantee Plan Phase 2)
pub use backend::{
    BalanceInfo, ChainBackend, ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError,
    ChainOpResult, ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus,
    DeploymentStatus, FinalityStatus, SanadOperation, SanadOperationResult, TokenBalance,
    TransactionInfo, TransactionStatus,
};

// Event schemas (Production Guarantee Plan Phase 6)
pub use events::{
    CsvEvent, EventData, EventFilter, EventFinalityStatus, EventIndexer, EventIndexerRegistry,
    event_names, metadata_fields,
};

// Cross-chain transfer
pub use cross_chain::{
    CrossChainHashAlgorithm, CrossChainLockEvent, CrossChainRegistry, CrossChainRegistryEntry,
    CrossChainTransferProof, StandardTransferVerifier, CrossChainDomain,
};

// Transfer stage (protocol lifecycle)
pub use transfer_stage::TransferStage;
pub use csv_hash::nullifier::{
    DoubleSpendError, SealConsumption, SealNullifier,
};
#[cfg(feature = "std")]
pub use csv_hash::nullifier::OptimizedSealNullifier;


// ===========================================================================
// Re-exports: Beta API (may receive additive changes)
// ===========================================================================

// Advanced commitment types
pub use commitments_ext::{
    EnhancedCommitment, FinalityProofType, InclusionProofType, ProofMetadata,
};

// Agent-friendly types
pub use mcp::{
    AgentChainAdapterInfo, AgentCreateSealResult, AgentExportProofResult, AgentGetSanadsResult,
    AgentProtocolInfoResult, AgentRpcStatus, AgentSanadSummary, AgentSealStatus,
    AgentTransferResult, AgentTransferStatus, AgentVerifyProofResult, ErrorSuggestion,
    FixAction, HasErrorSuggestion, VerificationLevel, error_codes,
};

// Production hardening
pub use hardening::{
    BoundedQueue, CircuitBreaker, CircuitState, DEFAULT_CIRCUIT_MAX_FAILURES,
    DEFAULT_CIRCUIT_RESET_TIMEOUT_SECS, DEFAULT_HEALTH_CHECK_TIMEOUT_SECS, DEFAULT_RPC_TIMEOUT_SECS,
    MAX_CACHE_SIZE, MAX_REGISTRY_SIZE, MAX_SEAL_NULLIFIER_SIZE, MemoryLimits, TimeoutConfig,
};

// Finality depths (protocol defaults)
pub use protocol_version::FinalityDepths;

// State machine (Phase 1)
pub use consignment::{Consignment, CONSIGNMENT_VERSION};
pub use genesis::Genesis;
pub use state::{GlobalState, OwnedState, StateAssignment, StateRef};
pub use transition::Transition;
pub use store::InMemorySealStore;


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

/// Experimental module — feature-gated behind `experimental`.
/// These APIs may change or be removed without notice.
#[cfg(feature = "experimental")]

// ===========================================================================
// Re-exports: Phase 3 (Atomic Swap / HTLSE)
// ===========================================================================

pub use atomic_swap::{
    AtomicSwapBackend, AtomicSwapError, AtomicSwapOffer, AtomicSwapRegistry, AtomicSwapState,
    DefaultTimeouts, HashLock, SwapDirection, SwapRecord, blocks_to_duration, compute_swap_id,
    derive_hash_lock, is_timeout_valid, verify_hash_lock,
};

// ===========================================================================
// Re-exports: Phase 3 (Stealth Addresses)
// ===========================================================================

pub use stealth::{
    EphemeralPoint, ScanPublicKey, SpendPublicKey, StealthAddress, StealthAddressPair,
    StealthScanEntry, StealthWallet, compute_ephemeral_point, derive_stealth_base,
};

// ===========================================================================
// Re-exports: Phase 3 (Pedersen Commitments) - feature-gated
// ===========================================================================

#[cfg(feature = "zk")]
pub use zk_proof::pedersen;
