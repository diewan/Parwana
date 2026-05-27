#![allow(unexpected_cfgs)]
#![allow(clippy::collapsible_if)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
//! Canonical verifier for CSV protocol proofs
//!
//! Provides the unified verification entry point for all proof types.
//! All verification must route through this verifier to ensure consistency.

pub mod anchor;
pub mod chain_bundle;
mod verifier;

pub use anchor::{
    AnchorError, CanonicalBlockHeader, CanonicalInclusionProof, CryptographicAnchor,
    FinalityGuarantee, ProofSystem, QuorumCertificate, ValidatorInfo, ValidatorSet, VerifiedHeader,
};
pub use chain_bundle::{
    ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier, DynChainProofVerifier,
    inclusion_anchor_ref, verify_chain_proof_bundle,
};
pub use verifier::{
    CanonicalVerifier, CanonicalVerifierImpl, VerificationContext, VerificationError,
    VerificationResult, verify_proof,
};
