#![allow(unexpected_cfgs)]
#![allow(clippy::collapsible_if)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
//! Canonical verifier for CSV protocol proofs
//!
//! Provides the unified verification entry point for all proof types.
//! All verification must route through this verifier to ensure consistency.

mod verifier;
pub mod chain_bundle;

pub use verifier::{
    verify_proof, CanonicalVerifier, CanonicalVerifierImpl, VerificationContext, VerificationResult,
    VerificationError,
};
pub use chain_bundle::{
    verify_chain_proof_bundle, inclusion_anchor_ref, ChainBundleError, ChainBundlePolicy,
    ChainNativeProofVerifier, DynChainProofVerifier,
};
