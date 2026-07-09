#![allow(unexpected_cfgs)]
#![allow(clippy::collapsible_if)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
//! Canonical verifier for CSV protocol proofs
//!
//! Provides the unified verification entry point for all proof types.
//! All verification must route through this verifier to ensure consistency.

pub mod anchors;
pub mod chain_proof_bundle;
mod verifier;

pub use anchors::{
    AnchorError, CanonicalBlockHeader, CanonicalInclusionProof, CryptographicAnchor,
    EthereumAnchor, FinalityGuarantee, Groth16PairingVerifier, ProofSystem, QuorumCertificate,
    UnavailableGroth16Verifier, ValidatorInfo, ValidatorSet, VerifiedHeader, ZkHeader,
    verify_zk_seal_unavailable, verify_zk_seal_with_pairing,
};
pub use chain_proof_bundle::{
    ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier, DynChainProofVerifier,
    inclusion_anchor_ref, verify_chain_proof_bundle,
};
pub use verifier::{
    CanonicalVerifier, CanonicalVerifierImpl, ExpectedDomain, VerificationContext,
    VerificationError, VerificationResult, verify_proof, verify_proof_bound,
};
