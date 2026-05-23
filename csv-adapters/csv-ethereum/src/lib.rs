//! Ethereum Adapter for CSV (Client-Side Validation)
#![allow(clippy::needless_return)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::collapsible_if)]
//!
//! This adapter implements the SealProtocol trait for Ethereum,
//! using storage slots as single-use seals and LOG events for commitment publication.

#![warn(missing_docs)]
#![allow(missing_docs)]

#[cfg(feature = "rpc")]
pub mod bindings;
pub mod config;
pub mod contract_bytecode;
pub mod error;
pub mod finality;
pub mod mpt;
pub mod mint;
pub mod ops;
pub mod proofs;
pub mod rpc;
pub mod sanad_contract;
pub mod seal;
pub mod seal_contract;
pub mod seal_protocol;
pub mod signatures;
pub mod types;
pub mod verifier;
// pub mod zk_verifier;  // REMOVED: verification centralized in csv-verifier per implementation.md

#[cfg(feature = "rpc")]
pub mod node;

#[cfg(feature = "rpc")]
pub use node::{
    AlloyRpcError, EthereumNode, publish, publish_seal_consumption,
    verify_seal_consumption_in_receipt,
};

pub use config::EthereumConfig;
pub use error::EthereumError;
pub use finality::{FinalityChecker, FinalityConfig};
pub use rpc::EthereumRpc;
/// Mock Ethereum RPC for testing - ONLY available in test builds
/// 
/// Note: This mock is gated behind `#[cfg(test)]` to prevent it from being
/// used in production code. Integration tests in external crates that need
/// this mock should depend on it under `[dev-dependencies]` only.
#[cfg(test)]
pub use rpc::MockEthereumRpc;
pub use sanad_contract::{
    CsvLockAbi, CsvMintAbi, cross_chain_lock_signature, sanad_minted_signature,
    sanad_refunded_signature,
};
pub use seal_contract::CsvSealAbi;
pub use seal_protocol::EthereumSealProtocol;
pub use types::{
    EthereumCommitAnchor, EthereumFinalityProof, EthereumInclusionProof, EthereumSealPoint,
};
// pub use zk_verifier::{  // REMOVED: verification centralized in csv-verifier per implementation.md
//     EthereumGroth16Verifier, SolidityGroth16Proof, generate_verifier_contract_bytecode,
// };

// Ops exports
pub use ops::EthereumBackend;
