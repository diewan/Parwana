//! Cross-Chain Hash Transfer
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::cross_chain` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all cross-chain types from csv-protocol
pub use csv_protocol::cross_chain::{
    CrossChainHashAlgorithm, CrossChainDomain, CrossChainLockEvent, TransferState,
    InclusionProof, BitcoinMerkleProof, EthereumMPTProof, SuiCheckpointProof,
    AptosLedgerProof, SolanaSlotProof, ZkSealProof, VerifierKey, ZkPublicInputs,
    CrossChainFinalityProof, CrossChainTransferProof, HashEntry,
    CrossChainTransferResult, CrossChainError, LockProvider, TransferVerifier,
    MintProvider, CrossChainRegistryEntry, CrossChainRegistry,
};
