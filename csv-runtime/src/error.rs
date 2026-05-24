//! Runtime error types

#![allow(missing_docs)]

use thiserror::Error;

use crate::failure_domain::FailureDomain;
use csv_protocol::verified::VerificationFailure;

/// Runtime errors that can occur during transfer execution
#[derive(Error, Debug)]
pub enum RuntimeError {
    /// Storage backend error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Adapter operation failed
    #[error("Adapter error: {0}")]
    Adapter(String),

    /// Transfer not found
    #[error("Transfer not found: {0}")]
    TransferNotFound(String),

    /// Invalid transfer state
    #[error("Invalid transfer state: {0}")]
    InvalidState(String),

    /// Concurrent coordinator conflict
    #[error("Concurrent coordinator conflict: {0}")]
    ConcurrentConflict(String),

    /// Lease conflict — another coordinator holds the lease
    #[error("Lease conflict: {0}")]
    LeaseConflict(String),

    /// Lease expired during mint operation
    #[error("Lease expired: {0}")]
    LeaseExpired(String),

    /// Replay detected — transfer already executed
    #[error("Replay detected: transfer with this ReplayId already exists")]
    ReplayDetected(csv_hash::ReplayIdHash),

    /// Mint failed after insert — needs recovery
    #[error("Mint failed: {cause}")]
    MintFailed { cause: String },

    /// Finality not met for chain
    #[error("Finality not met for chain {chain}")]
    FinalityNotMet {
        chain: csv_hash::chain_id::ChainId,
    },

    /// No policy registered for chain
    #[error("No finality policy registered for chain {0}")]
    NoPolicyForChain(csv_hash::chain_id::ChainId),
}

impl RuntimeError {
    /// Classify this error into a failure domain
    pub fn failure_domain(&self) -> FailureDomain {
        match self {
            RuntimeError::Storage(_) => FailureDomain::Storage,
            RuntimeError::Adapter(_) => FailureDomain::Rpc,
            RuntimeError::TransferNotFound(_) => FailureDomain::Storage,
            RuntimeError::InvalidState(_) => FailureDomain::Consensus,
            RuntimeError::ConcurrentConflict(_) => FailureDomain::Consensus,
            RuntimeError::LeaseConflict(_) => FailureDomain::Consensus,
            RuntimeError::LeaseExpired(_) => FailureDomain::Consensus,
            RuntimeError::ReplayDetected(_) => FailureDomain::Replay,
            RuntimeError::MintFailed { .. } => FailureDomain::Rpc,
            RuntimeError::FinalityNotMet { .. } => FailureDomain::Finality,
            RuntimeError::NoPolicyForChain(_) => FailureDomain::Consensus,
        }
    }
}

/// Errors specific to the transfer coordinator
#[derive(Error, Debug)]
pub enum TransferCoordinatorError {
    /// Replay detected — transfer already executed
    #[error("Replay detected: transfer with this ReplayId already exists")]
    ReplayDetected(csv_hash::ReplayIdHash),

    /// Unknown chain — adapter not registered
    #[error("Unknown chain: {0}")]
    UnknownChain(String),

    /// Unsupported operation for chain
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Verification failed thresholds check
    #[error("Verification failed: {0}")]
    VerificationFailed(VerificationFailure),

    /// Lock on source chain failed
    #[error("Lock failed: {0}")]
    LockFailed(String),

    /// No lease backend configured
    #[error("No lease backend configured")]
    NoLeaseBackend,

    /// Lease violation - coordinator does not own the lease
    #[error("Lease violation: {0}")]
    LeaseViolation(String),

    /// Transfer not found
    #[error("Transfer not found")]
    NotFound,

    /// Replay database error
    #[error("Replay database error: {0}")]
    ReplayDbError(String),

    /// Runtime error
    #[error("Runtime error: {0}")]
    RuntimeError(String),

    /// Finality verification failed
    #[error("Finality verification failed: {0}")]
    FinalityFailed(String),

    /// Proof building failed
    #[error("Proof building failed: {0}")]
    ProofBuildFailed(String),

    /// Proof verification failed (canonical verifier rejected the proof)
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// Mint on destination chain failed
    #[error("Mint failed: {0}")]
    MintFailed(String),

    /// Transfer already complete
    #[error("Transfer already complete")]
    AlreadyComplete,

    /// Transfer already rolled back
    #[error("Transfer already rolled back")]
    AlreadyRolledBack,
}

impl TransferCoordinatorError {
    /// Classify this error into a failure domain
    pub fn failure_domain(&self) -> FailureDomain {
        match self {
            TransferCoordinatorError::ReplayDetected(_) => FailureDomain::Replay,
            TransferCoordinatorError::UnknownChain(_) => FailureDomain::Consensus,
            TransferCoordinatorError::UnsupportedOperation(_) => FailureDomain::Consensus,
            TransferCoordinatorError::VerificationFailed(_) => FailureDomain::Verification,
            TransferCoordinatorError::LockFailed(_) => FailureDomain::Rpc,
            TransferCoordinatorError::NoLeaseBackend => FailureDomain::Consensus,
            TransferCoordinatorError::LeaseViolation(_) => FailureDomain::Consensus,
            TransferCoordinatorError::NotFound => FailureDomain::Storage,
            TransferCoordinatorError::ReplayDbError(_) => FailureDomain::Storage,
            TransferCoordinatorError::RuntimeError(_) => FailureDomain::Consensus,
            TransferCoordinatorError::FinalityFailed(_) => FailureDomain::Finality,
            TransferCoordinatorError::ProofBuildFailed(_) => FailureDomain::Verification,
            TransferCoordinatorError::ProofVerificationFailed(_) => FailureDomain::Verification,
            TransferCoordinatorError::MintFailed(_) => FailureDomain::Rpc,
            TransferCoordinatorError::AlreadyComplete => FailureDomain::Consensus,
            TransferCoordinatorError::AlreadyRolledBack => FailureDomain::Consensus,
        }
    }
}

impl From<RuntimeError> for TransferCoordinatorError {
    fn from(e: RuntimeError) -> Self {
        TransferCoordinatorError::RuntimeError(e.to_string())
    }
}
