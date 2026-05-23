//! Error definitions for CSV Seal program

use anchor_lang::prelude::*;

#[error_code]
pub enum CsvError {
    /// Attempted to consume an already consumed sanad
    #[msg("Sanad has already been consumed")]
    AlreadyConsumed,
    
    /// Attempted to lock an already locked sanad
    #[msg("Sanad has already been locked")]
    AlreadyLocked,
    
    /// Lock record not found in registry
    #[msg("Lock record not found in registry")]
    LockNotFound,
    
    /// Refund timeout has not yet expired
    #[msg("Refund timeout has not yet expired")]
    RefundTimeoutNotExpired,
    
    /// Sanad has already been refunded
    #[msg("Sanad has already been refunded")]
    AlreadyRefunded,
    
    /// Caller is not authorized
    #[msg("Caller is not authorized")]
    NotAuthorized,
    
    /// Nullifier already registered for this sanad
    #[msg("Nullifier already registered")]
    NullifierAlreadyRegistered,
    
    /// Sanad has not been consumed
    #[msg("Sanad has not been consumed")]
    NotConsumed,
    
    /// Lock registry is full
    #[msg("Lock registry is full")]
    RegistryFull,
    
    /// Invalid chain ID
    #[msg("Invalid chain ID")]
    InvalidChainId,
    
    /// Invalid commitment
    #[msg("Invalid commitment")]
    InvalidCommitment,
    
    /// Proof verification failed
    #[msg("Proof verification failed")]
    InvalidProof,
    
    /// Sanad not found
    #[msg("Sanad not found")]
    SanadNotFound,
    
    /// Invalid state root
    #[msg("Invalid state root")]
    InvalidStateRoot,

    /// Invalid asset/proof metadata
    #[msg("Invalid sanad metadata")]
    InvalidSanadMetadata,
}
