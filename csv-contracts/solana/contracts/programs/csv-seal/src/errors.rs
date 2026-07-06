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

    /// Lock has already been settled to the operator (mutually exclusive with refund)
    #[msg("Lock has already been settled")]
    AlreadySettled,

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

    /// Sanad not found
    #[msg("Sanad not found")]
    SanadNotFound,

    /// Invalid state root
    #[msg("Invalid state root")]
    InvalidStateRoot,

    /// Invalid asset/proof metadata
    #[msg("Invalid sanad metadata")]
    InvalidSanadMetadata,

    // ==================== Mint authentication (RFC-0012 §9) ====================
    /// A mint field that must be non-zero was zero (sanad_id/commitment/source_chain/lock_event_id/nullifier)
    #[msg("Malformed mint request: required field is zero")]
    InvalidMintRequest,

    /// Fewer distinct valid verifier signatures than the threshold
    #[msg("Insufficient verifier signatures for threshold")]
    InsufficientSignatures,

    /// A signature did not recover to an authorized verifier
    #[msg("Signature does not recover to an authorized verifier")]
    InvalidVerifierSignature,

    /// A signature was not the expected 65-byte r||s||v encoding, or had a high-s / bad v
    #[msg("Malformed verifier signature encoding")]
    MalformedSignature,

    /// The attestation expiry has passed
    #[msg("Mint attestation has expired")]
    AttestationExpired,

    /// The threshold is zero or exceeds the verifier set size
    #[msg("Invalid verifier threshold")]
    InvalidThreshold,

    /// Adding a verifier that is already present
    #[msg("Verifier already exists in the set")]
    VerifierAlreadyExists,

    /// Removing a verifier that is not present
    #[msg("Verifier not found in the set")]
    VerifierNotFound,

    /// The verifier set is at capacity
    #[msg("Verifier set is full")]
    VerifierSetFull,

    /// A verifier identity was not the expected 33-byte compressed public key
    #[msg("Malformed verifier public key")]
    MalformedVerifierKey,

    // ==================== Settlement authentication (RFC-0012 §10) ====================
    /// A settlement field that must be non-zero was zero
    #[msg("Malformed settlement request: required field is zero")]
    InvalidSettlementRequest,

    /// The settlement receipt expiry has passed
    #[msg("Settlement receipt has expired")]
    ReceiptExpired,

    /// The lock event has already been settled
    #[msg("Settlement already released for this lock event")]
    SettlementAlreadyReleased,
}
