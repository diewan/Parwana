//! Protocol constants

/// Maximum proof size in bytes
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// Maximum finality data size in bytes
pub const MAX_FINALITY_DATA: usize = 4 * 1024;

/// Maximum total signatures size in bytes
pub const MAX_SIGNATURES_TOTAL_SIZE: usize = 1024 * 1024;

/// Maximum proof bundle size in bytes
pub const MAX_PROOF_BUNDLE_SIZE: usize = 1024 * 1024;

/// Minimum required confirmations for finality
pub const MIN_REQUIRED_CONFIRMATIONS: u64 = 6;

/// Maximum proof age in seconds (24 hours)
pub const MAX_PROOF_AGE_SECONDS: u64 = 86400;
