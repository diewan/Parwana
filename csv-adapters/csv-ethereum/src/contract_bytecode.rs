//! Pre-compiled contract bytecode for CSV lock and mint contracts.
//!
//! These constants are populated by `forge build` in the contracts directory.
//! When no pre-compiled bytecode is available, deployment will return
//! `CapabilityUnavailable` errors.

/// CSVLock contract bytecode (without constructor arguments)
pub const CSVLOCK_BYTECODE: &[u8] = &[];

/// CSVMint contract bytecode (without constructor arguments)
pub const CSVMINT_BYTECODE: &[u8] = &[];
