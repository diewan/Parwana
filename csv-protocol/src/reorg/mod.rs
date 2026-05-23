//! Reorg Detection and Handling
//!
//! This module provides mechanisms to detect and handle blockchain
//! reorganizations safely.

pub mod detector;
pub mod reconciliation;
pub mod rollback;

// Re-exports
pub use detector::ReorgDetector;
pub use reconciliation::{
    ChainBackendForReconciliation, ReconciliationEngine, ReconciliationResult,
};
pub use rollback::{RollbackHandler, RollbackResult, RollbackStorageBackend};
