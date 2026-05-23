//! Rolled Back State
//!
//! Transfer rolled back due to chain reorg.

use super::TransferData;

/// Transfer has been rolled back due to reorg
#[derive(Clone, Debug)]
pub struct RolledBack {
    /// Shared transfer data
    pub data: TransferData,
    /// Reorg height
    pub reorg_height: u64,
    /// Rollback timestamp
    pub rolled_back_at: u64,
    /// Reason for rollback
    pub reason: String,
}

impl RolledBack {
    /// Create a new rolled back state
    pub fn new(data: TransferData, reorg_height: u64, reason: String) -> Self {
        Self {
            data,
            reorg_height,
            rolled_back_at: 0, // Will be set when rollback is recorded
            reason,
        }
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Get the rollback reason
    pub fn reason(&self) -> &str {
        &self.reason
    }
}
