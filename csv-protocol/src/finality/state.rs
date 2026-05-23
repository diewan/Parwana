//! Finality State Types
//!
//! Defines the different levels of finality that a transaction can have.

/// Finality status of a transaction
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinalityStatus {
    /// Transaction is pending (not yet confirmed)
    Pending,
    /// Transaction is confirmed but not yet final
    Confirmed,
    /// Transaction is finalized (cannot be rolled back)
    Finalized,
    /// Transaction was rolled back due to reorg
    RolledBack,
}

/// Finality state for a transaction
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalityState {
    /// Current status
    pub status: FinalityStatus,
    /// Block height when transaction was included
    pub included_at: u64,
    /// Current block height
    pub current_height: u64,
    /// Number of confirmations
    pub confirmations: u32,
    /// Required confirmations for finality
    pub required_confirmations: u32,
}

impl FinalityState {
    /// Create a new finality state
    pub fn new(included_at: u64, required_confirmations: u32) -> Self {
        Self {
            status: FinalityStatus::Pending,
            included_at,
            current_height: included_at,
            confirmations: 0,
            required_confirmations,
        }
    }

    /// Update with current block height
    pub fn update(&mut self, current_height: u64) {
        self.current_height = current_height;
        if current_height >= self.included_at {
            self.confirmations = (current_height - self.included_at) as u32;
        } else {
            // Reorg detected - transaction is no longer in chain
            self.status = FinalityStatus::RolledBack;
            return;
        }

        // Update status based on confirmations
        if self.confirmations >= self.required_confirmations {
            self.status = FinalityStatus::Finalized;
        } else if self.confirmations > 0 {
            self.status = FinalityStatus::Confirmed;
        } else {
            self.status = FinalityStatus::Pending;
        }
    }

    /// Check if the transaction is finalized
    pub fn is_finalized(&self) -> bool {
        self.status == FinalityStatus::Finalized
    }

    /// Check if the transaction was rolled back
    pub fn is_rolled_back(&self) -> bool {
        self.status == FinalityStatus::RolledBack
    }
}
