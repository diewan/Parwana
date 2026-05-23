//! Finality Monitor
//!
//! Monitors the finality state of transactions across chains.

use crate::finality::{ChainFinalityPolicy, FinalityState};
use csv_hash::chain_id::ChainId;

/// Finality monitor for tracking transaction finality
pub struct FinalityMonitor {
    /// Chain-specific finality policies
    policies: std::collections::BTreeMap<String, Box<dyn ChainFinalityPolicy>>,
}

impl FinalityMonitor {
    /// Create a new finality monitor
    pub fn new() -> Self {
        let mut policies = std::collections::BTreeMap::new();

        // Add default policies for known chains
        policies.insert(
            "bitcoin".to_string(),
            Box::new(super::policy::BitcoinFinalityPolicy::new()) as Box<dyn ChainFinalityPolicy>,
        );
        policies.insert(
            "ethereum".to_string(),
            Box::new(super::policy::EthereumFinalityPolicy::new()) as Box<dyn ChainFinalityPolicy>,
        );
        policies.insert(
            "aptos".to_string(),
            Box::new(super::policy::AptosFinalityPolicy::new()) as Box<dyn ChainFinalityPolicy>,
        );

        Self { policies }
    }

    /// Register a finality policy for a chain
    pub fn register_policy(&mut self, chain: ChainId, policy: Box<dyn ChainFinalityPolicy>) {
        self.policies.insert(chain.as_str().to_string(), policy);
    }

    /// Get the finality policy for a chain
    pub fn get_policy(&self, chain: &ChainId) -> Option<&dyn ChainFinalityPolicy> {
        self.policies.get(chain.as_str()).map(|p| p.as_ref())
    }

    /// Create a new finality state for a transaction
    pub fn create_state(&self, chain: &ChainId, included_at: u64) -> FinalityState {
        let required = self
            .get_policy(chain)
            .map(|p| p.required_confirmations())
            .unwrap_or(6); // Default to 6 confirmations

        FinalityState::new(included_at, required)
    }

    /// Update finality state with current block height
    pub fn update_state(&self, state: &mut FinalityState, current_height: u64) {
        state.update(current_height);
    }

    /// Check if a transaction is finalized
    pub fn is_finalized(&self, state: &FinalityState) -> bool {
        state.is_finalized()
    }

    /// Check if a transaction was rolled back
    pub fn is_rolled_back(&self, state: &FinalityState) -> bool {
        state.is_rolled_back()
    }
}

impl Default for FinalityMonitor {
    fn default() -> Self {
        Self::new()
    }
}
