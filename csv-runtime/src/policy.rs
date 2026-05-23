//! Runtime Policy Module
//!
//! This module centralizes all policy decisions that were previously
//! made by individual adapters. The runtime is the single authority for:
//! - Finality depth requirements (sourced from csv-core protocol defaults)
//! - RPC fallback behavior
//! - Retry logic
//! - Confirmation interpretation
//!
//! Adapters MUST NOT make policy decisions. They only execute operations
//! according to runtime-provided policies.

use std::time::Duration;
use crate::runtime_mode::RuntimeMode;

/// Runtime policy configuration
///
/// All policy decisions for cross-chain transfers are centralized here.
/// Adapters receive policy via RuntimeExecutionContext and MUST NOT
/// override or ignore these policies.
///
/// Finality depths are sourced from [`csv_core::FinalityDepths`] as defaults,
/// but may be overridden per-chain at runtime.
#[derive(Debug, Clone)]
pub struct RuntimePolicy {
    /// Finality depth required for each chain (defaults from csv-core)
    pub finality_depths: std::collections::HashMap<String, u64>,

    /// Whether to allow RPC fallback to simulated mode
    pub allow_rpc_fallback: bool,

    /// Maximum number of retry attempts for transient failures
    pub max_retries: u32,

    /// Retry delay between attempts
    pub retry_delay: Duration,

    /// Whether to enforce strict finality (no probabilistic finality)
    pub enforce_strict_finality: bool,

    /// Current runtime mode
    pub mode: RuntimeMode,
}

impl RuntimePolicy {
    /// Create a new runtime policy with default values sourced from csv-core.
    pub fn new() -> Self {
        let core_depths = csv_core::FinalityDepths::defaults();
        let mut finality_depths = std::collections::HashMap::new();

        // Populate from csv-core protocol defaults
        if let Some(d) = core_depths.for_chain("bitcoin") {
            finality_depths.insert("bitcoin".to_string(), d);
        }
        if let Some(d) = core_depths.for_chain("ethereum") {
            finality_depths.insert("ethereum".to_string(), d);
        }
        if let Some(d) = core_depths.for_chain("solana") {
            finality_depths.insert("solana".to_string(), d);
        }
        if let Some(d) = core_depths.for_chain("aptos") {
            finality_depths.insert("aptos".to_string(), d);
        }
        if let Some(d) = core_depths.for_chain("sui") {
            finality_depths.insert("sui".to_string(), d);
        }
        if let Some(d) = core_depths.for_chain("celestia") {
            finality_depths.insert("celestia".to_string(), d);
        }

        Self {
            finality_depths,
            allow_rpc_fallback: false,
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            enforce_strict_finality: true,
            mode: RuntimeMode::Normal,
        }
    }

    /// Create a new runtime policy with a specific mode
    pub fn with_mode(mode: RuntimeMode) -> Self {
        let mut policy = Self::new();
        policy.set_mode(mode);
        policy
    }

    /// Set the runtime mode and update policy settings accordingly.
    ///
    /// Note: enforce_strict_finality is always true regardless of mode.
    /// Finality is never optional in the CSV protocol.
    pub fn set_mode(&mut self, mode: RuntimeMode) {
        self.mode = mode;
        self.allow_rpc_fallback = mode.allows_rpc_fallback();
        self.enforce_strict_finality = true; // finality is always enforced
        self.max_retries = mode.max_retries();
        self.retry_delay = mode.retry_delay();
    }

    /// Get the required finality depth for a chain.
    ///
    /// Uses the runtime's configured depth, falling back to csv-core protocol
    /// defaults if not explicitly set, then to 1 as absolute minimum.
    pub fn finality_depth_for_chain(&self, chain_id: &str) -> Option<u64> {
        self.finality_depths
            .get(chain_id)
            .copied()
            .or_else(|| csv_core::FinalityDepths::defaults().for_chain(chain_id))
            .or(Some(1))
    }

   /// Set the finality depth for a specific chain
    pub fn set_finality_depth(&mut self, chain_id: String, depth: u64) {
        self.finality_depths.insert(chain_id, depth);
    }

    /// Check that the observed finality depth meets the required threshold for a chain.
    ///
    /// Returns `Err` if `observed < required` for the given chain.
    /// This enforces hard-fail finality: transfers are aborted if finality
    /// requirements are not met, regardless of runtime mode.
    pub fn check_finality_threshold(
        &self,
        chain: &str,
        observed: u64,
    ) -> Result<(), String> {
        let required = self.finality_depth_for_chain(chain);
        let required = required.unwrap_or(1);
        if observed < required {
            return Err(format!(
                "Chain {chain}: observed {observed} < required {required}"
            ));
        }
        Ok(())
    }

    /// Create a production policy (no fallbacks, strict enforcement)
    pub fn production() -> Self {
        Self::with_mode(RuntimeMode::Normal)
    }

    /// Create a development policy (allows fallbacks for testing)
    pub fn development() -> Self {
        Self::with_mode(RuntimeMode::Degraded)
    }

    /// Create an unsafe policy (emergency mode, minimal checks)
    pub fn unsafe_mode() -> Self {
        Self::with_mode(RuntimeMode::Unsafe)
    }
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_finality_depths() {
        let policy = RuntimePolicy::new();
        assert_eq!(policy.finality_depth_for_chain("bitcoin"), Some(6));
        assert_eq!(policy.finality_depth_for_chain("ethereum"), Some(15));
        assert_eq!(policy.finality_depth_for_chain("solana"), Some(32));
        assert_eq!(policy.finality_depth_for_chain("aptos"), Some(5));
        assert_eq!(policy.finality_depth_for_chain("sui"), Some(15));
        assert_eq!(policy.finality_depth_for_chain("celestia"), Some(100));
    }

    #[test]
    fn test_finality_depths_from_csv_core() {
        // Verify that runtime policy sources defaults from csv-core
        let core_depths = csv_core::FinalityDepths::defaults();
        let policy = RuntimePolicy::new();
        assert_eq!(policy.finality_depth_for_chain("bitcoin"), core_depths.for_chain("bitcoin"));
        assert_eq!(policy.finality_depth_for_chain("ethereum"), core_depths.for_chain("ethereum"));
    }

    #[test]
    fn test_finality_depth_fallback_to_csv_core() {
        let mut policy = RuntimePolicy::new();
        // Remove bitcoin from runtime policy
        policy.finality_depths.remove("bitcoin");
        // Should fall back to csv-core default
        assert_eq!(policy.finality_depth_for_chain("bitcoin"), Some(6));
    }

    #[test]
    fn test_set_custom_finality_depth() {
        let mut policy = RuntimePolicy::new();
        policy.set_finality_depth("bitcoin".to_string(), 12);
        assert_eq!(policy.finality_depth_for_chain("bitcoin"), Some(12));
    }

    #[test]
    fn test_production_policy() {
        let policy = RuntimePolicy::production();
        assert_eq!(policy.mode, RuntimeMode::Normal);
        assert!(!policy.allow_rpc_fallback);
        assert!(policy.enforce_strict_finality);
    }

    #[test]
    fn test_development_policy() {
        let policy = RuntimePolicy::development();
        assert_eq!(policy.mode, RuntimeMode::Degraded);
        assert!(policy.allow_rpc_fallback);
        // Finality is always enforced regardless of mode
        assert!(policy.enforce_strict_finality);
    }

    #[test]
    fn test_unsafe_policy() {
        let policy = RuntimePolicy::unsafe_mode();
        assert_eq!(policy.mode, RuntimeMode::Unsafe);
        assert!(policy.allow_rpc_fallback);
        // Finality is always enforced regardless of mode
        assert!(policy.enforce_strict_finality);
        assert!(policy.mode.requires_operator_confirmation());
    }

    #[test]
    fn test_set_mode() {
        let mut policy = RuntimePolicy::new();
        assert_eq!(policy.mode, RuntimeMode::Normal);

        policy.set_mode(RuntimeMode::Degraded);
        assert_eq!(policy.mode, RuntimeMode::Degraded);
        assert!(policy.allow_rpc_fallback);
        assert_eq!(policy.max_retries, 5);

        policy.set_mode(RuntimeMode::Unsafe);
        assert_eq!(policy.mode, RuntimeMode::Unsafe);
        assert_eq!(policy.max_retries, 1);
    }
}
