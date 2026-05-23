//! Adversarial Testing Module
//!
//! This module provides utilities and test scenarios for testing the CSV runtime
//! under adversarial conditions including:
//! - High availability (HA) failover scenarios
//! - Blockchain reorg simulations
//! - Race conditions for concurrent operations
//! - Adversarial proof bundles
//! - Double-spend attempts
//! - Lease conflicts
//! - Finality rollbacks

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

/// Adversarial scenario configuration
#[derive(Debug, Clone)]
pub struct AdversarialConfig {
    /// Whether to enable reorg simulation
    pub enable_reorg_simulation: bool,
    /// Whether to enable HA failover simulation
    pub enable_ha_failover: bool,
    /// Whether to enable race condition injection
    pub enable_race_conditions: bool,
    /// Maximum reorg depth to simulate
    pub max_reorg_depth: u64,
    /// Delay before HA failover
    pub ha_failover_delay: Duration,
}

impl Default for AdversarialConfig {
    fn default() -> Self {
        Self {
            enable_reorg_simulation: true,
            enable_ha_failover: true,
            enable_race_conditions: true,
            max_reorg_depth: 10,
            ha_failover_delay: Duration::from_secs(5),
        }
    }
}

/// Simulated blockchain reorg
#[derive(Debug, Clone)]
pub struct SimulatedReorg {
    /// Block height where reorg occurs
    pub reorg_height: u64,
    /// New chain height after reorg
    pub new_height: u64,
    /// Blocks that were orphaned
    pub orphaned_blocks: Vec<u64>,
    /// Timestamp of reorg
    pub timestamp: SystemTime,
}

impl SimulatedReorg {
    /// Create a new simulated reorg
    pub fn new(reorg_height: u64, new_height: u64) -> Self {
        let orphaned_blocks = (reorg_height..new_height).collect();
        Self {
            reorg_height,
            new_height,
            orphaned_blocks,
            timestamp: SystemTime::now(),
        }
    }
}

/// HA failover scenario
#[derive(Debug, Clone)]
pub struct HAFailoverScenario {
    /// Original runtime instance ID
    pub original_runtime_id: uuid::Uuid,
    /// Failover runtime instance ID
    pub failover_runtime_id: uuid::Uuid,
    /// Time of failover
    pub failover_time: SystemTime,
    /// Whether failover was successful
    pub success: bool,
}

impl HAFailoverScenario {
    /// Create a new HA failover scenario
    pub fn new(original_runtime_id: uuid::Uuid, failover_runtime_id: uuid::Uuid) -> Self {
        Self {
            original_runtime_id,
            failover_runtime_id,
            failover_time: SystemTime::now(),
            success: false,
        }
    }
}

/// Race condition scenario
#[derive(Debug, Clone)]
pub struct RaceConditionScenario {
    /// Description of the race condition
    pub description: String,
    /// Number of concurrent operations
    pub concurrent_operations: usize,
    /// Expected outcome
    pub expected_outcome: RaceOutcome,
}

/// Expected outcome of a race condition test
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceOutcome {
    /// Exactly one operation should succeed
    ExactlyOneSuccess,
    /// All operations should fail
    AllFail,
    /// Operations should be serialized
    Serialized,
    /// Operations should be idempotent
    Idempotent,
}

/// Adversarial test runner
pub struct AdversarialTestRunner {
    #[allow(dead_code)]
    config: AdversarialConfig,
    reorgs: Vec<SimulatedReorg>,
    ha_failovers: Vec<HAFailoverScenario>,
    race_conditions: Vec<RaceConditionScenario>,
}

impl AdversarialTestRunner {
    /// Create a new adversarial test runner with default config
    pub fn new() -> Self {
        Self::with_config(AdversarialConfig::default())
    }

    /// Create a new adversarial test runner with custom config
    pub fn with_config(config: AdversarialConfig) -> Self {
        Self {
            config,
            reorgs: Vec::new(),
            ha_failovers: Vec::new(),
            race_conditions: Vec::new(),
        }
    }

    /// Add a simulated reorg scenario
    pub fn add_reorg(&mut self, reorg: SimulatedReorg) {
        self.reorgs.push(reorg);
    }

    /// Add an HA failover scenario
    pub fn add_ha_failover(&mut self, failover: HAFailoverScenario) {
        self.ha_failovers.push(failover);
    }

    /// Add a race condition scenario
    pub fn add_race_condition(&mut self, race: RaceConditionScenario) {
        self.race_conditions.push(race);
    }

    /// Get all reorg scenarios
    pub fn reorgs(&self) -> &[SimulatedReorg] {
        &self.reorgs
    }

    /// Get all HA failover scenarios
    pub fn ha_failovers(&self) -> &[HAFailoverScenario] {
        &self.ha_failovers
    }

    /// Get all race condition scenarios
    pub fn race_conditions(&self) -> &[RaceConditionScenario] {
        &self.race_conditions
    }

    /// Reset all scenarios
    pub fn reset(&mut self) {
        self.reorgs.clear();
        self.ha_failovers.clear();
        self.race_conditions.clear();
    }
}

impl Default for AdversarialTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Concurrent operation executor for race condition testing
pub struct ConcurrentExecutor {
    max_concurrent: usize,
}

impl ConcurrentExecutor {
    /// Create a new concurrent executor
    pub fn new(max_concurrent: usize) -> Self {
        Self { max_concurrent }
    }

    /// Execute operations concurrently and collect results
    pub async fn execute_concurrent<F, Fut, T>(
        &self,
        operations: Vec<F>,
    ) -> Vec<Result<T, Box<dyn std::error::Error + Send + Sync>>>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>> + Send,
        T: Send + Sync + 'static,
    {
        let semaphore = Arc::new(Mutex::new(0));
        let mut tasks = Vec::new();

        for op in operations {
            let semaphore = semaphore.clone();
            let max_concurrent = self.max_concurrent;
            let task = tokio::spawn(async move {
                // Limit concurrency
                let mut guard = semaphore.lock().await;
                if *guard < max_concurrent {
                    *guard += 1;
                    drop(guard);
                } else {
                    drop(guard);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    return Err("Concurrency limit exceeded".into());
                }

                let result = op().await;

                let mut guard = semaphore.lock().await;
                *guard -= 1;
                drop(guard);

                result
            });
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap_or_else(|e| Err(Box::new(e) as _)));
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_reorg() {
        let reorg = SimulatedReorg::new(100, 105);
        assert_eq!(reorg.reorg_height, 100);
        assert_eq!(reorg.new_height, 105);
        assert_eq!(reorg.orphaned_blocks.len(), 5);
    }

    #[test]
    fn test_ha_failover_scenario() {
        let original_id = uuid::Uuid::new_v4();
        let failover_id = uuid::Uuid::new_v4();
        let scenario = HAFailoverScenario::new(original_id, failover_id);
        assert_eq!(scenario.original_runtime_id, original_id);
        assert_eq!(scenario.failover_runtime_id, failover_id);
        assert!(!scenario.success);
    }

    #[test]
    fn test_adversarial_test_runner() {
        let mut runner = AdversarialTestRunner::new();
        runner.add_reorg(SimulatedReorg::new(100, 105));
        runner.add_ha_failover(HAFailoverScenario::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ));
        assert_eq!(runner.reorgs().len(), 1);
        assert_eq!(runner.ha_failovers().len(), 1);
        runner.reset();
        assert_eq!(runner.reorgs().len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_executor() {
        let executor = ConcurrentExecutor::new(2);
        let ops: Vec<Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, Box<dyn std::error::Error + Send + Sync>>> + Send>> + Send>> = vec![
            Box::new(|| Box::pin(async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(1) })),
            Box::new(|| Box::pin(async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(2) })),
            Box::new(|| Box::pin(async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(3) })),
        ];

        let results = executor.execute_concurrent(ops).await;
        assert_eq!(results.len(), 3);
    }
}
