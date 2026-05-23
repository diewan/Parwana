//! RPC Metrics
//!
//! This module provides metrics collection for RPC operations,
//! tracking latency, success rates, provider health, and quorum disagreements.
//!
//! ## Metrics
//!
//! - `rpc_disagreement_total` — Count of RPC provider disagreements (quorum failures)
//! - `rpc_latency_ms` — Latency of RPC requests in milliseconds
//! - `provider_failure_total` — Count of provider failures
//! - `provider_timeout_total` — Count of provider timeouts
//! - `proof_verification_total` — Count of proof verification attempts
//! - `proof_verification_failed_total` — Count of failed proof verifications
//! - `replay_detection_total` — Count of replay detection checks
//! - `replay_detected_total` — Count of detected replays
//! - `rollback_triggered_total` — Count of rollbacks triggered
//! - `proof_pipeline_latency_ms` — Latency from lock confirmation to mint confirmation
//! - `verification_component_failure_total` — Count of verification component failures

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

// =========================================================================
// RPC Metrics
// =========================================================================

/// RPC operation metrics with atomic counters for thread safety
#[derive(Debug)]
pub struct RpcMetrics {
    /// Total number of requests
    total_requests: AtomicU64,
    /// Number of successful requests
    successful_requests: AtomicU64,
    /// Number of failed requests
    failed_requests: AtomicU64,
    /// Number of timeout failures
    timeout_failures: AtomicU64,
    /// Number of quorum disagreements
    disagreement_count: AtomicU64,
    /// Total latency in milliseconds
    total_latency_ms: AtomicU64,
    /// Provider-specific metrics
    provider_metrics: BTreeMap<String, Arc<ProviderMetrics>>,
}

/// Provider-specific metrics with atomic counters
#[derive(Debug)]
pub struct ProviderMetrics {
    /// Provider URL
    pub url: String,
    /// Number of requests to this provider
    requests: AtomicU64,
    /// Number of successful requests
    successful: AtomicU64,
    /// Number of failed requests
    failed: AtomicU64,
    /// Number of timeout failures
    timeouts: AtomicU64,
    /// Total latency in milliseconds
    total_latency_ms: AtomicU64,
    /// Last successful response timestamp
    last_success: AtomicU64,
    /// Last failure timestamp
    last_failure: AtomicU64,
}

impl ProviderMetrics {
    /// Create new provider metrics
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            requests: AtomicU64::new(0),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            last_success: AtomicU64::new(0),
            last_failure: AtomicU64::new(0),
        }
    }

    /// Record a successful request
    pub fn record_success(&self, latency_ms: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.successful.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.last_success.store(latency_ms, Ordering::Relaxed);
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(0, Ordering::Relaxed);
    }

    /// Record a timeout
    pub fn record_timeout(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.timeouts.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(0, Ordering::Relaxed);
    }

    /// Get average latency
    pub fn avg_latency_ms(&self) -> f64 {
        let requests = self.requests.load(Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }
        self.total_latency_ms.load(Ordering::Relaxed) as f64 / requests as f64
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let requests = self.requests.load(Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }
        self.successful.load(Ordering::Relaxed) as f64 / requests as f64
    }

    /// Get snapshot for display
    pub fn snapshot(&self) -> ProviderSnapshot {
        ProviderSnapshot {
            url: self.url.clone(),
            requests: self.requests.load(Ordering::Relaxed),
            successful: self.successful.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            avg_latency_ms: self.avg_latency_ms(),
            success_rate: self.success_rate(),
        }
    }
}

/// Snapshot of provider metrics for display
#[derive(Debug)]
pub struct ProviderSnapshot {
    pub url: String,
    pub requests: u64,
    pub successful: u64,
    pub failed: u64,
    pub timeouts: u64,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
}

/// Snapshot of RPC metrics for display
#[derive(Debug)]
pub struct RpcMetricsSnapshot {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub timeout_failures: u64,
    pub disagreement_count: u64,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub providers: Vec<ProviderSnapshot>,
}

impl RpcMetrics {
    /// Create new RPC metrics
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            timeout_failures: AtomicU64::new(0),
            disagreement_count: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            provider_metrics: BTreeMap::new(),
        }
    }

    /// Get or create provider metrics
    fn get_or_create_provider(&mut self, provider: &str) -> Arc<ProviderMetrics> {
        if let Some(metrics) = self.provider_metrics.get(provider) {
            return metrics.clone();
        }
        let metrics = Arc::new(ProviderMetrics::new(provider));
        self.provider_metrics
            .insert(provider.to_string(), metrics.clone());
        metrics
    }

    /// Record a successful RPC request
    pub fn record_success(&mut self, provider: &str, latency_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        let metrics = self.get_or_create_provider(provider);
        metrics.record_success(latency_ms);
    }

    /// Record a failed RPC request
    pub fn record_failure(&mut self, provider: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.failed_requests.fetch_add(1, Ordering::Relaxed);

        let metrics = self.get_or_create_provider(provider);
        metrics.record_failure();
    }

    /// Record a timeout
    pub fn record_timeout(&mut self, provider: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.timeout_failures.fetch_add(1, Ordering::Relaxed);

        let metrics = self.get_or_create_provider(provider);
        metrics.record_timeout();
    }

    /// Record a quorum disagreement
    pub fn record_disagreement(&mut self) {
        self.disagreement_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.successful_requests.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// Get average latency
    pub fn avg_latency_ms(&self) -> f64 {
        let successful = self.successful_requests.load(Ordering::Relaxed);
        if successful == 0 {
            return 0.0;
        }
        self.total_latency_ms.load(Ordering::Relaxed) as f64 / successful as f64
    }

    /// Get provider metrics
    pub fn get_provider_metrics(&self, provider: &str) -> Option<Arc<ProviderMetrics>> {
        self.provider_metrics.get(provider).cloned()
    }

    /// Get all provider metrics
    pub fn all_provider_metrics(&self) -> Vec<Arc<ProviderMetrics>> {
        self.provider_metrics.values().cloned().collect()
    }

    /// Get a snapshot of all metrics
    pub fn snapshot(&self) -> RpcMetricsSnapshot {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let timeouts = self.timeout_failures.load(Ordering::Relaxed);
        let disagreements = self.disagreement_count.load(Ordering::Relaxed);

        RpcMetricsSnapshot {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            timeout_failures: timeouts,
            disagreement_count: disagreements,
            avg_latency_ms: if successful == 0 {
                0.0
            } else {
                self.total_latency_ms.load(Ordering::Relaxed) as f64 / successful as f64
            },
            success_rate: if total == 0 {
                0.0
            } else {
                successful as f64 / total as f64
            },
            providers: self
                .provider_metrics
                .values()
                .map(|m| m.snapshot())
                .collect(),
        }
    }
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Proof Verification Metrics
// =========================================================================

/// Metrics for proof verification attempts
#[derive(Debug)]
pub struct ProofMetrics {
    /// Total verification attempts
    total_verifications: AtomicU64,
    /// Successful verifications
    successful_verifications: AtomicU64,
    /// Failed verifications
    failed_verifications: AtomicU64,
    /// Verification failures by component
    component_failures: BTreeMap<String, Arc<AtomicU64>>,
}

impl ProofMetrics {
    /// Create new proof metrics
    pub fn new() -> Self {
        Self {
            total_verifications: AtomicU64::new(0),
            successful_verifications: AtomicU64::new(0),
            failed_verifications: AtomicU64::new(0),
            component_failures: BTreeMap::new(),
        }
    }

    /// Record a successful verification
    pub fn record_success(&self) {
        self.total_verifications.fetch_add(1, Ordering::Relaxed);
        self.successful_verifications.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed verification with component breakdown
    pub fn record_failure(&mut self, component: &str) {
        self.total_verifications.fetch_add(1, Ordering::Relaxed);
        self.failed_verifications.fetch_add(1, Ordering::Relaxed);

        let counter = self
            .component_failures
            .entry(component.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total verification attempts
    pub fn total(&self) -> u64 {
        self.total_verifications.load(Ordering::Relaxed)
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.successful_verifications.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// Get component failure counts
    pub fn component_failures(&self) -> BTreeMap<String, u64> {
        self.component_failures
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }
}

impl Default for ProofMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Replay Detection Metrics
// =========================================================================

/// Metrics for replay detection
#[derive(Debug)]
pub struct ReplayMetrics {
    /// Total replay checks performed
    total_checks: AtomicU64,
    /// Replays detected
    replays_detected: AtomicU64,
    /// Replays detected via pre-insert check
    pre_insert_detections: AtomicU64,
    /// Replays detected via insert conflict
    insert_conflict_detections: AtomicU64,
}

impl ReplayMetrics {
    /// Create new replay metrics
    pub fn new() -> Self {
        Self {
            total_checks: AtomicU64::new(0),
            replays_detected: AtomicU64::new(0),
            pre_insert_detections: AtomicU64::new(0),
            insert_conflict_detections: AtomicU64::new(0),
        }
    }

    /// Record a replay detection via pre-insert check
    pub fn record_pre_insert_replay(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.replays_detected.fetch_add(1, Ordering::Relaxed);
        self.pre_insert_detections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replay detection via insert conflict
    pub fn record_insert_conflict_replay(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.replays_detected.fetch_add(1, Ordering::Relaxed);
        self.insert_conflict_detections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a clean check (no replay)
    pub fn record_clean(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total checks
    pub fn total_checks(&self) -> u64 {
        self.total_checks.load(Ordering::Relaxed)
    }

    /// Get replay rate
    pub fn replay_rate(&self) -> f64 {
        let total = self.total_checks();
        if total == 0 {
            return 0.0;
        }
        self.replays_detected.load(Ordering::Relaxed) as f64 / total as f64
    }
}

impl Default for ReplayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Rollback Metrics
// =========================================================================

/// Metrics for rollbacks triggered
#[derive(Debug)]
pub struct RollbackMetrics {
    /// Total rollbacks triggered
    total_rollbacks: AtomicU64,
    /// Rollbacks by reason
    rollbacks_by_reason: BTreeMap<String, Arc<AtomicU64>>,
}

impl RollbackMetrics {
    /// Create new rollback metrics
    pub fn new() -> Self {
        Self {
            total_rollbacks: AtomicU64::new(0),
            rollbacks_by_reason: BTreeMap::new(),
        }
    }

    /// Record a rollback with reason
    pub fn record_rollback(&mut self, reason: &str) {
        self.total_rollbacks.fetch_add(1, Ordering::Relaxed);

        let counter = self
            .rollbacks_by_reason
            .entry(reason.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total rollbacks
    pub fn total(&self) -> u64 {
        self.total_rollbacks.load(Ordering::Relaxed)
    }

    /// Get rollback reasons
    pub fn by_reason(&self) -> BTreeMap<String, u64> {
        self.rollbacks_by_reason
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }
}

impl Default for RollbackMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Proof Pipeline Metrics
// =========================================================================

/// Metrics for proof pipeline latency
#[derive(Debug)]
pub struct PipelineMetrics {
    /// Total pipeline executions
    total_executions: AtomicU64,
    /// Total pipeline latency in milliseconds
    total_latency_ms: AtomicU64,
    /// Pipeline latencies by chain
    chain_latency: BTreeMap<String, Arc<PipelineChainMetrics>>,
}

/// Per-chain pipeline metrics
#[derive(Debug)]
pub struct PipelineChainMetrics {
    /// Chain name
    pub chain: String,
    /// Total executions
    executions: AtomicU64,
    /// Total latency
    total_latency_ms: AtomicU64,
}

impl PipelineChainMetrics {
    /// Create new chain metrics
    pub fn new(chain: &str) -> Self {
        Self {
            chain: chain.to_string(),
            executions: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
        }
    }

    /// Record a pipeline execution
    pub fn record(&self, latency_ms: u64) {
        self.executions.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
    }

    /// Get average latency
    pub fn avg_latency_ms(&self) -> f64 {
        let execs = self.executions.load(Ordering::Relaxed);
        if execs == 0 {
            return 0.0;
        }
        self.total_latency_ms.load(Ordering::Relaxed) as f64 / execs as f64
    }
}

impl PipelineMetrics {
    /// Create new pipeline metrics
    pub fn new() -> Self {
        Self {
            total_executions: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            chain_latency: BTreeMap::new(),
        }
    }

    /// Get or create chain metrics
    fn get_or_create_chain(&mut self, chain: &str) -> Arc<PipelineChainMetrics> {
        if let Some(metrics) = self.chain_latency.get(chain) {
            return metrics.clone();
        }
        let metrics = Arc::new(PipelineChainMetrics::new(chain));
        self.chain_latency.insert(chain.to_string(), metrics.clone());
        metrics
    }

    /// Record a pipeline execution
    pub fn record_execution(&mut self, chain: &str, latency_ms: u64) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);

        let chain_metrics = self.get_or_create_chain(chain);
        chain_metrics.record(latency_ms);
    }

    /// Get average latency
    pub fn avg_latency_ms(&self) -> f64 {
        let execs = self.total_executions.load(Ordering::Relaxed);
        if execs == 0 {
            return 0.0;
        }
        self.total_latency_ms.load(Ordering::Relaxed) as f64 / execs as f64
    }

    /// Get chain metrics
    pub fn chain_metrics(&self, chain: &str) -> Option<Arc<PipelineChainMetrics>> {
        self.chain_latency.get(chain).cloned()
    }

    /// Get all chain metrics
    pub fn all_chain_metrics(&self) -> Vec<Arc<PipelineChainMetrics>> {
        self.chain_latency.values().cloned().collect()
    }
}

impl Default for PipelineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Unified Metrics Collector
// =========================================================================

/// Unified metrics collector that aggregates all CSV protocol metrics.
///
/// This is the primary interface for emitting observability events.
/// Each metric category is independent and can be used separately.
pub struct MetricsCollector {
    /// RPC metrics
    pub rpc: RpcMetrics,
    /// Proof verification metrics
    pub proof: ProofMetrics,
    /// Replay detection metrics
    pub replay: ReplayMetrics,
    /// Rollback metrics
    pub rollback: RollbackMetrics,
    /// Proof pipeline metrics
    pub pipeline: PipelineMetrics,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            rpc: RpcMetrics::new(),
            proof: ProofMetrics::new(),
            replay: ReplayMetrics::new(),
            rollback: RollbackMetrics::new(),
            pipeline: PipelineMetrics::new(),
        }
    }

    /// Emit a proof verification attempt event
    pub fn record_proof_verification(&mut self, success: bool, component: Option<&str>) {
        if success {
            self.proof.record_success();
        } else {
            self.proof.record_failure(component.unwrap_or("unknown"));
        }
    }

    /// Emit a replay detection event
    pub fn record_replay_detected(&mut self, source: ReplayDetectionSource) {
        match source {
            ReplayDetectionSource::PreInsertCheck => {
                self.replay.record_pre_insert_replay();
            }
            ReplayDetectionSource::InsertConflict => {
                self.replay.record_insert_conflict_replay();
            }
        }
    }

    /// Emit a clean replay check event
    pub fn record_replay_clean(&mut self) {
        self.replay.record_clean();
    }

    /// Emit a rollback event
    pub fn record_rollback(&mut self, reason: &str) {
        self.rollback.record_rollback(reason);
    }

    /// Emit a proof pipeline latency event
    pub fn record_pipeline_latency(&mut self, chain: &str, latency_ms: u64) {
        self.pipeline.record_execution(chain, latency_ms);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Source of replay detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDetectionSource {
    /// Detected via pre-insert check
    PreInsertCheck,
    /// Detected via insert conflict (CAS failure)
    InsertConflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_metrics_creation() {
        let metrics = RpcMetrics::new();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_success() {
        let mut metrics = RpcMetrics::new();
        metrics.record_success("provider1", 100);

        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_rate(), 1.0);
    }

    #[test]
    fn test_record_failure() {
        let mut metrics = RpcMetrics::new();
        metrics.record_failure("provider1");

        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failed_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_rate(), 0.0);
    }

    #[test]
    fn test_record_timeout() {
        let mut metrics = RpcMetrics::new();
        metrics.record_timeout("provider1");

        assert_eq!(metrics.timeout_failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_record_disagreement() {
        let mut metrics = RpcMetrics::new();
        metrics.record_disagreement();

        assert_eq!(metrics.disagreement_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_avg_latency() {
        let mut metrics = RpcMetrics::new();
        metrics.record_success("provider1", 100);
        metrics.record_success("provider1", 200);

        assert_eq!(metrics.avg_latency_ms(), 150.0);
    }

    #[test]
    fn test_provider_metrics() {
        let mut metrics = RpcMetrics::new();
        metrics.record_success("provider1", 100);
        metrics.record_failure("provider1");
        metrics.record_timeout("provider1");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.providers.len(), 1);
        assert_eq!(snapshot.providers[0].requests, 3);
        assert_eq!(snapshot.providers[0].successful, 1);
        assert_eq!(snapshot.providers[0].failed, 1);
        assert_eq!(snapshot.providers[0].timeouts, 1);
    }

    #[test]
    fn test_proof_metrics_success() {
        let metrics = ProofMetrics::new();
        metrics.record_success();
        assert_eq!(metrics.total(), 1);
        assert_eq!(metrics.success_rate(), 1.0);
    }

    #[test]
    fn test_proof_metrics_failure() {
        let mut metrics = ProofMetrics::new();
        metrics.record_failure("inclusion");
        assert_eq!(metrics.total(), 1);
        assert_eq!(metrics.success_rate(), 0.0);

        let failures = metrics.component_failures();
        assert_eq!(failures.get("inclusion"), Some(&1));
    }

    #[test]
    fn test_replay_metrics() {
        let metrics = ReplayMetrics::new();
        metrics.record_clean();
        metrics.record_pre_insert_replay();
        metrics.record_insert_conflict_replay();

        assert_eq!(metrics.total_checks(), 3);
        assert_eq!(metrics.replay_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_rollback_metrics() {
        let mut metrics = RollbackMetrics::new();
        metrics.record_rollback("reorg");
        metrics.record_rollback("reorg");
        metrics.record_rollback("finality_failure");

        assert_eq!(metrics.total(), 3);
        let by_reason = metrics.by_reason();
        assert_eq!(by_reason.get("reorg"), Some(&2));
        assert_eq!(by_reason.get("finality_failure"), Some(&1));
    }

    #[test]
    fn test_pipeline_metrics() {
        let mut metrics = PipelineMetrics::new();
        metrics.record_execution("bitcoin", 100);
        metrics.record_execution("bitcoin", 200);
        metrics.record_execution("ethereum", 150);

        assert_eq!(metrics.avg_latency_ms(), 150.0);

        let btc = metrics.chain_metrics("bitcoin").unwrap();
        assert_eq!(btc.avg_latency_ms(), 150.0);
    }

    #[test]
    fn test_metrics_collector() {
        let mut collector = MetricsCollector::new();
        collector.record_proof_verification(true, None);
        collector.record_proof_verification(false, Some("finality"));
        collector.record_replay_clean();
        collector.record_replay_detected(ReplayDetectionSource::PreInsertCheck);
        collector.record_rollback("reorg");

        assert_eq!(collector.proof.total(), 2);
        assert_eq!(collector.replay.total_checks(), 2);
        assert_eq!(collector.rollback.total(), 1);
    }
}
