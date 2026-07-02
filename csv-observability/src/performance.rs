//! Lightweight performance counters for runtime operations.

use core::sync::atomic::{AtomicU64, Ordering};

/// Snapshot of operation latency and result counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerformanceStats {
    pub operations: u64,
    pub failures: u64,
    pub total_latency_ms: u64,
}

impl PerformanceStats {
    pub fn average_latency_ms(&self) -> u64 {
        self.total_latency_ms
            .checked_div(self.operations)
            .unwrap_or(0)
    }
}

/// Thread-safe runtime performance collector.
#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    operations: AtomicU64,
    failures: AtomicU64,
    total_latency_ms: AtomicU64,
}

impl PerformanceMetrics {
    pub fn record_success(&self, latency_ms: u64) {
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
    }

    pub fn record_failure(&self, latency_ms: u64) {
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> PerformanceStats {
        PerformanceStats {
            operations: self.operations.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            total_latency_ms: self.total_latency_ms.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_latency_and_failures() {
        let metrics = PerformanceMetrics::default();
        metrics.record_success(10);
        metrics.record_failure(20);
        let stats = metrics.snapshot();
        assert_eq!(stats.operations, 2);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.average_latency_ms(), 15);
    }
}
