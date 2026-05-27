//! CSV Observability
//!
//! This crate provides observability features for the CSV Protocol,
//! including metrics, logging, and monitoring.

pub mod logging;
pub mod metrics;
pub mod performance;
pub mod runtime_health;

// Re-exports
pub use logging::{LogEntry, LogLevel, StructuredLogger, TraceSpan, Tracer};
pub use metrics::{ProviderMetrics, RpcMetrics};
pub use performance::{PerformanceMetrics, PerformanceStats};
pub use runtime_health::{DegradedReason, RuntimeHealth};
