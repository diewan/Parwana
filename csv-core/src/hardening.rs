//! Production hardening utilities for core module
//!
//! This module provides:
//! - Bounded queues for rate limiting
//! - Circuit breakers for failure detection
//! - Timeout configuration
//! - Memory limits enforcement
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::invariants::{
    BoundedQueue, CircuitBreaker, CircuitState, TimeoutConfig, MemoryLimits,
    MAX_SEAL_NULLIFIER_SIZE, MAX_CACHE_SIZE, MAX_REGISTRY_SIZE,
    DEFAULT_RPC_TIMEOUT_SECS, DEFAULT_HEALTH_CHECK_TIMEOUT_SECS,
    DEFAULT_CIRCUIT_MAX_FAILURES, DEFAULT_CIRCUIT_RESET_TIMEOUT_SECS,
};
