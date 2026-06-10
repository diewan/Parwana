//! Protocol invariants
//!
//! This module defines the core invariants that the CSV protocol must maintain.
//! These invariants are enforced through the type system and verification logic.
//!
//! **Layer Classification:**
//! - L4 (Runtime type): TimeoutConfig MAY use serde for operational serialization.

use std::fmt;

/// Protocol invariant violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// Proof size exceeds maximum
    ProofSizeExceeded,
    /// Finality data size exceeds maximum
    FinalityDataSizeExceeded,
    /// Signatures size exceeds maximum
    SignaturesSizeExceeded,
    /// Proof bundle size exceeds maximum
    ProofBundleSizeExceeded,
    /// Confirmations below minimum
    InsufficientConfirmations,
    /// Proof age exceeds maximum
    ProofExpired,
    /// Invalid state transition
    InvalidStateTransition,
    /// Replay detected
    ReplayDetected,
}

impl fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantViolation::ProofSizeExceeded => write!(f, "Proof size exceeds maximum"),
            InvariantViolation::FinalityDataSizeExceeded => {
                write!(f, "Finality data size exceeds maximum")
            }
            InvariantViolation::SignaturesSizeExceeded => {
                write!(f, "Signatures size exceeds maximum")
            }
            InvariantViolation::ProofBundleSizeExceeded => {
                write!(f, "Proof bundle size exceeds maximum")
            }
            InvariantViolation::InsufficientConfirmations => {
                write!(f, "Confirmations below minimum")
            }
            InvariantViolation::ProofExpired => write!(f, "Proof age exceeds maximum"),
            InvariantViolation::InvalidStateTransition => write!(f, "Invalid state transition"),
            InvariantViolation::ReplayDetected => write!(f, "Replay detected"),
        }
    }
}

impl std::error::Error for InvariantViolation {}

/// Result type for invariant checks
pub type InvariantResult<T> = Result<T, InvariantViolation>;

// ============================================================================
// Production Hardening Utilities
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum number of items in bounded queues
pub const MAX_SEAL_NULLIFIER_SIZE: usize = 1000;

/// Maximum number of entries in caches
pub const MAX_CACHE_SIZE: usize = 1000;

/// Maximum number of entries in registries
pub const MAX_REGISTRY_SIZE: usize = 10000;

/// Default timeout for RPC calls (in seconds)
pub const DEFAULT_RPC_TIMEOUT_SECS: u64 = 30;

/// Default timeout for health checks (in seconds)
pub const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u64 = 5;

/// Default maximum failures before circuit opens
pub const DEFAULT_CIRCUIT_MAX_FAILURES: usize = 5;

/// Default reset timeout for circuit breaker (in seconds)
pub const DEFAULT_CIRCUIT_RESET_TIMEOUT_SECS: u64 = 60;

/// Bounded queue for enforcing size limits on collections
///
/// Prevents unbounded growth of caches, registries, and other
/// in-memory data structures that could lead to memory exhaustion.
#[derive(Clone, Debug)]
pub struct BoundedQueue<T> {
    queue: VecDeque<T>,
    max_size: usize,
}

impl<T> BoundedQueue<T> {
    /// Create a new bounded queue with the given maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_size,
        }
    }

    /// Push an item to the back of the queue
    ///
    /// Returns `true` if the item was added, `false` if the queue is full.
    pub fn push(&mut self, item: T) -> bool {
        if self.queue.len() >= self.max_size {
            return false;
        }
        self.queue.push_back(item);
        true
    }

    /// Pop an item from the front of the queue (FIFO order)
    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Returns the number of items in the queue
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns `true` if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns `true` if the queue is at maximum capacity
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.max_size
    }
}

impl<T> Default for BoundedQueue<T> {
    fn default() -> Self {
        Self::new(MAX_SEAL_NULLIFIER_SIZE)
    }
}

/// Circuit breaker state for managing service availability
#[derive(Clone, Debug, PartialEq)]
pub enum CircuitState {
    /// Normal operation — requests are allowed
    Closed,
    /// Failure threshold exceeded — requests are blocked
    Open,
    /// Testing recovery — a single request is allowed through
    HalfOpen,
}

/// Circuit breaker for failure detection and automatic service isolation
///
/// Transitions from `Closed` to `Open` when failures exceed the threshold,
/// then to `HalfOpen` after a timeout period to test recovery.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    failure_count: usize,
    max_failures: usize,
    /// Unix epoch seconds of last failure (0 = never)
    last_failure_time: u64,
    /// Reset timeout in seconds
    reset_timeout_secs: u64,
    state: CircuitState,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given failure threshold and reset timeout
    pub fn new(max_failures: usize, reset_timeout_secs: u64) -> Self {
        Self {
            failure_count: 0,
            max_failures,
            last_failure_time: 0,
            reset_timeout_secs,
            state: CircuitState::Closed,
        }
    }

    /// Record a failure and potentially trip the circuit open
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Self::now_secs();

        if self.failure_count >= self.max_failures {
            self.state = CircuitState::Open;
        }
    }

    /// Record a success, resetting the circuit to closed state
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitState::Closed;
    }

    /// Check whether a request should be allowed through
    ///
    /// Returns `true` if the circuit is closed, or if the timeout
    /// has elapsed and the circuit is transitioning to half-open.
    pub fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if self.last_failure_time > 0 {
                    let elapsed = Self::now_secs().saturating_sub(self.last_failure_time);
                    if elapsed > self.reset_timeout_secs {
                        self.state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    self.state = CircuitState::HalfOpen;
                    true
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Returns the current circuit state
    pub fn state(&self) -> &CircuitState {
        &self.state
    }

    /// Returns the current consecutive failure count
    pub fn failure_count(&self) -> usize {
        self.failure_count
    }

    /// Get current time in seconds since Unix epoch
    #[cfg(not(target_arch = "wasm32"))]
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(target_arch = "wasm32")]
    fn now_secs() -> u64 {
        // WASM fallback - return 0 for now
        0
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(
            DEFAULT_CIRCUIT_MAX_FAILURES,
            DEFAULT_CIRCUIT_RESET_TIMEOUT_SECS,
        )
    }
}

/// Timeout configuration for RPC calls and health checks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Timeout for individual RPC calls (in seconds)
    pub rpc_call: u64,
    /// Timeout for health check requests (in seconds)
    pub health_check: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            rpc_call: DEFAULT_RPC_TIMEOUT_SECS,
            health_check: DEFAULT_HEALTH_CHECK_TIMEOUT_SECS,
        }
    }
}

/// Memory limits configuration for caches and registries
#[derive(Clone, Debug)]
pub struct MemoryLimits {
    /// Maximum number of entries in caches
    pub cache_size: usize,
    /// Maximum number of entries in registries
    pub registry_size: usize,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            cache_size: MAX_CACHE_SIZE,
            registry_size: MAX_REGISTRY_SIZE,
        }
    }
}
