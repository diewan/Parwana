//! Resource accounting for verification
//!
//! Calculates and enforces resource limits for verification to prevent
//! resource exhaustion attacks.

use serde::{Deserialize, Serialize};

/// Verification cost
///
/// Represents the computational cost of verifying a proof or content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCost {
    /// CPU cost in abstract units
    pub cpu: u64,
    /// Memory cost in bytes
    pub memory: u64,
    /// I/O cost in bytes read/written
    pub io: u64,
    /// Recursion depth
    pub recursion_depth: u64,
}

impl VerificationCost {
    /// Create a new verification cost
    pub fn new(cpu: u64, memory: u64, io: u64, recursion_depth: u64) -> Self {
        Self {
            cpu,
            memory,
            io,
            recursion_depth,
        }
    }

    /// Check if this cost exceeds a limit
    pub fn exceeds(&self, limit: &VerificationLimit) -> bool {
        self.cpu > limit.max_cpu
            || self.memory > limit.max_memory
            || self.io > limit.max_io
            || self.recursion_depth > limit.max_recursion_depth
    }

    /// Add two costs together
    pub fn add(&self, other: &VerificationCost) -> VerificationCost {
        VerificationCost {
            cpu: self.cpu + other.cpu,
            memory: self.memory + other.memory,
            io: self.io + other.io,
            recursion_depth: self.recursion_depth.max(other.recursion_depth),
        }
    }
}

impl Default for VerificationCost {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Verification limits
///
/// Defines maximum allowed costs for verification operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationLimit {
    /// Maximum CPU cost
    pub max_cpu: u64,
    /// Maximum memory cost
    pub max_memory: u64,
    /// Maximum I/O cost
    pub max_io: u64,
    /// Maximum recursion depth
    pub max_recursion_depth: u64,
}

impl VerificationLimit {
    /// Create conservative limits for production
    pub fn conservative() -> Self {
        Self {
            max_cpu: 1_000_000,            // 1M CPU units
            max_memory: 100 * 1024 * 1024, // 100 MB
            max_io: 10 * 1024 * 1024,      // 10 MB
            max_recursion_depth: 100,
        }
    }

    /// Create permissive limits for testing
    pub fn permissive() -> Self {
        Self {
            max_cpu: u64::MAX,
            max_memory: u64::MAX,
            max_io: u64::MAX,
            max_recursion_depth: 1000,
        }
    }

    /// Check if a cost is within limits
    pub fn allows(&self, cost: &VerificationCost) -> bool {
        !cost.exceeds(self)
    }
}

impl Default for VerificationLimit {
    fn default() -> Self {
        Self::conservative()
    }
}

/// Resource accounting error
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceError {
    /// CPU limit exceeded
    CPULimitExceeded { requested: u64, limit: u64 },
    /// Memory limit exceeded
    MemoryLimitExceeded { requested: u64, limit: u64 },
    /// I/O limit exceeded
    IOLimitExceeded { requested: u64, limit: u64 },
    /// Recursion depth exceeded
    RecursionDepthExceeded { requested: u64, limit: u64 },
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::CPULimitExceeded { requested, limit } => {
                write!(
                    f,
                    "CPU limit exceeded: requested {}, limit {}",
                    requested, limit
                )
            }
            ResourceError::MemoryLimitExceeded { requested, limit } => {
                write!(
                    f,
                    "Memory limit exceeded: requested {}, limit {}",
                    requested, limit
                )
            }
            ResourceError::IOLimitExceeded { requested, limit } => {
                write!(
                    f,
                    "I/O limit exceeded: requested {}, limit {}",
                    requested, limit
                )
            }
            ResourceError::RecursionDepthExceeded { requested, limit } => {
                write!(
                    f,
                    "Recursion depth exceeded: requested {}, limit {}",
                    requested, limit
                )
            }
        }
    }
}

impl std::error::Error for ResourceError {}
