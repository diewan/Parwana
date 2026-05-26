//! Backpressure management for runtime operations
//!
//! This module provides traits and types for managing backpressure
//! in the CSV runtime, preventing overload and ensuring system stability.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Trait for reporting backpressure status
///
/// Implementations can report current pressure levels and
/// provide metrics for monitoring and scaling decisions.
pub trait BackpressureSink: Send + Sync {
    /// Get the current queue depth
    fn queue_depth(&self) -> usize;

    /// Get the maximum queue capacity
    fn max_queue_depth(&self) -> usize;

    /// Check if the system is under backpressure
    fn is_under_pressure(&self) -> bool {
        self.queue_depth() >= (self.max_queue_depth() * 3 / 4)
    }

    /// Get pressure level as a percentage (0-100)
    fn pressure_level(&self) -> u8 {
        if self.max_queue_depth() == 0 {
            return 0;
        }
        ((self.queue_depth() * 100) / self.max_queue_depth()) as u8
    }
}

/// Backpressure mode for handling queue overflow
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackpressureMode {
    /// Reject new work when queue is full
    Reject,
    /// Drop oldest work when queue is full
    DropOldest,
    /// Block until queue has space
    Block,
}

impl fmt::Display for BackpressureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackpressureMode::Reject => write!(f, "Reject"),
            BackpressureMode::DropOldest => write!(f, "DropOldest"),
            BackpressureMode::Block => write!(f, "Block"),
        }
    }
}

/// Configuration for admission limits
#[derive(Clone, Debug)]
pub struct AdmissionLimits {
    /// Maximum queue depth
    pub max_queue_depth: usize,
    /// Backpressure mode
    pub backpressure_mode: BackpressureMode,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_queue_depth: 1000,
            backpressure_mode: BackpressureMode::Reject,
        }
    }
}

impl AdmissionLimits {
    /// Create new admission limits
    pub fn new(max_queue_depth: usize, backpressure_mode: BackpressureMode) -> Self {
        Self {
            max_queue_depth,
            backpressure_mode,
        }
    }

    /// Create with reject mode (default)
    pub fn reject(max_queue_depth: usize) -> Self {
        Self::new(max_queue_depth, BackpressureMode::Reject)
    }

    /// Create with drop oldest mode
    pub fn drop_oldest(max_queue_depth: usize) -> Self {
        Self::new(max_queue_depth, BackpressureMode::DropOldest)
    }

    /// Create with block mode
    pub fn block(max_queue_depth: usize) -> Self {
        Self::new(max_queue_depth, BackpressureMode::Block)
    }
}
