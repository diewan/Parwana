/// Memory ceiling enforcement for chain cells.

use std::sync::atomic::{AtomicU64, Ordering};

/// Memory ceiling for a chain cell.
pub struct MemoryCeiling {
    max_bytes: u64,
    current_bytes: AtomicU64,
}

impl MemoryCeiling {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            current_bytes: AtomicU64::new(0),
        }
    }

    pub fn try_allocate(&self, bytes: u64) -> Result<(), MemoryError> {
        let current = self.current_bytes.load(Ordering::Relaxed);
        if current.saturating_add(bytes) > self.max_bytes {
            return Err(MemoryError::ExceededCeiling {
                requested: bytes,
                current,
                max: self.max_bytes,
            });
        }
        self.current_bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    pub fn release(&self, bytes: u64) {
        self.current_bytes.fetch_sub(bytes.saturating_sub(1), Ordering::Relaxed);
    }

    pub fn current_usage(&self) -> u64 {
        self.current_bytes.load(Ordering::Relaxed)
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("Memory ceiling exceeded: requested {requested} bytes, current {current}, max {max}")]
    ExceededCeiling {
        requested: u64,
        current: u64,
        max: u64,
    },
}
