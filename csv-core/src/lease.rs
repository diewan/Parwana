//! Lease management for coordinated cross-chain transfers
//!
//! Leases prevent concurrent transfer attempts on the same sanad by multiple
//! actors. A lease is a time-bound authorization that must be acquired before
//! a transfer can proceed.

use core::fmt;
use serde::{Deserialize, Serialize};

use crate::collections::HashMap;
use csv_hash::Hash;
use csv_hash::csv_tagged_hash;

/// Unique lease identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub Hash);

impl LeaseId {
    /// Create a new lease ID from raw bytes
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Return the raw 32-byte lease ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.as_bytes()))
    }
}

/// A lease authorizing a single cross-chain transfer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease identifier
    pub id: LeaseId,
    /// Sanad ID being transferred
    pub sanad_id: Hash,
    /// Party authorized to execute the transfer
    pub owner: Hash,
    /// Timestamp when the lease was created (Unix epoch seconds)
    pub created_at: u64,
    /// Time-to-live in seconds
    pub ttl_secs: u64,
}

impl Lease {
    /// Create a new lease
    ///
    /// # Arguments
    /// * `sanad_id` — The sanad being transferred
    /// * `owner` — The party authorized to execute the transfer
    /// * `ttl_secs` — Time-to-live in seconds (must be > 0)
    pub fn new(sanad_id: Hash, owner: Hash, ttl_secs: u64) -> Self {
        Self {
            id: LeaseId(Hash::new([0u8; 32])), // Set by LeaseManager
            sanad_id,
            owner,
            created_at: now_secs(),
            ttl_secs,
        }
    }

    /// Check if this lease is still valid
    pub fn is_valid(&self, now: u64) -> bool {
        let expires_at = self.created_at + self.ttl_secs;
        now <= expires_at
    }

    /// Check if this lease is valid at the current time
    pub fn is_valid_now(&self) -> bool {
        self.is_valid(now_secs())
    }

    /// Return the expiration time as a Unix timestamp
    pub fn expires_at(&self) -> u64 {
        self.created_at + self.ttl_secs
    }

    /// Return the remaining time-to-live in seconds
    pub fn remaining_secs(&self, now: u64) -> u64 {
        let expires_at = self.expires_at();
        if now >= expires_at {
            0
        } else {
            expires_at - now
        }
    }
}

/// Returns the current time as Unix epoch seconds.
///
/// In `std` builds, this uses `SystemTime`. In `no_std` builds, it returns 0.
#[cfg(feature = "std")]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns the current time as Unix epoch seconds.
///
/// In `no_std` builds, this returns 0. Callers should override this
/// by replacing the function pointer in the `csv_runtime` crate.
#[cfg(not(feature = "std"))]
pub fn now_secs() -> u64 {
    0
}

/// Manages lease acquisition, validation, and release
#[derive(Debug, Default)]
pub struct LeaseManager {
    /// Active leases keyed by sanad_id
    pub leases: HashMap<Hash, Lease>,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
        }
    }

    /// Acquire a lease for a sanad
    ///
    /// Returns the lease ID if successful, or an error if a lease already exists
    /// for this sanad.
    ///
    /// # Arguments
    /// * `sanad_id` — The sanad to lock
    /// * `owner` — The party acquiring the lease
    /// * `ttl_secs` — Time-to-live in seconds
    pub fn acquire(
        &mut self,
        sanad_id: Hash,
        owner: Hash,
        ttl_secs: u64,
    ) -> Result<LeaseId, LeaseError> {
        if ttl_secs == 0 {
            return Err(LeaseError::InvalidTtl);
        }

        if let Some(existing) = self.leases.get(&sanad_id) {
            if existing.is_valid_now() {
                return Err(LeaseError::AlreadyLeased {
                    owner: existing.owner,
                    expires_at: existing.expires_at(),
                });
            }
            // Expired lease — allow re-acquisition
        }

        let mut lease = Lease::new(sanad_id, owner, ttl_secs);
        lease.id = LeaseId(Hash::new(csv_tagged_hash("csv.lease.id.v1", &lease.id.as_bytes()[..])));

        self.leases.insert(sanad_id, lease.clone());
        Ok(lease.id)
    }

    /// Validate a lease token for a given sanad and owner
    ///
    /// Returns Ok(()) if the lease is valid, or an error otherwise.
    ///
    /// # Arguments
    /// * `lease_id` — The lease ID to validate
    /// * `sanad_id` — The sanad being transferred
    /// * `owner` — The party executing the transfer
    pub fn validate(
        &self,
        lease_id: LeaseId,
        sanad_id: Hash,
        owner: Hash,
    ) -> Result<(), LeaseError> {
        let lease = self.leases.get(&sanad_id).ok_or(LeaseError::NotFound)?;

        if lease.id != lease_id {
            return Err(LeaseError::IdMismatch);
        }

        if lease.owner != owner {
            return Err(LeaseError::OwnerMismatch {
                expected: lease.owner,
            });
        }

        if !lease.is_valid_now() {
            return Err(LeaseError::Expired {
                expires_at: lease.expires_at(),
            });
        }

        Ok(())
    }

    /// Release a lease, allowing a new lease to be acquired
    pub fn release(&mut self, sanad_id: Hash) -> bool {
        self.leases.remove(&sanad_id).is_some()
    }

    /// Check if a lease exists for a sanad
    pub fn has_lease(&self, sanad_id: Hash) -> bool {
        self.leases
            .get(&sanad_id)
            .map(|l| l.is_valid_now())
            .unwrap_or(false)
    }

    /// Get the remaining time-to-live for a lease, if it exists and is valid
    pub fn remaining_ttl(&self, sanad_id: Hash) -> Option<u64> {
        self.leases
            .get(&sanad_id)
            .filter(|l| l.is_valid_now())
            .map(|l| l.remaining_secs(now_secs()))
    }
}

/// Lease management errors
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LeaseError {
    #[error("No lease found for this sanad")]
    NotFound,

    #[error("Lease ID does not match")]
    IdMismatch,

    #[error("Owner mismatch: expected {expected:?}")]
    OwnerMismatch { expected: Hash },

    #[error("Lease expired at {expires_at}")]
    Expired { expires_at: u64 },

    #[error("Sanad already leased by {owner:?}, expires at {expires_at}")]
    AlreadyLeased { owner: Hash, expires_at: u64 },

    #[error("TTL must be greater than 0")]
    InvalidTtl,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_creation() {
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);
        let lease = Lease::new(sanad_id, owner, 300);

        assert_eq!(lease.sanad_id, sanad_id);
        assert_eq!(lease.owner, owner);
        assert_eq!(lease.ttl_secs, 300);
        assert!(lease.is_valid_now());
    }

    #[test]
    fn test_lease_expiration() {
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);
        let lease = Lease::new(sanad_id, owner, 60);

        assert!(lease.is_valid_now());

        // Simulate time passing
        let now = now_secs();
        assert!(!lease.is_valid(now + 120));
        assert_eq!(lease.remaining_secs(now + 30), 30);
        assert_eq!(lease.remaining_secs(now + 120), 0);
    }

    #[test]
    fn test_lease_manager_acquire() {
        let mut manager = LeaseManager::new();
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);

        let _lease_id = manager.acquire(sanad_id, owner, 300).unwrap();
        assert!(manager.has_lease(sanad_id));
        assert_eq!(manager.remaining_ttl(sanad_id).unwrap(), 300);

        // Try to acquire again — should fail
        let result = manager.acquire(sanad_id, owner, 300);
        assert!(result.is_err());
    }

    #[test]
    fn test_lease_manager_validate() {
        let mut manager = LeaseManager::new();
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);

        let lease_id = manager.acquire(sanad_id, owner, 300).unwrap();

        // Valid lease
        assert!(manager.validate(lease_id, sanad_id, owner).is_ok());

        // Wrong owner
        let wrong_owner = Hash::new([3u8; 32]);
        assert!(manager.validate(lease_id, sanad_id, wrong_owner).is_err());

        // Wrong sanad
        let wrong_sanad = Hash::new([4u8; 32]);
        assert!(manager.validate(lease_id, wrong_sanad, owner).is_err());
    }

    #[test]
    fn test_lease_manager_release() {
        let mut manager = LeaseManager::new();
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);

        manager.acquire(sanad_id, owner, 300).unwrap();
        assert!(manager.has_lease(sanad_id));

        manager.release(sanad_id);
        assert!(!manager.has_lease(sanad_id));

        // Should be able to acquire again after release
        let lease_id = manager.acquire(sanad_id, owner, 300).unwrap();
        assert!(lease_id.as_bytes() != &[0u8; 32]);
    }

    #[test]
    fn test_lease_manager_invalid_ttl() {
        let mut manager = LeaseManager::new();
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Hash::new([2u8; 32]);

        let result = manager.acquire(sanad_id, owner, 0);
        assert!(result.is_err());
    }
}
