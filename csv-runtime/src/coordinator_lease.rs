//! Distributed coordinator lease — prevents split-brain double-mints.
//!
//! Only the coordinator holding a valid lease may attempt mints.
//! Implementation: Database row with advisory lock (PostgreSQL) or
//! single-writer token (RocksDB with flock).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};


use csv_protocol::cross_chain::CrossChainTransferProof;

use crate::error::RuntimeError;
use csv_storage::{ReplayDatabase, ReplayDbError};

/// Unique coordinator identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CoordinatorId(pub String);

impl std::fmt::Display for CoordinatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors that can occur during lease operations.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum LeaseError {
    #[error("Lease conflict: held by {held_by} until {expires_at}")]
    Conflict { held_by: String, expires_at: u64 },
    #[error("Lease expired for coordinator {coordinator} at {expired_at}")]
    Expired { coordinator: CoordinatorId, expired_at: u64 },
    #[error("Storage error: {0}")]
    Storage(String),
}

/// A distributed coordinator lease preventing split-brain double-mints.
///
/// Only the coordinator holding a valid lease may attempt mints.
#[async_trait::async_trait]
pub trait CoordinatorLease: Send + Sync {
    /// Attempt to acquire or renew the lease for this coordinator.
    /// Returns Ok(lease_expiry_unix_secs) if acquired.
    /// Returns Err(LeaseConflict { held_by, expires_at }) if another coordinator holds it.
    async fn acquire_or_renew(
        &self,
        coordinator_id: &CoordinatorId,
        ttl: Duration,
    ) -> Result<u64, LeaseError>;

    /// Release the lease explicitly (best-effort, not required for correctness).
    async fn release(&self, coordinator_id: &CoordinatorId) -> Result<(), LeaseError>;

    /// Returns true if the lease is currently held by this coordinator and not expired.
    async fn is_held_by(&self, coordinator_id: &CoordinatorId) -> bool;
}

/// In-memory lease implementation for testing.
pub struct InMemoryLease {
    state: std::sync::Arc<std::sync::RwLock<LeaseState>>,
}

struct LeaseState {
    holder: Option<CoordinatorId>,
    expires_at: Option<u64>,
}

impl InMemoryLease {
    /// Create a new in-memory lease for testing.
    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::RwLock::new(LeaseState {
                holder: None,
                expires_at: None,
            })),
        }
    }
}

impl Default for InMemoryLease {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryLease {
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl CoordinatorLease for InMemoryLease {
    async fn acquire_or_renew(
        &self,
        coordinator_id: &CoordinatorId,
        ttl: Duration,
    ) -> Result<u64, LeaseError> {
        let now = Self::now_secs();
        let expiry = now + ttl.as_secs();

        let mut state = self.state.write().map_err(|_| {
            LeaseError::Storage("lease lock poisoned".to_string())
        })?;

        match (&state.holder, state.expires_at) {
            (Some(holder), Some(_expires)) if *holder == *coordinator_id => {
                // Renew existing lease
                state.expires_at = Some(expiry);
                Ok(expiry)
            }
            (Some(holder), Some(expires)) if expires > now => {
                // Another coordinator holds a valid lease
                Err(LeaseError::Conflict {
                    held_by: holder.0.clone(),
                    expires_at: expires,
                })
            }
            _ => {
                // No holder or expired — acquire
                state.holder = Some(coordinator_id.clone());
                state.expires_at = Some(expiry);
                Ok(expiry)
            }
        }
    }

    async fn release(&self, coordinator_id: &CoordinatorId) -> Result<(), LeaseError> {
        let mut state = self.state.write().map_err(|_| {
            LeaseError::Storage("lease lock poisoned".to_string())
        })?;

        if state.holder.as_ref() == Some(coordinator_id) {
            state.holder = None;
            state.expires_at = None;
        }

        Ok(())
    }

    async fn is_held_by(&self, coordinator_id: &CoordinatorId) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        match (&state.holder, state.expires_at) {
            (Some(holder), Some(expires)) => {
                *holder == *coordinator_id && Self::now_secs() < expires
            }
            _ => false,
        }
    }
}

/// Guard that enforces lease before any mint operation.
pub struct LeaseGuard {
    coordinator_id: CoordinatorId,
    valid_until: u64,
}

impl LeaseGuard {
    /// Acquire a lease guard.
    pub async fn acquire<L: CoordinatorLease>(
        lease: &L,
        coordinator_id: CoordinatorId,
        ttl: Duration,
    ) -> Result<Self, LeaseError> {
        let valid_until = lease.acquire_or_renew(&coordinator_id, ttl).await?;
        Ok(Self {
            coordinator_id,
            valid_until,
        })
    }

    /// Verify lease is still valid before each mint step.
    /// Must be called before: insert_if_absent, mint_sanad, confirm_consumed.
    pub fn assert_valid(&self) -> Result<(), LeaseError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now >= self.valid_until {
            return Err(LeaseError::Expired {
                coordinator: self.coordinator_id.clone(),
                expired_at: self.valid_until,
            });
        }
        Ok(())
    }
}

/// Mint coordinator — only path to calling insert_if_absent + mint.
///
/// Wraps the entire mint flow with lease enforcement at each step.
pub struct MintCoordinator<DB: ReplayDatabase, L: CoordinatorLease, M: MintProvider> {
    db: DB,
    lease: L,
    minter: M,
    coordinator_id: CoordinatorId,
    lease_ttl: Duration,
}

impl<DB, L, M> MintCoordinator<DB, L, M>
where
    DB: ReplayDatabase,
    L: CoordinatorLease,
    M: MintProvider,
{
    /// Create a new mint coordinator.
    pub fn new(
        db: DB,
        lease: L,
        minter: M,
        coordinator_id: CoordinatorId,
        lease_ttl: Duration,
    ) -> Self {
        Self {
            db,
            lease,
            minter,
            coordinator_id,
            lease_ttl,
        }
    }

    /// Execute a mint operation with full lease enforcement.
    ///
    /// # Steps
    /// 1. Acquire lease before any state mutation
    /// 2. Derive and insert ReplayId — atomic CAS
    /// 3. Execute mint — lease still required
    /// 4. Confirm consumed only after on-chain verification
    pub async fn execute_mint(
        &self,
        proof: &CrossChainTransferProof,
    ) -> Result<MintReceipt, RuntimeError> {
        // Step 1: Acquire lease before any state mutation.
        let guard = LeaseGuard::acquire(&self.lease, self.coordinator_id.clone(), self.lease_ttl)
            .await
            .map_err(|e| RuntimeError::LeaseConflict(e.to_string()))?;

        // Step 2: Derive and insert ReplayId — atomic CAS.
        // Runtime coordinates only - use sanad_id (Hash) directly for replay detection
        let replay_id = proof.lock_event.sanad_id;
        guard
            .assert_valid()
            .map_err(|e| RuntimeError::LeaseExpired(e.to_string()))?;

        self.db
            .insert_if_absent(replay_id.as_bytes())
            .await
            .map_err(|e| match e {
                ReplayDbError::AlreadyExists => {
                    RuntimeError::ReplayDetected(csv_hash::ReplayIdHash(replay_id))
                }
                ReplayDbError::Storage(s) => RuntimeError::Storage(s.to_string()),
                ReplayDbError::NotFound => RuntimeError::Storage("Replay ID not found".to_string()),
            })?;

        // Step 3: Execute mint — lease still required.
        guard
            .assert_valid()
            .map_err(|e| {
                // Lease expired between insert and mint — log for recovery coordinator.
                tracing::error!(
                    "Lease expired after insert, before mint — recovery coordinator required"
                );
                RuntimeError::LeaseExpired(e.to_string())
            })?;

        let receipt = self
            .minter
            .mint_sanad(proof)
            .await
            .map_err(|e| {
                // Mint failed — ReplayId is Pending, recovery coordinator must resolve.
                tracing::error!(
                    "Mint failed after insert — needs recovery: {}",
                    e
                );
                RuntimeError::MintFailed {
                    cause: e.to_string(),
                }
            })?;

        // Step 4: Confirm consumed only after on-chain verification.
        self.db
            .consume_if_unconsumed(replay_id.as_bytes())
            .await
            .map_err(|e| RuntimeError::Storage(e.to_string()))?;

        Ok(receipt)
    }
}

/// Provider trait for mint operations.
#[allow(async_fn_in_trait)]
pub trait MintProvider: Send + Sync {
    /// Mint a Sanad from a verified cross-chain transfer proof.
    async fn mint_sanad(
        &self,
        proof: &CrossChainTransferProof,
    ) -> Result<MintReceipt, RuntimeError>;
}

/// Receipt from a successful mint operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintReceipt {
    /// The Sanad ID that was minted
    pub sanad_id: [u8; 32],
    /// Transaction hash on the destination chain
    pub tx_hash: [u8; 32],
    /// Block height / slot where the mint was included
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lease_acquire_and_renew() {
        let lease = InMemoryLease::new();
        let coord = CoordinatorId("node-1".to_string());

        // First acquire should succeed
        let expiry = lease.acquire_or_renew(&coord, Duration::from_secs(60)).await.unwrap();
        assert!(lease.is_held_by(&coord).await);

        // Renew should succeed for same coordinator
        let expiry2 = lease.acquire_or_renew(&coord, Duration::from_secs(60)).await.unwrap();
        assert!(expiry2 >= expiry);

        // Release should work
        lease.release(&coord).await.unwrap();
        assert!(!lease.is_held_by(&coord).await);
    }

    #[tokio::test]
    async fn test_lease_conflict() {
        let lease = InMemoryLease::new();
        let coord1 = CoordinatorId("node-1".to_string());
        let coord2 = CoordinatorId("node-2".to_string());

        // Node 1 acquires lease
        lease.acquire_or_renew(&coord1, Duration::from_secs(60)).await.unwrap();

        // Node 2 should get a conflict
        let result = lease.acquire_or_renew(&coord2, Duration::from_secs(60)).await;
        assert!(matches!(result, Err(LeaseError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_lease_expiry() {
        let lease = InMemoryLease::new();
        let coord1 = CoordinatorId("node-1".to_string());
        let coord2 = CoordinatorId("node-2".to_string());

        // Node 1 acquires with very short TTL
        lease
            .acquire_or_renew(&coord1, Duration::from_millis(10))
            .await
            .unwrap();

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Node 2 should now be able to acquire (lease expired)
        let result = lease.acquire_or_renew(&coord2, Duration::from_secs(60)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lease_guard_assert_valid() {
        let lease = InMemoryLease::new();
        let coord = CoordinatorId("node-1".to_string());

        let expiry = lease
            .acquire_or_renew(&coord, Duration::from_secs(60))
            .await
            .unwrap();

        let guard = LeaseGuard {
            coordinator_id: coord,
            valid_until: expiry,
        };

        // Should be valid
        assert!(guard.assert_valid().is_ok());

        // Simulate expiry
        let mut expired_guard = guard;
        expired_guard.valid_until = 0;
        assert!(matches!(
            expired_guard.assert_valid(),
            Err(LeaseError::Expired { .. })
        ));
    }
}
