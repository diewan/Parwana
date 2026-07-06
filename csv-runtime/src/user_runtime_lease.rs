//! Lease management for CSV protocol
//!
//! This module provides two lease systems:
//!
//! 1. **User-facing leases** (`UserLease`, `UserLeaseManager`): Time-bound authorizations
//!    that users must acquire before initiating cross-chain transfers. These prevent
//!    concurrent transfer attempts on the same sanad.
//!
//! 2. **Runtime leases** (`TransferLease`, `RuntimeId`): Runtime-level coordination
//!    for HA deployments that ensures exactly one runtime instance can advance a
//!    transfer's state at any time.
//!
//! # User-Facing Lease Lifecycle
//!
//! 1. **Acquire**: User acquires a lease for a sanad via CLI/SDK
//! 2. **Transfer**: User presents lease token when initiating transfer
//! 3. **Validate**: Runtime validates the lease before executing transfer
//! 4. **Expire**: Lease expires after TTL, allowing re-acquisition
//!
//! # Runtime Lease Lifecycle
//!
//! 1. **Acquire**: A runtime instance acquires a lease for a transfer
//! 2. **Execute**: The runtime performs mutating operations under the lease
//! 3. **Release**: The lease is released after successful completion
//! 4. **Expire**: If the runtime crashes, the lease expires and can be reacquired
//!
//! # Invariants
//!
//! - User leases are stored in persistent storage (csv-runtime authority)
//! - Runtime leases are in-memory for HA coordination
//! - Only the lease owner may perform mutating operations
//! - Stale leases (expired) can be forcibly released

use core::fmt::Debug;
use std::time::SystemTime;

use uuid::Uuid;

use csv_wire::SanadIdWire;

/// Runtime instance identifier.
///
/// A UUID v4 that uniquely identifies a runtime process. In HA deployments,
/// each runtime instance has a distinct `RuntimeId`.
pub type RuntimeId = Uuid;

/// Default lease duration in seconds.
///
/// This is the maximum time a lease remains valid without renewal.
/// If a runtime crashes, the lease will expire after this duration.
pub const DEFAULT_LEASE_DURATION_SECS: u64 = 30;

/// Maximum allowed lease duration in seconds.
///
/// Leases longer than this are rejected as potentially stale.
pub const MAX_LEASE_DURATION_SECS: u64 = 300;

/// Transfer execution lease — single-owner execution guard.
///
/// A lease grants exclusive authority to perform mutating operations on a
/// transfer. Only the runtime instance identified by `owner_runtime_id` may
/// execute operations while holding a valid lease.
///
/// # Invariants
///
/// - `expires_at` must be after `acquired_at`
/// - `epoch` must be monotonically increasing per transfer
/// - A lease is only valid if `is_active()` returns true
///
/// # Example
///
/// ```
/// use csv_runtime::user_runtime_lease::{TransferLease, DEFAULT_LEASE_DURATION_SECS};
/// use std::time::{Duration, SystemTime};
/// use uuid::Uuid;
/// use csv_hash::sanad::SanadId;
///
/// let transfer_id = SanadId::from_bytes(&[0u8; 32]);
/// let runtime_id = Uuid::new_v4();
/// let now = SystemTime::now();
/// let duration = Duration::from_secs(DEFAULT_LEASE_DURATION_SECS);
///
/// let lease = TransferLease::acquire(transfer_id.into(), runtime_id, 0, now, duration)
///     .expect("valid lease duration");
/// assert!(lease.is_active(now));
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransferLease {
    /// Transfer identifier this lease protects.
    pub transfer_id: SanadIdWire,
    /// Epoch counter to prevent stale lease adoption.
    ///
    /// Each time a lease is released and reacquired for the same transfer,
    /// the epoch must increase. This prevents a stale lease from being
    /// adopted after the transfer has moved on.
    pub epoch: u64,
    /// Owning runtime instance identifier.
    pub owner_runtime_id: RuntimeId,
    /// Time when the lease was acquired.
    pub acquired_at: SystemTime,
    /// Expiration time for the lease.
    pub expires_at: SystemTime,
}

/// Execution context passed to mutating runtime operations.
///
/// Every mutating operation (proof validation, rollback, mint authorization,
/// replay consumption, retry scheduling, finality transition) must verify
/// lease ownership and use the provided policy for all decisions.
///
/// Adapters MUST NOT make policy decisions. They only execute operations
/// according to the policy provided in this context.
#[derive(Debug, Clone)]
pub struct RuntimeExecutionContext {
    /// The lease authorizing this execution
    pub lease: TransferLease,
    /// The runtime instance performing the execution
    pub runtime_instance: RuntimeId,
    /// Runtime policy for this execution
    pub policy: crate::policy::RuntimePolicy,
}

impl TransferLease {
    /// Acquire a new lease for the given transfer.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - The transfer to lease
    /// * `runtime_id` - The runtime instance acquiring the lease
    /// * `epoch` - The epoch counter (must be >= any previous epoch for this transfer)
    /// * `now` - The current system time
    /// * `duration` - How long the lease should be valid
    pub fn acquire(
        transfer_id: SanadIdWire,
        runtime_id: RuntimeId,
        epoch: u64,
        now: SystemTime,
        duration: std::time::Duration,
    ) -> Result<Self, LeaseValidationError> {
        if duration.as_secs() > MAX_LEASE_DURATION_SECS {
            return Err(LeaseValidationError::DurationExceeded {
                requested_secs: duration.as_secs(),
                max_secs: MAX_LEASE_DURATION_SECS,
            });
        }
        let expires_at = now
            .checked_add(duration)
            .ok_or(LeaseValidationError::ExpirationOverflow)?;
        Ok(Self {
            transfer_id,
            epoch,
            owner_runtime_id: runtime_id,
            acquired_at: now,
            expires_at,
        })
    }

    /// Returns true if the lease is currently active relative to `now`.
    pub fn is_active(&self, now: SystemTime) -> bool {
        now < self.expires_at
    }

    /// Returns true if this lease is owned by the given runtime.
    pub fn is_owned_by(&self, runtime_id: RuntimeId) -> bool {
        self.owner_runtime_id == runtime_id
    }

    /// Returns true if this lease is owned by the given runtime AND is active.
    pub fn is_valid_for(&self, runtime_id: RuntimeId, now: SystemTime) -> bool {
        self.is_owned_by(runtime_id) && self.is_active(now)
    }

    /// Returns the remaining time until lease expiration.
    ///
    /// Returns `None` if the lease has already expired.
    pub fn remaining(&self, now: SystemTime) -> Option<std::time::Duration> {
        self.expires_at
            .duration_since(now)
            .ok()
            .filter(|_| now < self.expires_at)
    }

    /// Check if this lease has expired.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        !self.is_active(now)
    }

    /// Create a new lease with an incremented epoch (for lease renewal).
    ///
    /// This is used when a runtime renews its lease after a long-running
    /// operation. The epoch must increase to prevent stale lease adoption.
    pub fn renew(
        &self,
        now: SystemTime,
        duration: std::time::Duration,
    ) -> Result<Self, LeaseValidationError> {
        Self::acquire(
            self.transfer_id.clone(),
            self.owner_runtime_id,
            self.epoch + 1,
            now,
            duration,
        )
    }

    /// Check if this lease is stale (owned by a different runtime).
    pub fn is_stale_for(&self, runtime_id: RuntimeId) -> bool {
        !self.is_owned_by(runtime_id)
    }
}

impl RuntimeExecutionContext {
    /// Create a new execution context with policy.
    ///
    /// Ownership and expiry are validated by runtime entrypoints. Prefer
    /// [`RuntimeExecutionContext::try_new`] when constructing contexts from
    /// untrusted input.
    pub fn new(
        lease: TransferLease,
        runtime_instance: RuntimeId,
        policy: crate::policy::RuntimePolicy,
    ) -> Self {
        Self {
            lease,
            runtime_instance,
            policy,
        }
    }

    /// Create a new execution context and reject stale lease ownership.
    pub fn try_new(
        lease: TransferLease,
        runtime_instance: RuntimeId,
        policy: crate::policy::RuntimePolicy,
    ) -> Result<Self, LeaseValidationError> {
        if lease.is_stale_for(runtime_instance) {
            return Err(LeaseValidationError::Stale {
                transfer_id: lease.transfer_id.clone(),
                owner: lease.owner_runtime_id,
            });
        }
        Ok(Self {
            lease,
            runtime_instance,
            policy,
        })
    }

    /// Validate the execution context against the current time.
    ///
    /// Returns `Ok(())` if the lease is valid and not expired,
    /// `Err` if the lease has expired or is stale.
    pub fn validate(&self, now: SystemTime) -> Result<(), LeaseValidationError> {
        if self.lease.is_expired(now) {
            return Err(LeaseValidationError::Expired {
                transfer_id: self.lease.transfer_id.clone(),
                expires_at: self.lease.expires_at,
            });
        }
        if self.lease.is_stale_for(self.runtime_instance) {
            return Err(LeaseValidationError::Stale {
                transfer_id: self.lease.transfer_id.clone(),
                owner: self.lease.owner_runtime_id,
            });
        }
        Ok(())
    }

    /// Get the transfer ID this context authorizes.
    pub fn transfer_id(&self) -> &SanadIdWire {
        &self.lease.transfer_id
    }

    /// Get the runtime instance ID.
    pub fn runtime_instance(&self) -> RuntimeId {
        self.runtime_instance
    }
}

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// The lease has expired.
    Expired {
        /// The transfer ID.
        transfer_id: SanadIdWire,
        /// When the lease expired.
        expires_at: SystemTime,
    },
    /// The lease is owned by a different runtime.
    Stale {
        /// The transfer ID.
        transfer_id: SanadIdWire,
        /// The runtime that owns this lease.
        owner: RuntimeId,
    },
    /// Lease duration exceeds maximum allowed.
    DurationExceeded {
        /// Requested duration in seconds.
        requested_secs: u64,
        /// Maximum allowed duration in seconds.
        max_secs: u64,
    },
    /// Lease expiration time overflow.
    ExpirationOverflow,
}

impl core::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Expired {
                transfer_id,
                expires_at,
            } => write!(
                f,
                "Lease expired for transfer {:?}: expired at {:?}",
                transfer_id, expires_at
            ),
            Self::Stale { transfer_id, owner } => write!(
                f,
                "Lease for transfer {:?} is owned by runtime {}, not the calling runtime",
                transfer_id, owner
            ),
            Self::DurationExceeded {
                requested_secs,
                max_secs,
            } => write!(
                f,
                "Lease duration {}s exceeds maximum {}s",
                requested_secs, max_secs
            ),
            Self::ExpirationOverflow => write!(f, "Lease expiration time overflow"),
        }
    }
}

impl std::error::Error for LeaseValidationError {}
