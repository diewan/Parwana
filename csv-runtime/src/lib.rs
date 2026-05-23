//! csv-runtime — CSV Protocol orchestration engine
//!
//! This crate provides the runtime layer for cross-chain transfer execution.
//! It contains ONLY orchestration, queues, scheduling, and coordination logic.
//! It depends on csv-protocol and csv-storage (for traits) — no chain adapter imports.
//!
//! ## Architecture
//!
//! - **TransferCoordinator**: Single source of truth for transfer execution
//! - **AdapterRegistry**: Dependency injection for chain adapters
//! - **EventBus**: Structured events for observability
//! - **EventStore**: Durable event sourcing storage
//! - **ExecutionJournal**: Phase-by-phase audit trail for crash recovery
//! - **Queue**: Task queue for scheduling
//! - **Policy**: Runtime policies and circuit breakers (sourced from csv-core)
//! - **Verifier**: All proof verification delegated to csv-verifier::CanonicalVerifier
//!
//! ## Persistence
//!
//! Concrete persistence implementations (RocksDB, PostgreSQL) are in separate crates
//! that depend on csv-storage traits.

#![warn(missing_docs)]

pub mod adapter_registry;
pub mod config;
pub mod error;
pub mod event_bus;
pub mod event_envelope;
pub mod event_store;
pub mod execution_journal;
pub mod failure_domain;
pub mod lease;
pub mod policy;
pub mod queue;
pub mod recovery;
pub mod runtime_mode;
pub mod transfer_coordinator;
pub mod coordinator_lease;
pub mod replay_db;

// Re-exports (orchestration only)
pub use adapter_registry::{AdapterRegistryImpl, ChainAdapter};
pub use config::{CircuitBreakerConfig, ConfigValidationError, LeaseConfig, OperationalConfig, RetryConfig, RpcConfig, TimeoutConfig};
pub use error::{RuntimeError, TransferCoordinatorError};
pub use event_bus::{EventBus, TransferEvent};
pub use event_store::{EventStore, EventStoreError, InMemoryEventStore};
pub use execution_journal::{ExecutionJournal, InMemoryJournal, JournalError, PhaseOutcome, TransferPhaseEntry};
pub use failure_domain::{ClassifiedError, FailureDomain};
pub use lease::{
    DEFAULT_LEASE_DURATION_SECS, LeaseValidationError, RuntimeExecutionContext, RuntimeId,
    TransferLease, MAX_LEASE_DURATION_SECS,
};
pub use policy::RuntimePolicy;
pub use queue::{TaskQueue, TaskQueueError};
pub use recovery::{CheckpointId, CheckpointManager, RecoveryCheckpoint, ReplayCheckpoint, TransferStage, VerificationCheckpoint};
pub use runtime_mode::{CircuitBreaker, CircuitBreakerConfig as RuntimeCircuitBreakerConfig, CircuitBreakerState, HealthMonitor, HealthStatus, RuntimeMode};
pub use transfer_coordinator::TransferCoordinator;

// Coordinator lease re-exports
pub use coordinator_lease::{
    CoordinatorId, CoordinatorLease, InMemoryLease, LeaseError, LeaseGuard, MintCoordinator,
    MintProvider, MintReceipt,
};
