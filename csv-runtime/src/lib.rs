//! csv-runtime — CSV Protocol orchestration facade
//!
//! This crate is a facade that composes focused orchestration crates:
//! - csv-coordinator: Per-chain execution cells with isolated failure domains
//! - csv-admission: Admission control and pressure boundaries
//!
//! This crate re-exports types from these crates with no additional logic.
//! Target: < 200 lines of re-exports.

#![warn(missing_docs)]

// Re-exports from csv-coordinator
pub use csv_coordinator::{
    CapabilityNegotiator, CellCircuitBreaker, CellConfig, CellError, CellTask, ChainCell,
    CircuitState, InboundTransfer, MemoryCeiling, NegotiatedPlan, NegotiationError, RouterError,
    SecurityRequirements, TransferRouter,
};

// Re-exports from csv-admission
pub use csv_admission::{
    AdmissionController, AdmissionError, AdmissionLimits, AdmissionPermit, AdmissionSnapshot,
};

// Backpressure management
pub mod backpressure;
pub use backpressure::{
    AdmissionLimits as BackpressureAdmissionLimits, BackpressureMode, BackpressureSink,
};

// Legacy re-exports (to be migrated to focused crates)
pub mod adapter_registry;
pub mod config;
pub mod coordinator_lease;
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
pub mod replay_db;
pub mod runtime_mode;
pub mod transfer_coordinator;

// Wallet operations (facade over chain adapters)
pub mod wallet;

// Legacy re-exports (orchestration only)
pub use adapter_registry::{
    AdapterRegistryImpl, ChainAdapter, ChainCapabilityPort, ChainLockPort, ChainMintPort,
    ChainProofPort, ChainReadPort, ChainSealRegistryPort,
};
pub use config::{
    CircuitBreakerConfig, ConfigValidationError, LeaseConfig, OperationalConfig, RetryConfig,
    RpcConfig, TimeoutConfig,
};
pub use error::{RuntimeError, TransferCoordinatorError};
pub use event_bus::{EventBus, TransferEvent};
pub use event_store::{EventStore, EventStoreError, InMemoryEventStore};
#[cfg(feature = "persistent")]
pub use execution_journal::RocksDbExecutionJournal;
pub use execution_journal::{
    ExecutionJournal, InMemoryJournal, JournalError, PhaseOutcome, TransferPhaseEntry,
};
pub use failure_domain::{ClassifiedError, FailureDomain};
pub use lease::{
    DEFAULT_LEASE_DURATION_SECS, LeaseValidationError, MAX_LEASE_DURATION_SECS,
    RuntimeExecutionContext, RuntimeId, TransferLease,
};
pub use policy::RuntimePolicy;
pub use queue::{TaskQueue, TaskQueueError};
pub use recovery::{
    CheckpointId, CheckpointManager, RecoveryCheckpoint, ReplayCheckpoint, TransferStage,
    VerificationCheckpoint,
};
pub use runtime_mode::{
    CircuitBreaker, CircuitBreakerConfig as RuntimeCircuitBreakerConfig, CircuitBreakerState,
    HealthMonitor, HealthStatus, RuntimeMode,
};
pub use transfer_coordinator::{RecoveryContextProvider, TransferCoordinator};

// Coordinator lease re-exports
pub use coordinator_lease::{
    CoordinatorId, CoordinatorLease, InMemoryLease, LeaseError, LeaseGuard, MintCoordinator,
    MintProvider, MintReceipt,
};
