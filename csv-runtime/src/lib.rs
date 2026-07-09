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
    CircuitState, MemoryCeiling, NegotiatedPlan, NegotiationError, RouterError,
    SecurityRequirements, TransferRouter, TransferTask,
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
pub mod chain_discovery;
pub mod config;
pub mod distributed_coordinator_lease;
pub mod error;
pub mod event_bus;
pub mod event_envelope;
pub mod event_persistence;
pub mod execution_journal;
pub mod failure_domain;
pub mod policy;
pub mod queue;
pub mod recovery;
pub mod replay_database;
pub mod runtime_mode;
pub mod send_transfer;
pub mod transfer_coordinator;
pub mod user_runtime_lease;

// Wallet operations (facade over chain adapters)
pub mod wallet;

// Legacy re-exports (orchestration only)
pub use adapter_registry::AdapterRegistryImpl;
pub use chain_discovery::{ChainConfig, ChainDiscovery};
pub use config::{
    CircuitBreakerConfig, ConfigValidationError, LeaseConfig, OperationalConfig, RetryConfig,
    RpcConfig, TimeoutConfig,
};
pub use csv_adapter_core::{
    ChainAdapter, ChainCapabilityPort, ChainLockPort, ChainMintPort, ChainProofPort, ChainReadPort,
    ChainSealRegistryPort,
};
pub use error::{RuntimeError, TransferCoordinatorError};
pub use event_bus::{EventBus, TransferEvent};
pub use event_persistence::{EventStore, EventStoreError, InMemoryEventStore};
#[cfg(feature = "persistent")]
pub use execution_journal::RocksDbExecutionJournal;
pub use execution_journal::{
    ExecutionJournal, InMemoryJournal, JournalError, PhaseOutcome, TransferPhaseEntry,
};
pub use failure_domain::{ClassifiedError, FailureDomain};
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
pub use send_transfer::{
    Consignment, SealAssignment, SealCloseWitness, SendExecutor, SendExecutorError, SendReceipt,
    SendTransfer,
};
pub use transfer_coordinator::{
    RecoveryContextProvider, SettlementEvidence, SettlementReleaseRecord, SettlementStatus,
    TransferCoordinator, TransferOutcome, TransferReceipt,
};
pub use user_runtime_lease::{
    DEFAULT_LEASE_DURATION_SECS, LeaseValidationError, MAX_LEASE_DURATION_SECS,
    RuntimeExecutionContext, RuntimeId, TransferLease,
};

// Coordinator lease re-exports
pub use distributed_coordinator_lease::{
    CoordinatorId, CoordinatorLease, InMemoryLease, LeaseError, LeaseGuard, MintCoordinator,
    MintProvider, MintReceipt,
};
