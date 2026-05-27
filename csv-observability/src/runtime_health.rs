//! Runtime health state reported to operators and safety gates.

use serde::{Deserialize, Serialize};

/// Reason a runtime cannot be considered fully healthy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DegradedReason {
    RpcDisagreement,
    QuorumCollapse,
    HistoricalContinuityFailure,
    ReplayRegistryUnavailable,
    EventPersistenceLag,
    ClockDrift,
    PartialPartition,
    TrustPackageExpiry,
}

/// Health state used when deciding whether authority operations may proceed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeHealth {
    Healthy,
    Degraded { reason: DegradedReason },
    Unsafe,
}
