use serde::{Deserialize, Serialize};

/// Reasons why a runtime may be in a degraded state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DegradedReason {
    /// RPC nodes disagree about canonicality/quorum.
    RpcDisagreement,
    /// Quorum calculation collapsed below threshold.
    QuorumCollapse,
    /// Historical continuity anchor check failed on restart.
    HistoricalContinuityFailure,
    /// Replay registry is unavailable or inconsistent.
    ReplayRegistryUnavailable,
    /// Event persistence is lagging or blocked.
    EventPersistenceLag,
    /// Clock skew/drift detected across nodes.
    ClockDrift,
    /// Partial network partition causing split-brain risk.
    PartialPartition,
    /// Trust package used for offline verification expired.
    TrustPackageExpiry,
}

/// Runtime health state used to gate unsafe operations like minting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RuntimeHealth {
    /// Fully operational runtime.
    Healthy,
    /// Degraded but partially operational; contains a reason.
    Degraded {
        /// Reason for degradation.
        reason: DegradedReason,
    },
    /// Unsafe mode: critical failures; runtime must prevent dangerous ops.
    Unsafe,
}
