//! Runtime health, as the runtime reports it.
//!
//! An application shows this; it does not compute it. In particular, an
//! application must not conclude the runtime is healthy because its last call
//! happened to succeed — degradation is a runtime observation, not a UI inference.

use serde::{Deserialize, Serialize};

use super::{ArtifactKind, ContractArtifact, ContractError, ContractHeader, require_nonempty};

/// Overall runtime health.
///
/// Mirrors `csv_observability::runtime_health::RuntimeHealth` on the wire,
/// including its vocabulary: the unsafe state is called `Unsafe`, not
/// "unhealthy", because the runtime means it — authority operations do not
/// proceed in that state, and softening the word in the UI would be exactly the
/// error-to-warning downgrade the charter forbids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RuntimeHealthState {
    /// All components are operating normally.
    Healthy,
    /// The runtime is degraded but still accepting work.
    Degraded {
        /// Why the runtime declared itself degraded, in the runtime's own terms.
        reason: String,
    },
    /// The runtime is not fit to execute authority operations.
    Unsafe,
}

/// Health of a single runtime component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name, as the runtime names it (e.g. `"replay_db"`, `"circuit_breaker"`).
    pub component: String,
    /// Whether the runtime considers this component healthy.
    pub healthy: bool,
    /// What the runtime observed. Required when unhealthy: a component cannot be
    /// reported as failing without saying why.
    pub detail: Option<String>,
}

/// A runtime health report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHealthReport {
    /// Versioned contract header.
    pub header: ContractHeader,
    /// Overall health.
    pub state: RuntimeHealthState,
    /// Per-component health.
    pub components: Vec<ComponentHealth>,
    /// Unix seconds when the runtime made the observation.
    pub observed_at: u64,
}

impl RuntimeHealthReport {
    /// Build a health report at the current contract version.
    pub fn new(
        state: RuntimeHealthState,
        components: Vec<ComponentHealth>,
        observed_at: u64,
    ) -> Self {
        Self {
            header: ContractHeader::current(ArtifactKind::RuntimeHealth),
            state,
            components,
            observed_at,
        }
    }

    /// Whether the runtime is fit to execute authority operations.
    pub fn is_operational(&self) -> bool {
        !matches!(self.state, RuntimeHealthState::Unsafe)
    }
}

impl ContractArtifact for RuntimeHealthReport {
    const KIND: ArtifactKind = ArtifactKind::RuntimeHealth;

    fn header(&self) -> &ContractHeader {
        &self.header
    }

    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "runtime health report";

        if let RuntimeHealthState::Degraded { reason } = &self.state {
            require_nonempty(ARTIFACT, "state.reason", reason)?;
        }

        for component in &self.components {
            require_nonempty(ARTIFACT, "component", &component.component)?;
            if !component.healthy
                && component
                    .detail
                    .as_ref()
                    .is_none_or(|d| d.trim().is_empty())
            {
                return Err(ContractError::MissingField {
                    artifact: ARTIFACT,
                    field: "detail (required for an unhealthy component)",
                });
            }
        }

        // A report that names a failing component may not call itself healthy: that
        // is exactly the downgrade-to-warning this contract exists to prevent.
        if self.state == RuntimeHealthState::Healthy && self.components.iter().any(|c| !c.healthy) {
            return Err(ContractError::InvalidField {
                artifact: ARTIFACT,
                reason: "report is Healthy while naming an unhealthy component".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{decode, encode};

    fn degraded() -> RuntimeHealthState {
        RuntimeHealthState::Degraded {
            reason: "RpcDisagreement".to_string(),
        }
    }

    #[test]
    fn degraded_report_round_trips() {
        let report = RuntimeHealthReport::new(
            degraded(),
            vec![ComponentHealth {
                component: "circuit_breaker".to_string(),
                healthy: false,
                detail: Some("open after 5 consecutive RPC failures".to_string()),
            }],
            1_700_000_000,
        );
        let bytes = encode(&report).expect("valid report encodes");
        assert_eq!(decode::<RuntimeHealthReport>(&bytes).unwrap(), report);
        assert!(report.is_operational());
    }

    #[test]
    fn degraded_without_a_reason_is_rejected() {
        let report = RuntimeHealthReport::new(
            RuntimeHealthState::Degraded {
                reason: String::new(),
            },
            vec![],
            1_700_000_000,
        );
        assert!(
            report.validate().is_err(),
            "the runtime must say why it degraded"
        );
    }

    #[test]
    fn healthy_report_naming_a_failing_component_is_rejected() {
        let report = RuntimeHealthReport::new(
            RuntimeHealthState::Healthy,
            vec![ComponentHealth {
                component: "replay_db".to_string(),
                healthy: false,
                detail: Some("unreachable".to_string()),
            }],
            1_700_000_000,
        );
        assert!(
            report.validate().is_err(),
            "a failing component must not be downgraded to an overall-healthy report"
        );
    }

    #[test]
    fn unhealthy_component_without_detail_is_rejected() {
        let report = RuntimeHealthReport::new(
            degraded(),
            vec![ComponentHealth {
                component: "replay_db".to_string(),
                healthy: false,
                detail: None,
            }],
            1_700_000_000,
        );
        assert!(matches!(
            report.validate(),
            Err(ContractError::MissingField { .. })
        ));
    }

    #[test]
    fn an_unsafe_runtime_is_not_operational() {
        let report = RuntimeHealthReport::new(RuntimeHealthState::Unsafe, vec![], 1_700_000_000);
        assert!(!report.is_operational());
    }
}
