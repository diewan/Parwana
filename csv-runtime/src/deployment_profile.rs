//! Deployment profiles with per-component minimum thresholds.
//!
//! This module defines the `DeploymentProfile` enum which specifies the
//! minimum security thresholds for each deployment environment.
//! These are per-component requirements (not scalar enum comparisons).
//! `VerificationAssurance` is a display-only signal; production gating
//! must use `VerificationResult::meets_chain_thresholds` with `ChainCapabilities`.

use csv_protocol::verification_results::{FinalityStrength, InclusionStrength};

/// Deployment environment profiles.
///
/// Each profile defines minimum inclusion and finality thresholds
/// appropriate for that environment's risk tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeploymentProfile {
    /// Local development — minimal security, fast iteration.
    Local,
    /// Integration testing — basic security for CI/CD pipelines.
    Integration,
    /// Public testnet — moderate security for testnet operations.
    Testnet,
    /// Staging — near-production security for pre-production validation.
    Staging,
    /// Production — maximum security for mainnet operations.
    Production,
}

impl DeploymentProfile {
    /// Returns the minimum per-component inclusion thresholds for this deployment profile.
    pub fn minimum_inclusion(&self) -> InclusionStrength {
        match self {
            Self::Local | Self::Integration => InclusionStrength::Checksum,
            Self::Testnet | Self::Staging | Self::Production => InclusionStrength::MerklePath,
        }
    }

    /// Returns the minimum per-component finality thresholds for this deployment profile.
    pub fn minimum_finality(&self) -> FinalityStrength {
        match self {
            Self::Local => FinalityStrength::None,
            Self::Integration => FinalityStrength::Probabilistic { confirmations: 1 },
            Self::Testnet | Self::Staging => FinalityStrength::Probabilistic { confirmations: 3 },
            Self::Production => FinalityStrength::Deterministic,
        }
    }

    /// Reads the deployment profile from the CSV_DEPLOY_PROFILE environment variable.
    ///
    /// Defaults to `Local` if the environment variable is not set or contains
    /// an unrecognized value.
    pub fn from_env() -> Self {
        match std::env::var("CSV_DEPLOY_PROFILE").as_deref() {
            Ok("production") => Self::Production,
            Ok("staging") => Self::Staging,
            Ok("testnet") => Self::Testnet,
            Ok("integration") => Self::Integration,
            _ => Self::Local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_profile() {
        let profile = DeploymentProfile::Local;
        assert_eq!(profile.minimum_inclusion(), InclusionStrength::Checksum);
        assert_eq!(profile.minimum_finality(), FinalityStrength::None);
    }

    #[test]
    fn test_integration_profile() {
        let profile = DeploymentProfile::Integration;
        assert_eq!(profile.minimum_inclusion(), InclusionStrength::Checksum);
        assert_eq!(
            profile.minimum_finality(),
            FinalityStrength::Probabilistic { confirmations: 1 }
        );
    }

    #[test]
    fn test_testnet_profile() {
        let profile = DeploymentProfile::Testnet;
        assert_eq!(profile.minimum_inclusion(), InclusionStrength::MerklePath);
        assert_eq!(
            profile.minimum_finality(),
            FinalityStrength::Probabilistic { confirmations: 3 }
        );
    }

    #[test]
    fn test_staging_profile() {
        let profile = DeploymentProfile::Staging;
        assert_eq!(profile.minimum_inclusion(), InclusionStrength::MerklePath);
        assert_eq!(
            profile.minimum_finality(),
            FinalityStrength::Probabilistic { confirmations: 3 }
        );
    }

    #[test]
    fn test_production_profile() {
        let profile = DeploymentProfile::Production;
        assert_eq!(profile.minimum_inclusion(), InclusionStrength::MerklePath);
        assert_eq!(profile.minimum_finality(), FinalityStrength::Deterministic);
    }

    #[test]
    fn test_from_env_defaults_to_local() {
        // Ensure no env var is set during tests
        std::env::remove_var("CSV_DEPLOY_PROFILE");
        assert_eq!(DeploymentProfile::from_env(), DeploymentProfile::Local);
    }

    #[test]
    fn test_from_env_production() {
        std::env::set_var("CSV_DEPLOY_PROFILE", "production");
        assert_eq!(DeploymentProfile::from_env(), DeploymentProfile::Production);
        std::env::remove_var("CSV_DEPLOY_PROFILE");
    }

    #[test]
    fn test_from_env_unrecognized_falls_back() {
        std::env::set_var("CSV_DEPLOY_PROFILE", "unknown_value");
        assert_eq!(DeploymentProfile::from_env(), DeploymentProfile::Local);
        std::env::remove_var("CSV_DEPLOY_PROFILE");
    }
}
