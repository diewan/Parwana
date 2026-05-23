//! Protocol version compatibility matrix — formal version negotiation.
//!
//! The runtime refuses transfer execution when:
//! - proof schema version mismatches
//! - adapter capability version mismatches
//! - replay semantics differ
//! - finality semantics differ

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use csv_hash::chain_id::ChainId;
use crate::protocol_version::ProtocolVersion;

/// Compatibility matrix for version negotiation across protocol components.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    /// Protocol version this matrix was generated for.
    pub protocol_version: ProtocolVersion,
    /// Minimum runtime version that is compatible.
    pub minimum_runtime_version: ProtocolVersion,
    /// Minimum adapter versions per chain.
    pub minimum_adapter_versions: BTreeMap<ChainId, ProtocolVersion>,
}

/// Result of a version compatibility check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityResult {
    /// Versions are fully compatible.
    Compatible,
    /// Versions are incompatible for the given reason.
    Incompatible(String),
}

impl CompatibilityMatrix {
    /// Create a new compatibility matrix.
    pub fn new(
        protocol_version: ProtocolVersion,
        minimum_runtime_version: ProtocolVersion,
    ) -> Self {
        Self {
            protocol_version,
            minimum_runtime_version,
            minimum_adapter_versions: BTreeMap::new(),
        }
    }

    /// Set the minimum adapter version for a chain.
    pub fn with_adapter_version(
        mut self,
        chain: ChainId,
        version: ProtocolVersion,
    ) -> Self {
        self.minimum_adapter_versions.insert(chain, version);
        self
    }

    /// Check if a runtime version is compatible.
    pub fn check_runtime(&self, runtime_version: &ProtocolVersion) -> CompatibilityResult {
        if runtime_version.major != self.minimum_runtime_version.major {
            return CompatibilityResult::Incompatible(format!(
                "Runtime major version mismatch: expected {}, got {}",
                self.minimum_runtime_version.major, runtime_version.major
            ));
        }
        if runtime_version.minor < self.minimum_runtime_version.minor {
            return CompatibilityResult::Incompatible(format!(
                "Runtime version too old: minimum {}.{}.x, got {}.{}.{}",
                self.minimum_runtime_version.major,
                self.minimum_runtime_version.minor,
                runtime_version.major,
                runtime_version.minor,
                runtime_version.patch,
            ));
        }
        CompatibilityResult::Compatible
    }

    /// Check if an adapter version for a chain is compatible.
    pub fn check_adapter(
        &self,
        chain: &ChainId,
        adapter_version: &ProtocolVersion,
    ) -> CompatibilityResult {
        match self.minimum_adapter_versions.get(chain) {
            Some(min_version) => {
                if adapter_version.major != min_version.major {
                    return CompatibilityResult::Incompatible(format!(
                        "Adapter {} major version mismatch: expected {}, got {}",
                        chain, min_version.major, adapter_version.major
                    ));
                }
                if adapter_version.minor < min_version.minor {
                    return CompatibilityResult::Incompatible(format!(
                        "Adapter {} version too old: minimum {}.{}.x, got {}.{}.{}",
                        chain,
                        min_version.major,
                        min_version.minor,
                        adapter_version.major,
                        adapter_version.minor,
                        adapter_version.patch,
                    ));
                }
                CompatibilityResult::Compatible
            }
            None => CompatibilityResult::Incompatible(format!(
                "Chain {} not found in compatibility matrix",
                chain
            )),
        }
    }

    /// Validate all components against the matrix, returning all incompatibilities.
    pub fn validate_all(
        &self,
        runtime_version: &ProtocolVersion,
        adapter_versions: &[(ChainId, ProtocolVersion)],
    ) -> Vec<CompatibilityResult> {
        let mut results = Vec::new();
        results.push(self.check_runtime(runtime_version));
        for (chain, version) in adapter_versions {
            results.push(self.check_adapter(chain, version));
        }
        results
    }
}