use alloc::string::String;
use alloc::vec::Vec;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use csv_hash::Hash;

/// Provenance metadata for a fetched proof bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofProvenance {
    /// URLs from which the proof material was fetched.
    pub fetched_from: Vec<String>,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
    /// Hash of the RPC quorum decision used to assemble the proof.
    pub rpc_quorum_hash: Hash,
    /// Runtime version string recorded when the proof was observed.
    pub runtime_version: String,
    /// Adapter version string recorded when the proof was observed.
    pub adapter_version: String,
    /// Optional hash of the trust package used for offline verification.
    pub trust_package_hash: Option<Hash>,
}
