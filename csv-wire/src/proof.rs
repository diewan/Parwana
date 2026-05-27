use crate::canonical::CanonicalProofWire;
use csv_algebra::proof::CanonicalProof;
use serde::{Deserialize, Serialize};

/// Proof bundle wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundleWire {
    pub proofs: Vec<CanonicalProofWire>,
    pub bundle_id: String,
    pub timestamp: u64,
}

impl ProofBundleWire {
    pub fn new(proofs: Vec<CanonicalProof>, bundle_id: [u8; 32], timestamp: u64) -> Self {
        Self {
            proofs: proofs.into_iter().map(|p| p.into()).collect(),
            bundle_id: hex::encode(bundle_id),
            timestamp,
        }
    }

    pub fn bundle_id(&self) -> Result<[u8; 32], String> {
        hex::decode(&self.bundle_id)
            .map_err(|e| format!("Invalid bundle_id hex: {}", e))?
            .try_into()
            .map_err(|_| "bundle_id must be 32 bytes".to_string())
    }
}
