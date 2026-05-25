use serde::{Serialize, Deserialize};
use csv_algebra::proof::CanonicalProof as AlgebraProof;
use csv_algebra::proof::Metadata;

/// Wire format for canonical proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalProofWire {
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub proof_nodes: Vec<String>,
    pub chain_id: u32,
    pub metadata_fields: Vec<(String, String)>,
}

impl From<AlgebraProof> for CanonicalProofWire {
    fn from(proof: AlgebraProof) -> Self {
        Self {
            block_height: proof.block_height,
            block_hash: hex::encode(proof.block_hash),
            state_root: hex::encode(proof.state_root),
            proof_nodes: proof.proof_nodes.iter().map(|n| hex::encode(n)).collect(),
            chain_id: proof.chain_id(),
            metadata_fields: proof.metadata.fields.iter()
                .map(|(k, v)| (k.clone(), hex::encode(v)))
                .collect(),
        }
    }
}

impl TryFrom<CanonicalProofWire> for AlgebraProof {
    type Error = String;

    fn try_from(wire: CanonicalProofWire) -> Result<Self, String> {
        let block_hash = hex::decode(&wire.block_hash)
            .map_err(|e| format!("Invalid block_hash hex: {}", e))?
            .try_into()
            .map_err(|_| "block_hash must be 32 bytes".to_string())?;

        let state_root = hex::decode(&wire.state_root)
            .map_err(|e| format!("Invalid state_root hex: {}", e))?
            .try_into()
            .map_err(|_| "state_root must be 32 bytes".to_string())?;

        let proof_nodes = wire.proof_nodes.iter()
            .map(|n| hex::decode(n).map_err(|e| format!("Invalid proof_node hex: {}", e)))
            .collect::<Result<Vec<_>, _>>()?;

        let metadata_fields = wire.metadata_fields.iter()
            .map(|(k, v)| hex::decode(v).map(|bytes| (k.clone(), bytes)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid metadata field hex: {}", e))?;

        Ok(AlgebraProof {
            block_height: wire.block_height,
            block_hash,
            state_root,
            proof_nodes,
            metadata: Metadata {
                chain_id: wire.chain_id,
                fields: metadata_fields,
            },
        })
    }
}
