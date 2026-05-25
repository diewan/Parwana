use crate::finality::FinalityEvidence;

/// Pure proof types.
/// 
/// Canonical proof structures without wire encoding.
/// No serde, no IO, no infrastructure dependencies.

/// A canonical proof structure.
/// This is the protocol-level representation of a proof,
/// independent of any chain-specific encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProof {
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// State root
    pub state_root: [u8; 32],
    /// Proof nodes (Merkle proof or equivalent)
    pub proof_nodes: Vec<Vec<u8>>,
    /// Chain-specific metadata
    pub metadata: Metadata,
}

/// Chain-specific proof metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Chain identifier
    pub chain_id: u32,
    /// Additional chain-specific fields
    pub fields: Vec<(String, Vec<u8>)>,
}

impl CanonicalProof {
    pub fn new(
        block_height: u64,
        block_hash: [u8; 32],
        state_root: [u8; 32],
        proof_nodes: Vec<Vec<u8>>,
        chain_id: u32,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            state_root,
            proof_nodes,
            metadata: Metadata {
                chain_id,
                fields: Vec::new(),
            },
        }
    }

    pub fn with_metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.fields.push((key, value));
        self
    }

    pub fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    pub fn state_root(&self) -> &[u8; 32] {
        &self.state_root
    }

    pub fn chain_id(&self) -> u32 {
        self.metadata.chain_id
    }
}

/// Proof ancestry information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAncestry {
    /// Parent proof hash
    pub parent_hash: [u8; 32],
    /// Sequence number
    pub sequence: u64,
}

impl ProofAncestry {
    pub fn new(parent_hash: [u8; 32], sequence: u64) -> Self {
        Self {
            parent_hash,
            sequence,
        }
    }
}
