//! Wire format types for L3 storage serialization.
//!
//! These types provide serde-compatible wrappers for L0 types (Hash, SanadId, Commitment)
//! that are used in L3 storage layers (checkpoints, persistence). L0 types themselves
//! do not have serde derives to enforce canonical encoding in protocol-critical paths.

use csv_hash::{Commitment, Hash, SanadId};
use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

/// Wire format for hash (hex-encoded string for serde serialization).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashWire {
    pub bytes: String,
}

impl HashWire {
    /// Get the raw bytes of the hash (decodes hex string)
    pub fn as_bytes(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.bytes).map_err(|e| format!("Invalid hash hex: {}", e))
    }
}

impl From<Hash> for HashWire {
    fn from(hash: Hash) -> Self {
        Self {
            bytes: hex::encode(hash.as_slice()),
        }
    }
}

impl TryFrom<HashWire> for Hash {
    type Error = String;

    fn try_from(wire: HashWire) -> Result<Self, String> {
        let bytes = hex::decode(&wire.bytes).map_err(|e| format!("Invalid hash hex: {}", e))?;

        if bytes.len() != 32 {
            return Err("Hash must be 32 bytes".to_string());
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash::new(arr))
    }
}

/// Wire format for SanadId (hex-encoded string for serde serialization).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SanadIdWire {
    pub bytes: String,
}

impl SanadIdWire {
    /// Get the raw bytes of the sanad_id (decodes hex string)
    pub fn as_bytes(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.bytes).map_err(|e| format!("Invalid sanad_id hex: {}", e))
    }
}

impl From<SanadId> for SanadIdWire {
    fn from(sanad_id: SanadId) -> Self {
        Self {
            bytes: hex::encode(sanad_id.as_bytes()),
        }
    }
}

impl TryFrom<SanadIdWire> for SanadId {
    type Error = String;

    fn try_from(wire: SanadIdWire) -> Result<Self, String> {
        let bytes = hex::decode(&wire.bytes).map_err(|e| format!("Invalid sanad_id hex: {}", e))?;

        Ok(SanadId::from_bytes(&bytes))
    }
}

/// Wire format for commitment (hex-encoded fields for serde serialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentWire {
    pub version: u8,
    pub protocol_id: String,
    pub mpc_root: String,
    pub contract_id: String,
    pub previous_commitment: String,
    pub transition_payload_hash: String,
    pub seal_id: String,
    pub domain_separator: String,
}

impl From<Commitment> for CommitmentWire {
    fn from(commitment: Commitment) -> Self {
        Self {
            version: commitment.version,
            protocol_id: hex::encode(commitment.protocol_id.as_slice()),
            mpc_root: hex::encode(commitment.mpc_root.as_slice()),
            contract_id: hex::encode(commitment.contract_id.as_slice()),
            previous_commitment: hex::encode(commitment.previous_commitment.as_slice()),
            transition_payload_hash: hex::encode(commitment.transition_payload_hash.as_slice()),
            seal_id: hex::encode(commitment.seal_id.as_slice()),
            domain_separator: hex::encode(commitment.domain_separator),
        }
    }
}

impl TryFrom<CommitmentWire> for Commitment {
    type Error = String;

    fn try_from(wire: CommitmentWire) -> Result<Self, String> {
        let decode_hash = |hex_str: &str| -> Result<Hash, String> {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
            if bytes.len() != 32 {
                return Err("Hash must be 32 bytes".to_string());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Hash::new(arr))
        };

        let protocol_id = decode_hash(&wire.protocol_id)?;
        let mpc_root = decode_hash(&wire.mpc_root)?;
        let contract_id = decode_hash(&wire.contract_id)?;
        let previous_commitment = decode_hash(&wire.previous_commitment)?;
        let transition_payload_hash = decode_hash(&wire.transition_payload_hash)?;
        let seal_id = decode_hash(&wire.seal_id)?;

        let domain_separator = hex::decode(&wire.domain_separator)
            .map_err(|e| format!("Invalid domain_separator hex: {}", e))?;

        if domain_separator.len() != 32 {
            return Err("domain_separator must be 32 bytes".to_string());
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&domain_separator);

        Ok(Commitment {
            version: wire.version,
            protocol_id,
            mpc_root,
            contract_id,
            previous_commitment,
            transition_payload_hash,
            seal_id,
            domain_separator: arr,
        })
    }
}

/// Wire format for SealPoint (hex-encoded fields for serde serialization).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealPointWire {
    pub id: String,
    pub nonce: Option<u64>,
    pub version: Option<u64>,
}

impl From<SealPoint> for SealPointWire {
    fn from(seal_point: SealPoint) -> Self {
        Self {
            id: hex::encode(&seal_point.id),
            nonce: seal_point.nonce,
            version: seal_point.version,
        }
    }
}

impl TryFrom<SealPointWire> for SealPoint {
    type Error = String;

    fn try_from(wire: SealPointWire) -> Result<Self, String> {
        let id = hex::decode(&wire.id).map_err(|e| format!("Invalid seal point id hex: {}", e))?;
        
        SealPoint::new(id, wire.nonce, wire.version)
            .map_err(|e| e.to_string())
    }
}
