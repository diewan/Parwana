use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

/// Wire format for seal point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPointWire {
    pub id: String,
    pub nonce: Option<u64>,
}

impl From<SealPoint> for SealPointWire {
    fn from(seal: SealPoint) -> Self {
        Self {
            id: hex::encode(&seal.id),
            nonce: seal.nonce,
        }
    }
}

impl TryFrom<SealPointWire> for SealPoint {
    type Error = String;

    fn try_from(wire: SealPointWire) -> Result<Self, String> {
        let id = hex::decode(&wire.id).map_err(|e| format!("Invalid id hex: {}", e))?;

        SealPoint::new(id, wire.nonce).map_err(|e| e.to_string())
    }
}
