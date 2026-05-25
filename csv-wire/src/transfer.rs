use serde::{Serialize, Deserialize};

/// Transfer wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferWire {
    pub transfer_id: String,
    pub seal_id: String,
    pub source_chain: u32,
    pub dest_chain: u32,
}

impl TransferWire {
    pub fn new(transfer_id: [u8; 32], seal_id: [u8; 32], source_chain: u32, dest_chain: u32) -> Self {
        Self {
            transfer_id: hex::encode(transfer_id),
            seal_id: hex::encode(seal_id),
            source_chain,
            dest_chain,
        }
    }

    pub fn transfer_id(&self) -> Result<[u8; 32], String> {
        hex::decode(&self.transfer_id)
            .map_err(|e| format!("Invalid transfer_id hex: {}", e))?
            .try_into()
            .map_err(|_| "transfer_id must be 32 bytes".to_string())
    }

    pub fn seal_id(&self) -> Result<[u8; 32], String> {
        hex::decode(&self.seal_id)
            .map_err(|e| format!("Invalid seal_id hex: {}", e))?
            .try_into()
            .map_err(|_| "seal_id must be 32 bytes".to_string())
    }
}
