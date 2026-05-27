use csv_hash::{ChainId, Hash, SanadId};
use csv_protocol::transfer_state::{
    AwaitingFinality, Locked, ProofBuilding, ProofValidated, TransferData,
};
use serde::{Deserialize, Serialize};

/// Wire format for transfer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDataWire {
    pub transfer_id: String,
    pub sanad_id: String,
    pub source_chain: u32,
    pub destination_chain: u32,
    pub seal_point: String,
    pub commitment_hash: String,
    pub initiated_at: u64,
}

impl From<TransferData> for TransferDataWire {
    fn from(data: TransferData) -> Self {
        Self {
            transfer_id: hex::encode(data.transfer_id.as_slice()),
            sanad_id: hex::encode(data.sanad_id.as_bytes()),
            source_chain: data.source_chain.as_str().parse().unwrap_or(0),
            destination_chain: data.destination_chain.as_str().parse().unwrap_or(0),
            seal_point: hex::encode(&data.seal_point),
            commitment_hash: hex::encode(data.commitment_hash.as_slice()),
            initiated_at: data.initiated_at,
        }
    }
}

impl TryFrom<TransferDataWire> for TransferData {
    type Error = String;

    fn try_from(wire: TransferDataWire) -> Result<Self, String> {
        let transfer_id_bytes = hex::decode(&wire.transfer_id)
            .map_err(|e| format!("Invalid transfer_id hex: {}", e))?;
        let transfer_id = if transfer_id_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&transfer_id_bytes);
            Hash::new(arr)
        } else {
            return Err("transfer_id must be 32 bytes".to_string());
        };

        let sanad_id_bytes =
            hex::decode(&wire.sanad_id).map_err(|e| format!("Invalid sanad_id hex: {}", e))?;
        let sanad_id = SanadId::from_bytes(&sanad_id_bytes);

        let source_chain = ChainId::new(&wire.source_chain.to_string());
        let destination_chain = ChainId::new(&wire.destination_chain.to_string());

        let seal_point =
            hex::decode(&wire.seal_point).map_err(|e| format!("Invalid seal_point hex: {}", e))?;

        let commitment_hash_bytes = hex::decode(&wire.commitment_hash)
            .map_err(|e| format!("Invalid commitment_hash hex: {}", e))?;
        let commitment_hash = if commitment_hash_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&commitment_hash_bytes);
            Hash::new(arr)
        } else {
            return Err("commitment_hash must be 32 bytes".to_string());
        };

        Ok(TransferData::new(
            transfer_id,
            sanad_id,
            source_chain,
            destination_chain,
            seal_point,
            commitment_hash,
        ))
    }
}

/// Wire format for locked state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedWire {
    pub data: TransferDataWire,
    pub lock_height: u64,
    pub lock_tx_hash: String,
}

impl From<Locked> for LockedWire {
    fn from(locked: Locked) -> Self {
        Self {
            data: locked.data.into(),
            lock_height: locked.lock_height,
            lock_tx_hash: hex::encode(&locked.lock_tx_hash),
        }
    }
}

impl TryFrom<LockedWire> for Locked {
    type Error = String;

    fn try_from(wire: LockedWire) -> Result<Self, String> {
        let data = wire.data.try_into()?;
        let lock_tx_hash = hex::decode(&wire.lock_tx_hash)
            .map_err(|e| format!("Invalid lock_tx_hash hex: {}", e))?;

        Ok(Locked::new(data, wire.lock_height, lock_tx_hash))
    }
}

/// Wire format for awaiting finality state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingFinalityWire {
    pub data: TransferDataWire,
    pub proof_height: u64,
    pub required_confirmations: u32,
    pub current_confirmations: u32,
}

impl From<AwaitingFinality> for AwaitingFinalityWire {
    fn from(state: AwaitingFinality) -> Self {
        Self {
            data: state.data.into(),
            proof_height: state.proof_height,
            required_confirmations: state.required_confirmations,
            current_confirmations: state.current_confirmations,
        }
    }
}

impl TryFrom<AwaitingFinalityWire> for AwaitingFinality {
    type Error = String;

    fn try_from(wire: AwaitingFinalityWire) -> Result<Self, String> {
        let data = wire.data.try_into()?;
        let mut state = AwaitingFinality::new(data, wire.proof_height, wire.required_confirmations);
        state.update_confirmations(wire.current_confirmations);
        Ok(state)
    }
}

/// Wire format for proof building state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBuildingWire {
    pub data: TransferDataWire,
    pub started_at: u64,
    pub progress: u8,
}

impl From<ProofBuilding> for ProofBuildingWire {
    fn from(state: ProofBuilding) -> Self {
        Self {
            data: state.data.into(),
            started_at: state.started_at,
            progress: state.progress,
        }
    }
}

impl TryFrom<ProofBuildingWire> for ProofBuilding {
    type Error = String;

    fn try_from(wire: ProofBuildingWire) -> Result<Self, String> {
        let data = wire.data.try_into()?;
        let mut state = ProofBuilding::new(data);
        state.started_at = wire.started_at;
        state.update_progress(wire.progress);
        Ok(state)
    }
}

/// Wire format for proof validated state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofValidatedWire {
    pub data: TransferDataWire,
    pub proof: String,
    pub validated_at: u64,
}

impl From<ProofValidated> for ProofValidatedWire {
    fn from(state: ProofValidated) -> Self {
        Self {
            data: state.data.into(),
            proof: hex::encode(&state.proof),
            validated_at: state.validated_at,
        }
    }
}

impl TryFrom<ProofValidatedWire> for ProofValidated {
    type Error = String;

    fn try_from(wire: ProofValidatedWire) -> Result<Self, String> {
        let data = wire.data.try_into()?;
        let proof = hex::decode(&wire.proof).map_err(|e| format!("Invalid proof hex: {}", e))?;

        let mut state = ProofValidated::new(data, proof);
        state.validated_at = wire.validated_at;
        Ok(state)
    }
}
