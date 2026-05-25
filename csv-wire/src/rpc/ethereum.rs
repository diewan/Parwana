use csv_algebra::proof::CanonicalProof;
use csv_algebra::transfer::ChainId;

/// Ethereum-specific RPC wire format.
#[derive(Debug, Clone)]
pub struct EthereumRpcProof {
    pub block_number: u64,
    pub block_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Vec<Vec<u8>>,
}

impl TryFrom<EthereumRpcProof> for CanonicalProof {
    type Error = String;

    fn try_from(rpc_proof: EthereumRpcProof) -> Result<Self, String> {
        let block_hash: [u8; 32] = rpc_proof.block_hash
            .try_into()
            .map_err(|_| "Ethereum block_hash must be 32 bytes".to_string())?;

        let state_root: [u8; 32] = rpc_proof.state_root
            .try_into()
            .map_err(|_| "Ethereum state_root must be 32 bytes".to_string())?;

        let mut proof_nodes = rpc_proof.account_proof;
        proof_nodes.extend(rpc_proof.storage_proof);

        Ok(CanonicalProof::new(
            rpc_proof.block_number,
            block_hash,
            state_root,
            proof_nodes,
            1, // Ethereum chain ID as u32
        ))
    }
}
