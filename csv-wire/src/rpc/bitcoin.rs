use csv_algebra::proof::CanonicalProof;
use csv_algebra::transfer::ChainId;

/// Bitcoin-specific RPC wire format.
#[derive(Debug, Clone)]
pub struct BitcoinRpcProof {
    pub block_height: u64,
    pub block_hash: Vec<u8>,
    pub merkle_proof: Vec<Vec<u8>>,
    pub tx_index: u32,
}

impl TryFrom<BitcoinRpcProof> for CanonicalProof {
    type Error = String;

    fn try_from(rpc_proof: BitcoinRpcProof) -> Result<Self, String> {
        let block_hash: [u8; 32] = rpc_proof.block_hash
            .try_into()
            .map_err(|_| "Bitcoin block_hash must be 32 bytes".to_string())?;

        // Bitcoin doesn't have a traditional state_root, use block_hash as placeholder
        let state_root = block_hash;

        Ok(CanonicalProof::new(
            rpc_proof.block_height,
            block_hash,
            state_root,
            rpc_proof.merkle_proof,
            ChainId::new(0), // Bitcoin chain ID
        ).with_metadata("tx_index".to_string(), rpc_proof.tx_index.to_be_bytes().to_vec()))
    }
}
