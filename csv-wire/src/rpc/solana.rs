use csv_algebra::proof::CanonicalProof;
use csv_algebra::transfer::ChainId;

/// Solana-specific RPC wire format.
#[derive(Debug, Clone)]
pub struct SolanaRpcProof {
    pub slot: u64,
    pub block_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub proof: Vec<u8>,
}

impl TryFrom<SolanaRpcProof> for CanonicalProof {
    type Error = String;

    fn try_from(rpc_proof: SolanaRpcProof) -> Result<Self, String> {
        let block_hash: [u8; 32] = rpc_proof.block_hash
            .try_into()
            .map_err(|_| "Solana block_hash must be 32 bytes".to_string())?;

        let state_root: [u8; 32] = rpc_proof.state_root
            .try_into()
            .map_err(|_| "Solana state_root must be 32 bytes".to_string())?;

        Ok(CanonicalProof::new(
            rpc_proof.slot,
            block_hash,
            state_root,
            vec![rpc_proof.proof],
            2, // Solana chain ID as u32
        ))
    }
}
