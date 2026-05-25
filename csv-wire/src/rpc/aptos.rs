use csv_algebra::proof::CanonicalProof;

/// Aptos-specific RPC wire format.
#[derive(Debug, Clone)]
pub struct AptosRpcProof {
    pub version: u64,
    pub block_hash: Vec<u8>,
    pub state_root_hash: Vec<u8>,
    pub ledger_info: Vec<u8>,
}

impl TryFrom<AptosRpcProof> for CanonicalProof {
    type Error = String;

    fn try_from(rpc_proof: AptosRpcProof) -> Result<Self, String> {
        let block_hash: [u8; 32] = rpc_proof.block_hash
            .try_into()
            .map_err(|_| "Aptos block_hash must be 32 bytes".to_string())?;

        let state_root: [u8; 32] = rpc_proof.state_root_hash
            .try_into()
            .map_err(|_| "Aptos state_root must be 32 bytes".to_string())?;

        Ok(CanonicalProof::new(
            rpc_proof.version,
            block_hash,
            state_root,
            vec![rpc_proof.ledger_info],
            3, // Aptos chain ID as u32
        ).with_metadata("aptos_version".to_string(), rpc_proof.version.to_be_bytes().to_vec()))
    }
}
