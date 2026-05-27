use csv_algebra::proof::CanonicalProof;

/// Celestia-specific RPC wire format.
#[derive(Debug, Clone)]
pub struct CelestiaRpcProof {
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub namespace: Vec<u8>,
    pub share_proof: Vec<u8>,
    pub blob_index: u32,
}

impl TryFrom<CelestiaRpcProof> for CanonicalProof {
    type Error = String;

    fn try_from(rpc_proof: CelestiaRpcProof) -> Result<Self, String> {
        let block_hash: [u8; 32] = rpc_proof.block_hash
            .try_into()
            .map_err(|_| "Celestia block_hash must be 32 bytes".to_string())?;

        let namespace: [u8; 32] = rpc_proof.namespace
            .try_into()
            .map_err(|_| "Celestia namespace must be 32 bytes".to_string())?;

        Ok(CanonicalProof::new(
            rpc_proof.height,
            block_hash,
            namespace,
            vec![rpc_proof.share_proof],
            4, // Celestia chain ID as u32
        )
        .with_metadata("blob_index".to_string(), rpc_proof.blob_index.to_be_bytes().to_vec()))
    }
}
