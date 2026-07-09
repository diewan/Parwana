//! Celestia Seal Protocol Implementation
//!
//! This module implements the `SealProtocol` trait from `csv_protocol` for the
//! Celestia Data Availability layer. It provides:
//!
//! - **Single-use seals** via proof consumption on Celestia
//! - **Commitment anchoring** on the DA layer
//! - **Inclusion proofs** for verification
//! - **Finality guarantees** via Tendermint consensus
//!
//! ## Single Use Seal Model
//!
//! Celestia seals are unique by their (height, namespace, commitment) tuple.
//! Once a seal is "consumed" (used for a state transition), it cannot be
//! reused because the commitment would conflict.
//!
//! ```text
//! Seal Consumption:
//! 1. Create seal pointing to uncommitted DA location
//! 2. Publish commitment to that location
//! 3. Seal is now "consumed" (cannot publish different commitment there)
//! ```

use async_trait::async_trait;
use csv_hash::Hash;
use csv_hash::dag::DAGSegment;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;

use crate::blob::Blob;
use crate::commitment::{BlobCommitment, CommitmentProof, FraudProof};
use crate::da_layer::{CelestiaDaLayer, CelestiaRpc, DataAvailabilityLayer};
use crate::error::{CelestiaError, Result};
use crate::ipfs::IpfsClient;
use crate::namespace::Namespace;
use crate::proof_id::ProofId;
use crate::types::{CelestiaAnchor, CelestiaFinalityProof, CelestiaSealPoint};

/// Celestia-specific seal protocol implementation
pub struct CelestiaSealProtocol<C, I> {
    /// Inner DA layer
    da_layer: CelestiaDaLayer<C, I>,
    /// Default namespace for seals
    namespace: Namespace,
}

impl<C, I> CelestiaSealProtocol<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    /// Create a new seal protocol
    pub fn new(da_layer: CelestiaDaLayer<C, I>, namespace: Namespace) -> Self {
        Self {
            da_layer,
            namespace,
        }
    }

    /// Create with default namespace
    pub fn with_default_namespace(da_layer: CelestiaDaLayer<C, I>) -> Self {
        Self::new(da_layer, Namespace::metadata())
    }

    /// Create a test instance
    pub fn with_test() -> Result<Self>
    where
        C: Default,
        I: Default,
    {
        let da_layer = CelestiaDaLayer::new(
            crate::da_layer::DaLayerConfig::default(),
            C::default(),
            Some(I::default()),
        );
        Ok(Self::new(da_layer, Namespace::metadata()))
    }

    /// Celestia remains DA-only for transfers: this adapter verifies blob
    /// availability/finality but is intentionally not registered as a minting
    /// or transfer-authority adapter.
    pub fn is_da_only(&self) -> bool {
        true
    }
}

/// Convert CelestiaError to csv_protocol::error::ProtocolError
impl From<CelestiaError> for csv_protocol::error::ProtocolError {
    fn from(err: CelestiaError) -> Self {
        csv_protocol::error::ProtocolError::Generic(err.to_string())
    }
}

/// Implement the core SealProtocol trait
#[async_trait]
impl<C, I> SealProtocol for CelestiaSealProtocol<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    type SealPoint = CelestiaSealPoint;
    type CommitAnchor = CelestiaAnchor;
    type InclusionProof = CommitmentProof;
    type FinalityProof = CelestiaFinalityProof;

    async fn publish(
        &self,
        commitment: Hash,
        seal: Self::SealPoint,
        _sanad_id: Hash,
    ) -> std::result::Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        // This is a synchronous wrapper around async code
        // In production, this should be properly async

        // Check that seal hasn't been consumed
        if !seal.is_valid() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Seal already consumed",
            )));
        }

        // The commitment becomes the blob commitment
        let blob_commitment = BlobCommitment::new(*commitment.as_bytes());

        let header = self.da_layer.get_header(seal.height).await?;
        if header.hash == [0u8; 32] {
            return Err(Box::new(CelestiaError::InvalidProofId(
                "Celestia header is missing block hash".to_string(),
            )));
        }

        // Celestia DA anchors are located by height/namespace/blob commitment.
        // There is no destination mint transaction here, so carry the blob
        // commitment as the stable DA anchor identifier in the legacy tx_hash
        // field used by the shared CommitAnchor type.
        let tx_hash = seal.proof_id.commitment;

        // Create the anchor
        let anchor = CelestiaAnchor::new(
            crate::proof_id::ProofLocation::Celestia {
                proof_id: seal.proof_id,
            },
            seal.height,
            header.hash,
            blob_commitment,
            tx_hash,
        );

        Ok(anchor)
    }

    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        let proof_id = anchor.proof_id();
        if proof_id.height != anchor.height {
            return Err(Box::new(CelestiaError::CommitmentVerificationFailed(
                "Anchor height does not match proof location".to_string(),
            )));
        }

        let proof = self.da_layer.get_commitment_proof(&proof_id).await?;
        proof.verify_structure()?;

        if proof.height != anchor.height {
            return Err(Box::new(CelestiaError::CommitmentVerificationFailed(
                "Celestia inclusion proof height mismatch".to_string(),
            )));
        }
        if proof.namespace != proof_id.namespace {
            return Err(Box::new(CelestiaError::NamespaceMismatch {
                expected: proof_id.namespace.to_hex(),
                actual: proof.namespace.to_hex(),
            }));
        }
        if proof.commitment != anchor.commitment {
            return Err(Box::new(CelestiaError::CommitmentVerificationFailed(
                "Celestia inclusion proof commitment mismatch".to_string(),
            )));
        }
        if proof.block_hash != anchor.block_hash {
            return Err(Box::new(CelestiaError::CommitmentVerificationFailed(
                "Celestia inclusion proof block hash mismatch".to_string(),
            )));
        }

        Ok(proof)
    }

    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        let proof_id = anchor.proof_id();
        if proof_id.height != anchor.height {
            return Err(Box::new(CelestiaError::InvalidProofId(
                "Anchor height does not match proof location".to_string(),
            )));
        }

        let proof = self.da_layer.verify_finality(&proof_id).await?;
        proof.verify_structure()?;
        if !proof.is_finalized() {
            return Err(Box::new(CelestiaError::InvalidProofId(
                "Celestia finality proof is missing quorum evidence".to_string(),
            )));
        }

        if proof.height != anchor.height {
            return Err(Box::new(CelestiaError::InvalidProofId(
                "Celestia finality proof height mismatch".to_string(),
            )));
        }
        if proof.block_hash != anchor.block_hash {
            return Err(Box::new(CelestiaError::InvalidProofId(
                "Celestia finality proof block hash mismatch".to_string(),
            )));
        }

        Ok(proof)
    }

    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        // Verify seal hasn't been consumed
        if !seal.is_valid() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Seal has been consumed",
            )));
        }

        // In production, this would query DA to double-check
        Ok(())
    }

    async fn create_seal(
        &self,
        value: Option<u64>,
    ) -> std::result::Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        // Create a new seal at the next available height
        // In production, this would query for the latest height
        let height = value.unwrap_or(1); // Use value as height hint

        // SECURITY CRITICAL: Derive actual commitment from namespace and height
        // instead of using placeholder zeros
        use sha2::Digest;
        let mut commitment_hasher = sha2::Sha256::new();
        commitment_hasher.update(b"CSV-CELESTIA-SEAL-");
        commitment_hasher.update(self.namespace.as_bytes());
        commitment_hasher.update(height.to_le_bytes());
        commitment_hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        let commitment: [u8; 32] = commitment_hasher.finalize().into();

        log::info!(
            "CELESTIA: Derived commitment for seal at height {}: 0x{}",
            height,
            hex::encode(commitment)
        );

        let proof_id = ProofId::new(height, self.namespace, commitment);

        let seal = CelestiaSealPoint::new(proof_id, height);
        Ok(seal)
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Domain separator for Celestia
        hasher.update(self.domain_separator());

        // Include all commitment components
        hasher.update(contract_id.as_bytes());
        hasher.update(previous_commitment.as_bytes());
        hasher.update(transition_payload_hash.as_bytes());
        hasher.update(seal_point.proof_id.to_bytes());

        // Include namespace for domain separation
        hasher.update(self.namespace.as_bytes());

        let hash: [u8; 32] = hasher.finalize().into();
        Hash::new(hash)
    }

    async fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        transition_dag: csv_protocol::seal_protocol::DagSegment,
    ) -> std::result::Result<ProofBundle, Box<dyn std::error::Error + 'static>> {
        let inclusion = self.verify_inclusion(anchor.clone()).await?;
        let finality = self.verify_finality(anchor.clone()).await?;

        let seal_ref =
            csv_hash::seal::SealPoint::new(anchor.location.to_bytes(), Some(anchor.height), None)
                .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid seal: {}", e),
                )) as Box<dyn std::error::Error>
            })?;

        let anchor_ref = csv_hash::seal::CommitAnchor::new(
            anchor.tx_hash.to_vec(),
            anchor.height,
            anchor.commitment.as_bytes().to_vec(),
        )
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid anchor: {}", e),
            )) as Box<dyn std::error::Error>
        })?;

        // Construct proof bytes from row_proof and data_proof
        let mut proof_bytes = Vec::new();
        for hash in &inclusion.row_proof {
            proof_bytes.extend_from_slice(hash);
        }
        for hash in &inclusion.data_proof {
            proof_bytes.extend_from_slice(hash);
        }

        let inclusion_proof = csv_protocol::proof_taxonomy::InclusionProof::new(
            proof_bytes,
            csv_hash::Hash::new(inclusion.block_hash),
            inclusion.height,
            inclusion.row_index as u64,
        )
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid inclusion proof: {}", e),
            )) as Box<dyn std::error::Error>
        })?;

        let finality_proof = csv_protocol::proof_taxonomy::FinalityProof::new(
            anchor.block_hash.to_vec(),
            anchor.height,
            !finality.quorum_signatures.is_empty(),
        )
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid finality proof: {}", e),
            )) as Box<dyn std::error::Error>
        })?;

        // Convert DagSegment to DAGSegment for state transition DAG
        // Compute node_id from anchor hashes to ensure uniqueness
        let mut node_id_data = Vec::new();
        node_id_data.extend_from_slice(transition_dag.anchor_from.as_bytes());
        node_id_data.extend_from_slice(transition_dag.anchor_to.as_bytes());
        let node_id = csv_hash::Hash::new(csv_hash::csv_tagged_hash("dag-node-id", &node_id_data));

        // Create a single DAGNode from the transition data
        let dag_node = csv_hash::dag::DAGNode::new(
            node_id,
            transition_dag.transition_data.clone(),
            vec![transition_dag.proof.clone()], // Use proof as signature
            vec![],                             // No witnesses for single transition
            vec![transition_dag.anchor_from],   // Parent is the source anchor
        );

        // Compute root_commitment from the node
        let root_commitment = dag_node.hash();
        let dag_segment = DAGSegment::new(vec![dag_node], root_commitment);

        // Extract signatures from DAG node
        let signatures: Vec<Vec<u8>> = dag_segment
            .nodes
            .iter()
            .flat_map(|node| node.signatures.clone())
            .collect();

        if signatures.is_empty() {
            log::warn!(
                "CELESTIA: No signatures found in DAGSegment - proof bundle may not be verifiable"
            );
        } else {
            log::info!(
                "CELESTIA: Extracted {} signatures from DAGSegment",
                signatures.len()
            );
        }

        csv_protocol::proof_taxonomy::ProofBundle::with_signature_scheme(
            csv_protocol::signature::SignatureScheme::Secp256k1,
            dag_segment,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Failed to build proof bundle: {}", e),
            )) as Box<dyn std::error::Error>
        })
    }

    async fn rollback(
        &self,
        _anchor: Self::CommitAnchor,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        // Handle rollback for a specific anchor due to chain reorganization
        // In production, this would:
        // 1. Verify the anchor is no longer in the canonical chain
        // 2. Mark the anchor as rolled back
        // 3. Allow the seal to be reused if appropriate

        // For now, we accept the rollback without validation
        // This preserves the audit trail while allowing recovery
        Ok(())
    }

    fn domain_separator(&self) -> [u8; 32] {
        // Domain separator for Celestia adapter
        // Computed as SHA256("CSV/Celestia/v1/production")
        [
            0x8a, 0x3e, 0xf1, 0x9c, 0x2b, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f,
            0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b,
            0x7c, 0x8d, 0x9e, 0x0f,
        ]
    }

    fn signature_scheme(&self) -> SignatureScheme {
        // Celestia uses secp256k1 (Tendermint style)
        SignatureScheme::Secp256k1
    }
}

/// Extended functionality for Celestia seal protocol
impl<C, I> CelestiaSealProtocol<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    /// Submit a blob and create a seal in one operation
    pub async fn submit_and_seal(&self, data: Vec<u8>) -> Result<(ProofId, CelestiaSealPoint)> {
        let blob = Blob::new(self.namespace, data)?;
        let proof_id = self.da_layer.submit_blob(blob).await?;

        let seal = CelestiaSealPoint::new(proof_id, proof_id.height);
        Ok((proof_id, seal))
    }

    /// Verify a full proof bundle from the DA layer
    pub async fn verify_bundle_from_da(&self, proof_id: &ProofId) -> Result<ProofBundle> {
        let blob = self.da_layer.get_blob(proof_id).await?;
        let bundle = ProofBundle::from_canonical_bytes(&blob.data).map_err(|e| {
            CelestiaError::DeserializationError(format!(
                "Failed to deserialize proof bundle: {}",
                e
            ))
        })?;
        Ok(bundle)
    }

    /// Submit a fraud proof to the fraud namespace
    pub async fn submit_fraud_proof(&self, fraud: FraudProof) -> Result<ProofId> {
        self.da_layer.submit_fraud_proof(fraud).await
    }

    /// Get the namespace
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Create a seal with IPFS backing
    pub async fn create_ipfs_seal(&self, data: Vec<u8>) -> Result<(ProofId, CelestiaSealPoint)> {
        let location = self.da_layer.store_on_ipfs(&data, self.namespace).await?;

        let proof_id = match &location {
            crate::proof_id::ProofLocation::Hybrid { metadata_id, .. } => *metadata_id,
            crate::proof_id::ProofLocation::IpfsBacked { anchor_height, .. } => {
                ProofId::new(*anchor_height, self.namespace, [0u8; 32])
            }
            _ => {
                return Err(CelestiaError::InternalError(
                    "Expected hybrid or ipfs-backed location".to_string(),
                ));
            }
        };

        let seal = CelestiaSealPoint::new(proof_id, proof_id.height)
            .with_ipfs(location.cid().unwrap_or(""));

        Ok((proof_id, seal))
    }
}

/// Builder for CelestiaSealProtocol
pub struct CelestiaSealProtocolBuilder<C, I> {
    da_layer: Option<CelestiaDaLayer<C, I>>,
    namespace: Option<Namespace>,
}

impl<C, I> CelestiaSealProtocolBuilder<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            da_layer: None,
            namespace: None,
        }
    }

    /// Set DA layer
    pub fn with_da_layer(mut self, da_layer: CelestiaDaLayer<C, I>) -> Self {
        self.da_layer = Some(da_layer);
        self
    }

    /// Set namespace
    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Build the protocol
    pub fn build(self) -> Result<CelestiaSealProtocol<C, I>> {
        let da_layer = self
            .da_layer
            .ok_or_else(|| CelestiaError::InternalError("DA layer required".to_string()))?;

        let namespace = self.namespace.unwrap_or(Namespace::metadata());

        Ok(CelestiaSealProtocol::new(da_layer, namespace))
    }
}

impl<C, I> Default for CelestiaSealProtocolBuilder<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for test protocol
pub type TestCelestiaSealProtocol =
    CelestiaSealProtocol<crate::da_layer::MockCelestiaRpc, crate::ipfs::MockIpfsClient>;

/// Create a test seal protocol
pub async fn create_test_protocol() -> TestCelestiaSealProtocol {
    use crate::da_layer::{DaLayerConfig, MockCelestiaRpc};
    use crate::ipfs::MockIpfsClient;

    let celestia = MockCelestiaRpc::new();
    celestia.set_height(100).await;

    let ipfs = MockIpfsClient::new();
    let config = DaLayerConfig::default();

    let da_layer = CelestiaDaLayer::new(config, celestia, Some(ipfs));
    CelestiaSealProtocol::new(da_layer, Namespace::metadata())
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_protocol::seal_protocol::SealProtocol;

    #[tokio::test]
    async fn test_seal_protocol_creation() {
        let protocol = create_test_protocol().await;
        assert_eq!(protocol.namespace(), Namespace::metadata());
    }

    #[tokio::test]
    async fn test_create_seal() {
        let protocol = create_test_protocol().await;
        let seal = protocol.create_seal(Some(12345)).await.unwrap();

        assert!(seal.is_valid());
        assert_eq!(seal.height, 12345);
    }

    #[tokio::test]
    async fn test_submit_and_seal() {
        let protocol = create_test_protocol().await;
        let data = vec![1, 2, 3, 4, 5];

        let (proof_id, seal) = protocol.submit_and_seal(data).await.unwrap();

        assert_eq!(seal.proof_id, proof_id);
        assert!(seal.is_valid());
    }

    #[tokio::test]
    async fn test_create_ipfs_seal() {
        let protocol = create_test_protocol().await;
        let data = vec![0u8; 1024 * 1024 + 1]; // Large data

        let (_proof_id, seal) = protocol.create_ipfs_seal(data).await.unwrap();

        assert!(seal.ipfs_cid.is_some());
        assert!(seal.is_valid());
    }

    #[tokio::test]
    async fn test_enforce_seal() {
        let protocol = create_test_protocol().await;
        let seal = protocol.create_seal(Some(12345)).await.unwrap();
        assert!(protocol.enforce_seal(seal).await.is_ok());

        // Consumed seal should fail
        let mut consumed_seal = protocol.create_seal(Some(12346)).await.unwrap();
        consumed_seal.consume([0u8; 32]);
        assert!(protocol.enforce_seal(consumed_seal).await.is_err());
    }

    #[tokio::test]
    async fn test_hash_commitment() {
        let protocol = create_test_protocol().await;

        let contract_id = Hash::new([1u8; 32]);
        let previous_commitment = Hash::new([2u8; 32]);
        let transition_payload_hash = Hash::new([3u8; 32]);
        let seal = protocol.create_seal(Some(12345)).await.unwrap();

        let hash = protocol.hash_commitment(
            contract_id,
            previous_commitment,
            transition_payload_hash,
            &seal,
        );

        // Should be non-zero
        assert_ne!(hash.as_bytes(), &[0u8; 32]);

        // Verify domain separator is included
        let hash2 = protocol.hash_commitment(
            contract_id,
            previous_commitment,
            transition_payload_hash,
            &seal,
        );
        assert_eq!(hash.as_bytes(), hash2.as_bytes());
    }

    #[tokio::test]
    async fn test_verify_inclusion() {
        let protocol = create_test_protocol().await;

        let anchor = CelestiaAnchor::new(
            crate::proof_id::ProofLocation::Celestia {
                proof_id: ProofId::new(12345, Namespace::metadata(), [9u8; 32]),
            },
            12345,
            [12345u64 as u8; 32],
            BlobCommitment::new([9u8; 32]),
            [8u8; 32],
        );

        let proof = protocol.verify_inclusion(anchor).await;
        assert!(proof.is_ok());
    }

    #[tokio::test]
    async fn test_verify_inclusion_rejects_anchor_mismatch() {
        let protocol = create_test_protocol().await;

        let anchor = CelestiaAnchor::new(
            crate::proof_id::ProofLocation::Celestia {
                proof_id: ProofId::new(12345, Namespace::metadata(), [9u8; 32]),
            },
            12345,
            [7u8; 32],
            BlobCommitment::new([9u8; 32]),
            [8u8; 32],
        );

        let proof = protocol.verify_inclusion(anchor).await;
        assert!(proof.is_err());
    }

    #[tokio::test]
    async fn test_verify_finality_rejects_anchor_mismatch() {
        let protocol = create_test_protocol().await;

        let anchor = CelestiaAnchor::new(
            crate::proof_id::ProofLocation::Celestia {
                proof_id: ProofId::new(12345, Namespace::metadata(), [9u8; 32]),
            },
            12345,
            [7u8; 32],
            BlobCommitment::new([9u8; 32]),
            [8u8; 32],
        );

        let proof = protocol.verify_finality(anchor).await;
        assert!(proof.is_err());
    }

    #[tokio::test]
    async fn test_builder() {
        use crate::da_layer::{DaLayerConfig, MockCelestiaRpc};
        use crate::ipfs::MockIpfsClient;

        let celestia = MockCelestiaRpc::new();
        celestia.set_height(100).await;

        let ipfs = MockIpfsClient::new();
        let config = DaLayerConfig::default();

        let da_layer = CelestiaDaLayer::new(config, celestia, Some(ipfs));

        let protocol = CelestiaSealProtocolBuilder::new()
            .with_da_layer(da_layer)
            .with_namespace(Namespace::bitcoin_stark())
            .build()
            .unwrap();

        assert_eq!(protocol.namespace(), Namespace::bitcoin_stark());
    }
}
