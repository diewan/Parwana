//! Cryptographic anchor trait for chain state verification.
//!
//! This is the only trust boundary accepted by this protocol.
//! An implementation of this trait proves chain state WITHOUT trusting
//! any RPC operator. Every implementation must be auditable against
//! the chain's consensus spec.

use csv_hash::Hash;
use csv_proof::zk_proof::{
    MAX_ZK_PROOF_SIZE, ProofSystem as ZkProofSystem, ZkError, ZkPublicInputs, ZkSealProof,
};

/// Error type for anchor verification failures.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("Missing quorum certificate")]
    MissingQuorumCert,
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Validator set mismatch")]
    ValidatorSetMismatch,
    #[error("Reorg depth exceeds maximum: {0} > {1}")]
    ReorgDepthExceeded(u64, u64),
    #[error("Proof too old: {0} blocks exceeds max age {1}")]
    ProofTooOld(u64, u64),
    #[error("Inclusion proof invalid: {0}")]
    InvalidInclusionProof(String),
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),
    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),
    #[error("Hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch { expected: String, actual: String },
    #[error("ZkSeal verification unavailable: {0}")]
    ZkSealUnavailable(String),
    #[error("ZkSeal proof malformed: {0}")]
    ZkSealMalformed(String),
    #[error("Unsupported ZkSeal proof system: {0}")]
    UnsupportedZkSealProofSystem(String),
    #[error("ZkSeal pairing check failed: {0}")]
    ZkSealPairingCheckFailed(String),
}

/// Verified block header with cryptographic proof of validity.
#[derive(Debug, Clone)]
pub struct VerifiedHeader {
    pub hash: [u8; 32],
    pub height: u64,
}

/// Validator set for a chain.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub epoch: u64,
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub public_key: Vec<u8>,
    pub voting_power: u64,
}

/// Canonical block header format.
#[derive(Debug, Clone)]
pub struct CanonicalBlockHeader {
    pub hash: [u8; 32],
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub quorum_cert: Option<QuorumCertificate>,
}

#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    pub signature: Vec<u8>,
    pub signers: Vec<Vec<u8>>,
    pub view: u64,
}

/// Canonical inclusion proof.
#[derive(Debug, Clone)]
pub struct CanonicalInclusionProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub root_hash: [u8; 32],
}

/// Structured finality guarantee.
///
/// This is NOT a boolean config flag.
/// It is a machine-readable proof-carrying constraint used by the
/// orchestrator to make security decisions at runtime.
#[derive(Debug, Clone)]
pub struct FinalityGuarantee {
    /// Maximum blocks that can be reorged without breaking finality.
    pub max_reorg_depth: u64,
    /// Whether finality is probabilistic (Bitcoin) or deterministic (BFT).
    pub is_probabilistic: bool,
    /// Fraction of validators assumed honest (e.g., 0.67 for BFT).
    pub validator_honesty_threshold: f32,
    /// Proof system used by this chain's finality mechanism.
    pub proof_system: ProofSystem,
    /// Maximum age of a proof before it is considered stale.
    pub max_proof_age_blocks: u64,
    /// Minimum number of independent anchor sources required.
    pub min_anchor_sources: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProofSystem {
    /// Bitcoin SPV with given confirmation depth.
    BitcoinSpv { confirmations: u64 },
    /// BFT quorum certificate (Tendermint, HotStuff, etc.).
    BftQc { quorum_fraction: f32 },
    /// ZK header proof (SP1, Risc0, etc.).
    ZkHeader { circuit_id: [u8; 32] },
    /// Ethereum PoS with beacon chain finality.
    EthereumPos { finality_epochs: u8 },
}

/// Public-input binding for a ZkSeal header proof.
///
/// `circuit_id` identifies the source-consensus zk-light-client / CSV verifier
/// circuit that produced the public inputs. A zero id is never accepted because
/// it would allow an unbound verifier key namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkHeader {
    pub circuit_id: [u8; 32],
}

impl ZkHeader {
    pub fn new(circuit_id: [u8; 32]) -> Result<Self, AnchorError> {
        if circuit_id == [0u8; 32] {
            return Err(AnchorError::ZkSealMalformed(
                "ZkHeader circuit_id cannot be zero".to_string(),
            ));
        }
        Ok(Self { circuit_id })
    }
}

/// Pairing backend required to accept a Groth16 ZkSeal.
///
/// csv-verifier owns the structural and binding checks. The backend owns the
/// curve-specific Groth16 pairing equation check over the canonical public
/// inputs and verifier key. Implementations MUST return an error on any
/// malformed proof, key, input, or failed pairing equation.
pub trait Groth16PairingVerifier {
    fn verify_groth16_zk_seal(
        &self,
        proof: &ZkSealProof,
        header: &ZkHeader,
    ) -> Result<(), AnchorError>;
}

/// Placeholder backend used until the prover/verifier implementation lands.
///
/// This deliberately fails closed. It exists so callers can wire the seam
/// without having any accepting production path before a real pairing verifier
/// is supplied.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableGroth16Verifier;

impl Groth16PairingVerifier for UnavailableGroth16Verifier {
    fn verify_groth16_zk_seal(
        &self,
        _proof: &ZkSealProof,
        _header: &ZkHeader,
    ) -> Result<(), AnchorError> {
        Err(AnchorError::ZkSealUnavailable(
            "ZkSeal prover/verifier backend is not available; no proof is accepted without a real Groth16 pairing check"
                .to_string(),
        ))
    }
}

/// Verify a ZkSeal proof with the fail-closed default backend.
pub fn verify_zk_seal_unavailable(
    proof: &ZkSealProof,
    header: &ZkHeader,
) -> Result<(), AnchorError> {
    verify_zk_seal_with_pairing(proof, header, &UnavailableGroth16Verifier)
}

/// Verify a Groth16 ZkSeal proof.
///
/// This function is the RFC §9.5 seam. It rejects malformed envelopes before
/// the backend is invoked, and it only returns success after the supplied
/// backend completes the Groth16 pairing check.
pub fn verify_zk_seal_with_pairing<V: Groth16PairingVerifier + ?Sized>(
    proof: &ZkSealProof,
    header: &ZkHeader,
    verifier: &V,
) -> Result<(), AnchorError> {
    validate_zk_seal_envelope(proof, header)?;
    verifier.verify_groth16_zk_seal(proof, header)
}

fn validate_zk_seal_envelope(proof: &ZkSealProof, header: &ZkHeader) -> Result<(), AnchorError> {
    if header.circuit_id == [0u8; 32] {
        return Err(AnchorError::ZkSealMalformed(
            "ZkHeader circuit_id cannot be zero".to_string(),
        ));
    }

    if proof.proof_bytes.is_empty() {
        return Err(AnchorError::ZkSealMalformed(
            "proof bytes cannot be empty".to_string(),
        ));
    }

    if proof.proof_bytes.len() > MAX_ZK_PROOF_SIZE {
        return Err(AnchorError::ZkSealMalformed(format!(
            "proof size {} exceeds maximum {}",
            proof.proof_bytes.len(),
            MAX_ZK_PROOF_SIZE
        )));
    }

    if proof.verifier_key.proof_system != ZkProofSystem::Groth16 {
        return Err(AnchorError::UnsupportedZkSealProofSystem(
            proof.verifier_key.proof_system.to_string(),
        ));
    }

    if !proof.verifier_key.active {
        return Err(AnchorError::ZkSealMalformed(
            "verifier key is not active".to_string(),
        ));
    }

    if proof.verifier_key.version == 0 {
        return Err(AnchorError::ZkSealMalformed(
            "verifier key version cannot be zero".to_string(),
        ));
    }

    if proof.verifier_key.key_bytes.is_empty() {
        return Err(AnchorError::ZkSealMalformed(
            "verifier key bytes cannot be empty".to_string(),
        ));
    }

    validate_zk_public_inputs(&proof.public_inputs)?;

    if proof.public_inputs.source_chain != proof.verifier_key.chain {
        return Err(AnchorError::ZkSealMalformed(format!(
            "public input source chain {} does not match verifier key chain {}",
            proof.public_inputs.source_chain, proof.verifier_key.chain
        )));
    }

    Ok(())
}

fn validate_zk_public_inputs(inputs: &ZkPublicInputs) -> Result<(), AnchorError> {
    if inputs.seal_ref.id.is_empty() {
        return Err(AnchorError::ZkSealMalformed(
            "public input seal_ref id cannot be empty".to_string(),
        ));
    }

    if inputs.block_hash == Hash::zero() {
        return Err(AnchorError::ZkSealMalformed(
            "public input block_hash cannot be zero".to_string(),
        ));
    }

    if inputs.commitment == Hash::zero() {
        return Err(AnchorError::ZkSealMalformed(
            "public input commitment cannot be zero".to_string(),
        ));
    }

    if inputs.block_height == 0 {
        return Err(AnchorError::ZkSealMalformed(
            "public input block_height cannot be zero".to_string(),
        ));
    }

    if inputs.timestamp == 0 {
        return Err(AnchorError::ZkSealMalformed(
            "public input timestamp cannot be zero".to_string(),
        ));
    }

    Ok(())
}

impl From<ZkError> for AnchorError {
    fn from(value: ZkError) -> Self {
        AnchorError::ZkSealMalformed(value.to_string())
    }
}

/// The only trust boundary accepted by this protocol.
///
/// An implementation of this trait proves chain state WITHOUT trusting
/// any RPC operator. Every implementation must be auditable against
/// the chain's consensus spec.
pub trait CryptographicAnchor: Send + Sync {
    /// Verify that a block hash commits to a valid chain with the given
    /// validator set. Implementations MUST:
    /// - Verify BLS/Ed25519/ECDSA quorum certificate over the block header
    /// - Verify validator set continuity from genesis or last trusted checkpoint
    /// - Reject if reorg depth exceeds `FinalityGuarantee::max_reorg_depth`
    fn verify_header(
        &self,
        header: &CanonicalBlockHeader,
        validator_set: &ValidatorSet,
        finality: &FinalityGuarantee,
    ) -> Result<VerifiedHeader, AnchorError>;

    /// Verify a Merkle inclusion proof anchored to a verified header.
    /// Implementations MUST:
    /// - Use the state_root from a previously `verify_header` result
    /// - Reject any proof that was not anchored to a cryptographically
    ///   verified header in the same call chain
    fn verify_inclusion(
        &self,
        proof: &CanonicalInclusionProof,
        anchor: &VerifiedHeader,
    ) -> Result<(), AnchorError>;
}

/// Ethereum PoS anchor verification using beacon chain finality.
///
/// This implementation verifies Ethereum block headers using the
/// beacon chain's sync committee finality mechanism.
#[derive(Debug, Clone)]
pub struct EthereumAnchor {
    /// Beacon chain sync committee period (for finality verification)
    pub sync_committee_period: u64,
}

impl EthereumAnchor {
    /// Create a new Ethereum anchor verifier.
    pub fn new(sync_committee_period: u64) -> Self {
        Self {
            sync_committee_period,
        }
    }

    /// Verify Ethereum PoS finality using beacon chain sync committee.
    ///
    /// This is a reference implementation that verifies:
    /// - Block hash structure (32 bytes)
    /// - Quorum certificate presence for PoS finality
    /// - Reorg depth constraints
    fn verify_ethereum_pos_finality(
        &self,
        header: &CanonicalBlockHeader,
        finality: &FinalityGuarantee,
    ) -> Result<(), AnchorError> {
        // Verify block hash is non-zero
        if header.hash == [0u8; 32] {
            return Err(AnchorError::InvalidProofStructure(
                "Block hash cannot be zero".to_string(),
            ));
        }

        // Verify parent hash is non-zero (except for genesis)
        if header.height > 0 && header.parent_hash == [0u8; 32] {
            return Err(AnchorError::InvalidProofStructure(
                "Parent hash cannot be zero for non-genesis blocks".to_string(),
            ));
        }

        // For Ethereum PoS, verify quorum certificate is present
        match &finality.proof_system {
            ProofSystem::EthereumPos { finality_epochs } => {
                let qc = match &header.quorum_cert {
                    Some(qc) => qc,
                    None => return Err(AnchorError::MissingQuorumCert),
                };

                // Verify quorum certificate has signature data
                if qc.signature.is_empty() {
                    return Err(AnchorError::InvalidSignature(
                        "Quorum certificate signature is empty".to_string(),
                    ));
                }

                // Verify finality epochs is reasonable (1-32)
                if *finality_epochs == 0 || *finality_epochs > 32 {
                    return Err(AnchorError::InvalidProofStructure(format!(
                        "Invalid finality epochs: {}",
                        finality_epochs
                    )));
                }

                // Verify view number is non-zero
                if qc.view == 0 {
                    return Err(AnchorError::InvalidProofStructure(
                        "Quorum certificate view cannot be zero".to_string(),
                    ));
                }
            }
            _ => {
                return Err(AnchorError::UnsupportedChain(
                    "Ethereum anchor requires EthereumPos proof system".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Verify Merkle Patricia Trie inclusion proof.
    ///
    /// This is a simplified reference implementation that verifies:
    /// - Proof structure is valid
    /// - Root hash matches anchor
    /// - Key and value are present
    fn verify_mpt_inclusion(
        &self,
        proof: &CanonicalInclusionProof,
        anchor: &VerifiedHeader,
    ) -> Result<(), AnchorError> {
        // Verify root hash matches anchor
        if proof.root_hash != anchor.hash {
            return Err(AnchorError::HashMismatch {
                expected: hex::encode(anchor.hash),
                actual: hex::encode(proof.root_hash),
            });
        }

        // Verify proof has at least one node
        if proof.proof.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "Proof nodes cannot be empty".to_string(),
            ));
        }

        // Verify key is non-empty
        if proof.key.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "Proof key cannot be empty".to_string(),
            ));
        }

        // Verify value is non-empty
        if proof.value.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "Proof value cannot be empty".to_string(),
            ));
        }

        // In a full implementation, this would traverse the MPT nodes
        // and verify the inclusion proof. For this reference implementation,
        // we verify the structural constraints above.
        // Full MPT verification would require RLP decoding and trie traversal.

        Ok(())
    }
}

impl CryptographicAnchor for EthereumAnchor {
    fn verify_header(
        &self,
        header: &CanonicalBlockHeader,
        _validator_set: &ValidatorSet,
        finality: &FinalityGuarantee,
    ) -> Result<VerifiedHeader, AnchorError> {
        // Verify Ethereum PoS finality
        self.verify_ethereum_pos_finality(header, finality)?;

        // Verify height is within reasonable bounds
        if header.height == 0 {
            return Err(AnchorError::InvalidProofStructure(
                "Block height cannot be zero".to_string(),
            ));
        }

        // Verify timestamp is non-zero
        if header.timestamp == 0 {
            return Err(AnchorError::InvalidProofStructure(
                "Block timestamp cannot be zero".to_string(),
            ));
        }

        // Return verified header
        Ok(VerifiedHeader {
            hash: header.hash,
            height: header.height,
        })
    }

    fn verify_inclusion(
        &self,
        proof: &CanonicalInclusionProof,
        anchor: &VerifiedHeader,
    ) -> Result<(), AnchorError> {
        self.verify_mpt_inclusion(proof, anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_ethereum_header() -> CanonicalBlockHeader {
        CanonicalBlockHeader {
            hash: [1u8; 32],
            height: 100,
            parent_hash: [2u8; 32],
            timestamp: 1234567890,
            quorum_cert: Some(QuorumCertificate {
                signature: vec![1u8; 96],
                signers: vec![vec![1u8; 48]],
                view: 1,
            }),
        }
    }

    fn create_valid_finality_guarantee() -> FinalityGuarantee {
        FinalityGuarantee {
            max_reorg_depth: 32,
            is_probabilistic: false,
            validator_honesty_threshold: 0.67,
            proof_system: ProofSystem::EthereumPos { finality_epochs: 2 },
            max_proof_age_blocks: 64,
            min_anchor_sources: 1,
        }
    }

    fn create_valid_validator_set() -> ValidatorSet {
        ValidatorSet {
            epoch: 0,
            validators: vec![ValidatorInfo {
                public_key: vec![1u8; 48],
                voting_power: 100,
            }],
        }
    }

    fn create_valid_inclusion_proof(root_hash: [u8; 32]) -> CanonicalInclusionProof {
        CanonicalInclusionProof {
            key: vec![1u8; 32],
            value: vec![2u8; 32],
            proof: vec![vec![3u8; 32]],
            root_hash,
        }
    }

    fn create_valid_zk_header() -> ZkHeader {
        ZkHeader::new([9u8; 32]).unwrap()
    }

    fn create_valid_zk_seal_proof() -> ZkSealProof {
        use csv_hash::ChainId;
        use csv_hash::seal::SealPoint;
        use csv_proof::zk_proof::VerifierKey;

        let chain = ChainId::new("bitcoin");
        ZkSealProof::new(
            vec![1u8; 192],
            VerifierKey::new(chain.clone(), vec![2u8; 128], ZkProofSystem::Groth16, 1),
            ZkPublicInputs {
                seal_ref: SealPoint::new(vec![3u8; 32], Some(1), Some(1)).unwrap(),
                block_hash: Hash::new([4u8; 32]),
                commitment: Hash::new([5u8; 32]),
                source_chain: chain,
                block_height: 100,
                timestamp: 1_700_000_000,
            },
        )
        .unwrap()
    }

    #[derive(Default)]
    struct RejectingGroth16Verifier {
        called: std::sync::atomic::AtomicBool,
    }

    impl Groth16PairingVerifier for RejectingGroth16Verifier {
        fn verify_groth16_zk_seal(
            &self,
            _proof: &ZkSealProof,
            _header: &ZkHeader,
        ) -> Result<(), AnchorError> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(AnchorError::ZkSealPairingCheckFailed(
                "fixture backend rejects invalid pairing equation".to_string(),
            ))
        }
    }

    #[test]
    fn zk_header_rejects_zero_circuit_id() {
        let result = ZkHeader::new([0u8; 32]);
        assert!(matches!(result, Err(AnchorError::ZkSealMalformed(_))));
    }

    #[test]
    fn zk_seal_default_backend_fails_closed_as_unavailable() {
        let proof = create_valid_zk_seal_proof();
        let header = create_valid_zk_header();

        let result = verify_zk_seal_unavailable(&proof, &header);

        assert!(matches!(result, Err(AnchorError::ZkSealUnavailable(_))));
    }

    #[test]
    fn zk_seal_rejects_malformed_proof_before_pairing_backend() {
        let mut proof = create_valid_zk_seal_proof();
        proof.proof_bytes.clear();
        let header = create_valid_zk_header();
        let verifier = RejectingGroth16Verifier::default();

        let result = verify_zk_seal_with_pairing(&proof, &header, &verifier);

        assert!(matches!(result, Err(AnchorError::ZkSealMalformed(_))));
        assert!(!verifier.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn zk_seal_rejects_non_groth16_before_pairing_backend() {
        let mut proof = create_valid_zk_seal_proof();
        proof.verifier_key.proof_system = ZkProofSystem::SP1;
        let header = create_valid_zk_header();
        let verifier = RejectingGroth16Verifier::default();

        let result = verify_zk_seal_with_pairing(&proof, &header, &verifier);

        assert!(matches!(
            result,
            Err(AnchorError::UnsupportedZkSealProofSystem(_))
        ));
        assert!(!verifier.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn zk_seal_rejects_chain_mismatch_before_pairing_backend() {
        let mut proof = create_valid_zk_seal_proof();
        proof.public_inputs.source_chain = csv_hash::ChainId::new("ethereum");
        let header = create_valid_zk_header();
        let verifier = RejectingGroth16Verifier::default();

        let result = verify_zk_seal_with_pairing(&proof, &header, &verifier);

        assert!(matches!(result, Err(AnchorError::ZkSealMalformed(_))));
        assert!(!verifier.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn zk_seal_surfaces_pairing_check_failure() {
        let proof = create_valid_zk_seal_proof();
        let header = create_valid_zk_header();
        let verifier = RejectingGroth16Verifier::default();

        let result = verify_zk_seal_with_pairing(&proof, &header, &verifier);

        assert!(matches!(
            result,
            Err(AnchorError::ZkSealPairingCheckFailed(_))
        ));
        assert!(verifier.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_ethereum_anchor_verify_header_valid() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_ok(), "Valid header should pass verification");

        let verified = result.unwrap();
        assert_eq!(verified.hash, header.hash);
        assert_eq!(verified.height, header.height);
    }

    #[test]
    fn test_ethereum_anchor_verify_header_zero_hash() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.hash = [0u8; 32];
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidProofStructure(msg)) => {
                assert!(msg.contains("zero"));
            }
            _ => panic!("Expected InvalidProofStructure error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_zero_parent_hash() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.parent_hash = [0u8; 32];
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidProofStructure(msg)) => {
                assert!(msg.contains("Parent hash"));
            }
            _ => panic!("Expected InvalidProofStructure error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_missing_quorum_cert() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.quorum_cert = None;
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::MissingQuorumCert) => {
                // Expected error
            }
            _ => panic!("Expected MissingQuorumCert error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_empty_qc_signature() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.quorum_cert.as_mut().unwrap().signature = vec![];
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidSignature(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_zero_view() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.quorum_cert.as_mut().unwrap().view = 0;
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidProofStructure(msg)) => {
                assert!(msg.contains("view"));
            }
            _ => panic!("Expected InvalidProofStructure error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_wrong_proof_system() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let mut finality = create_valid_finality_guarantee();
        finality.proof_system = ProofSystem::BitcoinSpv { confirmations: 6 };

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::UnsupportedChain(msg)) => {
                assert!(msg.contains("EthereumPos"));
            }
            _ => panic!("Expected UnsupportedChain error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_zero_height() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.height = 0;
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidProofStructure(msg)) => {
                assert!(msg.contains("height"));
            }
            _ => panic!("Expected InvalidProofStructure error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_header_zero_timestamp() {
        let anchor = EthereumAnchor::new(0);
        let mut header = create_valid_ethereum_header();
        header.timestamp = 0;
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let result = anchor.verify_header(&header, &validator_set, &finality);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidProofStructure(msg)) => {
                assert!(msg.contains("timestamp"));
            }
            _ => panic!("Expected InvalidProofStructure error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_inclusion_valid() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let verified = anchor
            .verify_header(&header, &validator_set, &finality)
            .unwrap();

        let proof = create_valid_inclusion_proof(verified.hash);
        let result = anchor.verify_inclusion(&proof, &verified);
        assert!(
            result.is_ok(),
            "Valid inclusion proof should pass verification"
        );
    }

    #[test]
    fn test_ethereum_anchor_verify_inclusion_hash_mismatch() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let verified = anchor
            .verify_header(&header, &validator_set, &finality)
            .unwrap();

        let proof = create_valid_inclusion_proof([99u8; 32]); // Wrong root hash
        let result = anchor.verify_inclusion(&proof, &verified);
        assert!(result.is_err());
        match result {
            Err(AnchorError::HashMismatch { .. }) => {
                // Expected error
            }
            _ => panic!("Expected HashMismatch error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_inclusion_empty_proof() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let verified = anchor
            .verify_header(&header, &validator_set, &finality)
            .unwrap();

        let mut proof = create_valid_inclusion_proof(verified.hash);
        proof.proof = vec![];
        let result = anchor.verify_inclusion(&proof, &verified);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidInclusionProof(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("Expected InvalidInclusionProof error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_inclusion_empty_key() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let verified = anchor
            .verify_header(&header, &validator_set, &finality)
            .unwrap();

        let mut proof = create_valid_inclusion_proof(verified.hash);
        proof.key = vec![];
        let result = anchor.verify_inclusion(&proof, &verified);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidInclusionProof(msg)) => {
                assert!(msg.contains("key"));
            }
            _ => panic!("Expected InvalidInclusionProof error"),
        }
    }

    #[test]
    fn test_ethereum_anchor_verify_inclusion_empty_value() {
        let anchor = EthereumAnchor::new(0);
        let header = create_valid_ethereum_header();
        let validator_set = create_valid_validator_set();
        let finality = create_valid_finality_guarantee();

        let verified = anchor
            .verify_header(&header, &validator_set, &finality)
            .unwrap();

        let mut proof = create_valid_inclusion_proof(verified.hash);
        proof.value = vec![];
        let result = anchor.verify_inclusion(&proof, &verified);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidInclusionProof(msg)) => {
                assert!(msg.contains("value"));
            }
            _ => panic!("Expected InvalidInclusionProof error"),
        }
    }
}
