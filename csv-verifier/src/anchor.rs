/// Cryptographic anchor trait for chain state verification.
/// 
/// This is the only trust boundary accepted by this protocol.
/// An implementation of this trait proves chain state WITHOUT trusting
/// any RPC operator. Every implementation must be auditable against
/// the chain's consensus spec.


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
    #[error("Anchor verification not implemented for this chain")]
    NotImplemented,
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
