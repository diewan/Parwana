//! Hash registry - L0: Typed hash wrappers
//!
//! **Layer:** L0 (Hash types)
//! **Encoding:** MUST use canonical_cbor for protocol-critical paths
//! **Serde Policy:** MUST NOT use serde derives (enforced by deny.toml)
//!
//! This module defines the hash domains and hash types used in the CSV protocol.
//! All types in this module are L0 types and must NOT use serde for serialization.
//!
//! # Types
//!
//! - `Hash`: Core 32-byte hash value
//! - `ReplayIdHash`: Replay protection identifier
//! - `SealHash`: Seal commitment hash
//! - `SanadIdHash`: Sanad identifier hash
//! - `CommitmentHash`: Commitment identifier
//! - `NullifierHash`: Nullifier for double-spend protection
//! - `VerificationHash`: Proof verification hash
//! - `MerkleHash`: Merkle tree hash
//!
//! # Important
//!
//! The core `Hash` struct has serde derives for compatibility with L2 type serialization,
//! but all typed hash wrappers (ReplayIdHash, SealHash, etc.) MUST NOT have serde derives.
//! For protocol-critical hashing paths, use `to_canonical_bytes()` / `from_canonical_bytes()`
//! via `csv_codec::canonical` for deterministic serialization.

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// A 32-byte hash value.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()` for protocol-critical paths
/// **Serde:** Forbidden - L0 types MUST NOT use serde (enforced by deny.toml)
///
/// This is the fundamental building block for commitments, sanad IDs,
/// seal references, and all cryptographic operations in CSV.
///
/// # Security
///
/// For protocol-critical hashing (computing commitments, replay IDs, etc.),
/// use `to_canonical_bytes()` to ensure deterministic encoding. For wire format,
/// use `csv-wire` which owns all serialization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Creates a new [`struct@Hash`] from exactly 32 bytes.
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a hash of all zeros. Useful as a sentinel value.
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Returns a reference to the underlying 32-byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a mutable reference to the underlying 32-byte array.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// Returns the hash as a byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the hash and returns the inner byte array.
    #[inline]
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }

    /// Returns a new [`Vec<u8>`] containing the hash bytes.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Compute SHA-256 hash of data
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self(result.into())
    }

    /// Combines two hashes by hashing their concatenation with domain separation.
    ///
    /// Uses tagged hashing with the "csv-merkle-combine" domain to prevent
    /// cross-protocol hash collision attacks on Merkle tree nodes.
    ///
    /// This is used for Merkle tree internal node construction.
    pub fn combine(left: &Self, right: &Self) -> Self {
        use crate::tagged_hash::tagged_hash;
        let data = [&left.0[..], &right.0[..]].concat();
        Self(tagged_hash(HashDomain::MerkleCombine, &data).hash.0)
    }

    /// Returns the hash as a lowercase hex string without the `0x` prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a [`struct@Hash`] from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, HashParseError> {
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| HashParseError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HashParseError::WrongLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<&[u8; 32]> for Hash {
    #[inline]
    fn from(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = HashParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(HashParseError::WrongLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl FromStr for Hash {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", self.to_hex())
        } else {
            write!(f, "0x{}…", &self.to_hex()[..8])
        }
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

impl Default for Hash {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

/// Errors that can occur when parsing a [`struct@Hash`] from a string or byte slice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[allow(missing_docs)]
pub enum HashParseError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("expected 32 bytes, got {got}")]
    WrongLength { expected: usize, got: usize },
}

/// Exhaustive enum for domain-separated hashing (RFC-0002).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[allow(missing_docs)]
pub enum HashDomain {
    // Seal domains
    BitcoinSealV1,
    EthereumSealV1,
    SolanaSealV1,
    SuiSealV1,
    AptosSealV1,
    CelestiaSealV1,
    StarkSealV1,

    // Commitment domains
    TransferCommitmentV1,
    CommitmentVersion,
    CommitmentProtocolId,
    CommitmentMpcRoot,
    CommitmentContractId,
    CommitmentPrevious,
    CommitmentPayload,
    CommitmentSeal,
    CommitmentDomain,

    // Identity domains
    SanadId,
    Nullifier,
    ReplayIdV1,

    // Verification domains
    VerificationProofV1,
    VerificationResult,
    ProofLeafV1,

    // Stealth domains
    StealthAddressV1,
    StealthNonceV1,
    EphemeralPointV1,

    // Protocol domains
    ProtocolVersion,
    MerkleCombine,
    MerkleLeaf,

    // MPC domains
    MpcProof,
}

impl HashDomain {
    /// Returns the domain separator bytes for this domain.
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::BitcoinSealV1 => b"csv.bitcoin.seal.v1",
            Self::EthereumSealV1 => b"csv.ethereum.seal.v1",
            Self::SolanaSealV1 => b"csv.solana.seal.v1",
            Self::SuiSealV1 => b"csv.sui.seal.v1",
            Self::AptosSealV1 => b"csv.aptos.seal.v1",
            Self::CelestiaSealV1 => b"csv.celestia.seal.v1",
            Self::StarkSealV1 => b"csv.stark.seal.v1",
            Self::TransferCommitmentV1 => b"csv.transfer.commitment.v1",
            Self::CommitmentVersion => b"csv.commitment.version",
            Self::CommitmentProtocolId => b"csv.commitment.protocol_id",
            Self::CommitmentMpcRoot => b"csv.commitment.mpc_root",
            Self::CommitmentContractId => b"csv.commitment.contract_id",
            Self::CommitmentPrevious => b"csv.commitment.previous",
            Self::CommitmentPayload => b"csv.commitment.payload",
            Self::CommitmentSeal => b"csv.commitment.seal",
            Self::CommitmentDomain => b"csv.commitment.domain",
            Self::SanadId => b"csv.sanad.id",
            Self::Nullifier => b"csv.nullifier",
            Self::ReplayIdV1 => b"csv.replay.id.v1",
            Self::VerificationProofV1 => b"csv.verification.proof.v1",
            Self::VerificationResult => b"csv.verification.result",
            Self::ProofLeafV1 => b"csv.proof.leaf.v1",
            Self::StealthAddressV1 => b"csv.stealth.address.v1",
            Self::StealthNonceV1 => b"csv.stealth.nonce.v1",
            Self::EphemeralPointV1 => b"csv.stealth.ephemeral.v1",
            Self::ProtocolVersion => b"csv.protocol.version",
            Self::MerkleCombine => b"csv.merkle.combine",
            Self::MerkleLeaf => b"csv.merkle.leaf",
            Self::MpcProof => b"csv.mpc.proof",
        }
    }

    /// Returns the domain tag as a string for tagged hashing.
    pub fn tag(&self) -> &'static str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("csv.unknown.domain")
    }
}

/// Domain category for grouping related hash domains (RFC-0002).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum DomainCategory {
    Seal,
    Commitment,
    Identity,
    Verification,
    Stealth,
    Protocol,
    Mpc,
}

impl HashDomain {
    /// Returns the category for this domain.
    pub fn category(&self) -> DomainCategory {
        match self {
            Self::BitcoinSealV1
            | Self::EthereumSealV1
            | Self::SolanaSealV1
            | Self::SuiSealV1
            | Self::AptosSealV1
            | Self::CelestiaSealV1
            | Self::StarkSealV1 => DomainCategory::Seal,
            Self::TransferCommitmentV1
            | Self::CommitmentVersion
            | Self::CommitmentProtocolId
            | Self::CommitmentMpcRoot
            | Self::CommitmentContractId
            | Self::CommitmentPrevious
            | Self::CommitmentPayload
            | Self::CommitmentSeal
            | Self::CommitmentDomain => DomainCategory::Commitment,
            Self::SanadId | Self::Nullifier | Self::ReplayIdV1 => DomainCategory::Identity,
            Self::VerificationProofV1 | Self::VerificationResult | Self::ProofLeafV1 => DomainCategory::Verification,
            Self::StealthAddressV1 | Self::StealthNonceV1 | Self::EphemeralPointV1 => {
                DomainCategory::Stealth
            }
            Self::ProtocolVersion | Self::MerkleCombine | Self::MerkleLeaf => {
                DomainCategory::Protocol
            }
            Self::MpcProof => DomainCategory::Mpc,
        }
    }
}

/// Typed hash wrapper for seal hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SealHash(pub Hash);

impl SealHash {
    /// Creates a new SealHash from data using Bitcoin seal domain.
    pub fn new_bitcoin(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::BitcoinSealV1, data);
        Self(tagged.hash)
    }

    /// Creates a new SealHash from data using Ethereum seal domain.
    pub fn new_ethereum(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::EthereumSealV1, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for commitment hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CommitmentHash(pub Hash);

impl CommitmentHash {
    /// Creates a new CommitmentHash from data using transfer commitment domain.
    pub fn new_transfer(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::TransferCommitmentV1, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for Sanad ID hashes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SanadIdHash(pub Hash);

impl SanadIdHash {
    /// Creates a new SanadIdHash from data.
    pub fn new(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::SanadId, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for nullifier hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NullifierHash(pub Hash);

impl NullifierHash {
    /// Creates a new NullifierHash from data.
    pub fn new(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::Nullifier, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for replay ID hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReplayIdHash(pub Hash);

impl ReplayIdHash {
    /// Creates a new ReplayIdHash from data.
    pub fn new(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::ReplayIdV1, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for verification hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerificationHash(pub Hash);

impl VerificationHash {
    /// Creates a new VerificationHash from data.
    pub fn new(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::VerificationProofV1, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

/// Typed hash wrapper for Merkle tree hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Forbidden (enforced by deny.toml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MerkleHash(pub Hash);

impl MerkleHash {
    /// Creates a new MerkleHash from data.
    pub fn new(data: &[u8]) -> Self {
        use crate::tagged_hash::tagged_hash;
        let tagged = tagged_hash(HashDomain::MerkleCombine, data);
        Self(tagged.hash)
    }

    /// Returns the underlying hash.
    pub fn as_hash(&self) -> Hash {
        self.0
    }
}
