//! Sanad identifier types
//!
//! SanadId derivation uses domain-separated tagged hashing:
//! ```text
//! SanadId = tagged_hash("urn:lnp-bp:csv:csv.sanad.id.v1", descriptor_hash || commitment || salt)
//! ```
//!
//! This ensures:
//! - Salt affects the ID (prevents collision when same commitment used with different salts)
//! - Descriptor hash binds content metadata to the ID
//! - Domain separation prevents cross-protocol replay

use crate::{Hash, tagged_hash_str};

/// Preimage for Sanad ID derivation.
///
/// This struct contains all the inputs that go into the Sanad ID hash.
/// Using a preimage ensures type safety and makes the derivation explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SanadIdPreimage {
    /// Descriptor hash (32-byte hash of the SanadPayloadDescriptor)
    pub descriptor_hash: [u8; 32],
    /// Commitment hash (32-byte commitment hash)
    pub commitment: [u8; 32],
    /// Salt bytes for uniqueness
    pub salt: Vec<u8>,
}

impl SanadIdPreimage {
    /// Create a new SanadIdPreimage.
    pub fn new(descriptor_hash: [u8; 32], commitment: [u8; 32], salt: Vec<u8>) -> Self {
        Self {
            descriptor_hash,
            commitment,
            salt,
        }
    }

    /// Convert to canonical bytes for hashing.
    ///
    /// The canonical format is: descriptor_hash || commitment || salt
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.salt.len());
        bytes.extend_from_slice(&self.descriptor_hash);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.salt);
        bytes
    }
}

/// Domain tag for Sanad ID derivation.
pub const DOMAIN_SANAD_ID_V1: &str = "urn:lnp-bp:csv:csv.sanad.id.v1";

/// A unique Sanad identifier.
///
/// Derived via domain-separated tagged hashing:
/// ```text
/// SanadId = tagged_hash("csv.sanad.id.v1", descriptor_hash || commitment_bytes || salt)
/// ```
///
/// The domain tag `csv.sanad.id.v1` ensures Sanad IDs are cryptographically
/// separated from all other protocol hashes (commitments, nullifiers, proof leaves).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SanadId(pub Hash);

impl SanadId {
    /// Creates a new SanadId from a 32-byte hash.
    #[inline]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Creates a new SanadId from a byte slice.
    ///
    /// Exact 32-byte inputs are used directly. Other lengths are hashed into a
    /// canonical 32-byte identifier.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 32 {
            return Self(Hash::sha256(bytes));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Self::new(array)
    }

    /// Derives a SanadId from a SanadIdPreimage using domain-separated tagged hashing.
    ///
    /// This is the canonical method for Sanad ID derivation and should be used
    /// in all production code to ensure consistency across the protocol.
    ///
    /// ## Arguments
    ///
    /// * `preimage` — The SanadIdPreimage containing descriptor_hash, commitment, and salt
    ///
    /// ## Security
    ///
    /// The domain tag `csv.sanad.id.v1` ensures this hash is cryptographically
    /// separated from all other protocol hashes. The descriptor_hash binds content
    /// metadata to the Sanad identity. The salt ensures uniqueness even when the
    /// same commitment is used multiple times.
    #[inline]
    pub fn from_domain_canonical(preimage: &SanadIdPreimage) -> Self {
        let bytes = preimage.to_canonical_bytes();
        let hash_bytes = tagged_hash_str(DOMAIN_SANAD_ID_V1, &bytes);
        Self(Hash::new(hash_bytes))
    }

    /// Derives a SanadId from a descriptor hash, commitment, and salt.
    ///
    /// Uses domain-separated tagged hashing:
    /// ```text
    /// SanadId = tagged_hash("urn:lnp-bp:csv:csv.sanad.id.v1", descriptor_hash || commitment || salt)
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `descriptor_hash` — 32-byte hash of the SanadPayloadDescriptor (canonical CBOR)
    /// * `commitment` — 32-byte commitment hash
    /// * `salt` — Salt bytes that affect the ID derivation
    ///
    /// ## Security
    ///
    /// The domain tag `csv.sanad.id.v1` ensures this hash is cryptographically
    /// separated from all other protocol hashes. The descriptor_hash binds content
    /// metadata to the Sanad identity. The salt ensures uniqueness even when the
    /// same commitment is used multiple times.
    ///
    /// ## Note
    ///
    /// This method is a convenience wrapper. For new code, prefer using
    /// `from_domain_canonical` with a `SanadIdPreimage` for better type safety.
    #[inline]
    pub fn from_descriptor_commitment_salt(
        descriptor_hash: &[u8; 32],
        commitment: &[u8; 32],
        salt: &[u8],
    ) -> Self {
        let preimage = SanadIdPreimage::new(*descriptor_hash, *commitment, salt.to_vec());
        Self::from_domain_canonical(&preimage)
    }

    /// Derives a SanadId from a descriptor hash, commitment, and salt.
    ///
    /// Convenience wrapper that accepts descriptor_hash as `Hash`.
    pub fn from_descriptor_commitment(
        descriptor_hash: Hash,
        commitment: Hash,
        salt: &[u8],
    ) -> Self {
        Self::from_descriptor_commitment_salt(
            descriptor_hash.as_bytes(),
            commitment.as_bytes(),
            salt,
        )
    }

    /// Returns the underlying hash bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanad_id_creation() {
        let hash = Hash::new([1u8; 32]);
        let sanad_id = SanadId(hash);
        assert_eq!(sanad_id.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_sanad_id_from_bytes() {
        let bytes = [2u8; 32];
        let sanad_id = SanadId::from_bytes(&bytes);
        assert_eq!(sanad_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_sanad_id_new() {
        let bytes = [3u8; 32];
        let sanad_id = SanadId::new(bytes);
        assert_eq!(sanad_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_sanad_id_preimage_canonical_bytes() {
        let preimage = SanadIdPreimage::new(
            [1u8; 32],
            [2u8; 32],
            vec![3u8; 16],
        );
        let bytes = preimage.to_canonical_bytes();
        assert_eq!(bytes.len(), 64 + 16);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(&bytes[64..80], &[3u8; 16]);
    }

    #[test]
    fn test_sanad_id_from_domain_canonical() {
        let preimage = SanadIdPreimage::new(
            [1u8; 32],
            [2u8; 32],
            vec![3u8; 16],
        );
        let id = SanadId::from_domain_canonical(&preimage);
        // Verify the ID is non-zero
        assert_ne!(id.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_golden_vector_salt_affects_id() {
        // Golden vector: same descriptor_hash and commitment, different salts must produce different IDs
        let descriptor_hash = [1u8; 32];
        let commitment = [2u8; 32];
        let salt1 = vec![3u8; 16];
        let salt2 = vec![4u8; 16];

        let preimage1 = SanadIdPreimage::new(descriptor_hash, commitment, salt1.clone());
        let preimage2 = SanadIdPreimage::new(descriptor_hash, commitment, salt2.clone());

        let id1 = SanadId::from_domain_canonical(&preimage1);
        let id2 = SanadId::from_domain_canonical(&preimage2);

        // Different salts MUST produce different IDs
        assert_ne!(id1, id2, "Salt must affect Sanad ID derivation");
    }

    #[test]
    fn test_golden_vector_descriptor_affects_id() {
        // Golden vector: same commitment and salt, different descriptor_hash must produce different IDs
        let descriptor_hash1 = [1u8; 32];
        let descriptor_hash2 = [5u8; 32];
        let commitment = [2u8; 32];
        let salt = vec![3u8; 16];

        let preimage1 = SanadIdPreimage::new(descriptor_hash1, commitment, salt.clone());
        let preimage2 = SanadIdPreimage::new(descriptor_hash2, commitment, salt);

        let id1 = SanadId::from_domain_canonical(&preimage1);
        let id2 = SanadId::from_domain_canonical(&preimage2);

        // Different descriptor_hash MUST produce different IDs
        assert_ne!(id1, id2, "Descriptor hash must affect Sanad ID derivation");
    }

    #[test]
    fn test_golden_vector_commitment_affects_id() {
        // Golden vector: same descriptor_hash and salt, different commitment must produce different IDs
        let descriptor_hash = [1u8; 32];
        let commitment1 = [2u8; 32];
        let commitment2 = [6u8; 32];
        let salt = vec![3u8; 16];

        let preimage1 = SanadIdPreimage::new(descriptor_hash, commitment1, salt.clone());
        let preimage2 = SanadIdPreimage::new(descriptor_hash, commitment2, salt);

        let id1 = SanadId::from_domain_canonical(&preimage1);
        let id2 = SanadId::from_domain_canonical(&preimage2);

        // Different commitment MUST produce different IDs
        assert_ne!(id1, id2, "Commitment must affect Sanad ID derivation");
    }

    #[test]
    fn test_golden_vector_same_inputs_same_id() {
        // Golden vector: identical inputs must produce identical IDs
        let descriptor_hash = [1u8; 32];
        let commitment = [2u8; 32];
        let salt = vec![3u8; 16];

        let preimage1 = SanadIdPreimage::new(descriptor_hash, commitment, salt.clone());
        let preimage2 = SanadIdPreimage::new(descriptor_hash, commitment, salt);

        let id1 = SanadId::from_domain_canonical(&preimage1);
        let id2 = SanadId::from_domain_canonical(&preimage2);

        // Identical inputs MUST produce identical IDs
        assert_eq!(id1, id2, "Identical inputs must produce identical Sanad IDs");
    }

    #[test]
    fn test_from_descriptor_commitment_salt_uses_preimage() {
        // Verify that from_descriptor_commitment_salt uses the preimage internally
        let descriptor_hash = [1u8; 32];
        let commitment = [2u8; 32];
        let salt = vec![3u8; 16];

        let id1 = SanadId::from_descriptor_commitment_salt(&descriptor_hash, &commitment, &salt);
        let preimage = SanadIdPreimage::new(descriptor_hash, commitment, salt);
        let id2 = SanadId::from_domain_canonical(&preimage);

        // Both methods must produce the same ID
        assert_eq!(id1, id2, "from_descriptor_commitment_salt must use from_domain_canonical");
    }
}
