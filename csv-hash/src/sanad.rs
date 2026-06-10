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

use crate::{Hash, csv_tagged_hash, tagged_hash_str};

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
    #[inline]
    pub fn from_descriptor_commitment_salt(
        descriptor_hash: &[u8; 32],
        commitment: &[u8; 32],
        salt: &[u8],
    ) -> Self {
        let mut combined = Vec::with_capacity(64 + salt.len());
        combined.extend_from_slice(descriptor_hash);
        combined.extend_from_slice(commitment);
        combined.extend_from_slice(salt);
        let hash_bytes = tagged_hash_str("urn:lnp-bp:csv:csv.sanad.id.v1", &combined);
        Self(Hash::new(hash_bytes))
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
}
