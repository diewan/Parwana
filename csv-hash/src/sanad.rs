//! Sanad identifier types
//!
//! SanadId derivation uses domain-separated tagged hashing:
//! ```text
//! SanadId = tagged_hash("urn:lnp-bp:csv:csv.sanad.id.v1", descriptor_hash || commitment || salt)
//! ```
//!
//! This ensures:
//! - Salt affects the ID (prevents collision when same commitment used with different salts)
/// - Descriptor hash binds content metadata to the ID
/// - Domain separation prevents cross-protocol replay
use crate::{Hash, tagged_hash_str};

/// Preimage for Sanad ID derivation.
///
/// This struct contains all the inputs that go into the Sanad ID hash.
/// Using a preimage ensures type safety and makes the derivation explicit.
///
/// **Layer:** L0
/// **Serde:** Forbidden - L0 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
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
///
/// **Layer:** L0
/// **Serde:** Forbidden - L0 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Parse a Sanad ID from a hex string.
    ///
    /// Accepts both `0x`-prefixed and non-prefixed hex strings.
    /// The input must represent exactly 32 bytes (64 hex characters, or 66 with `0x` prefix).
    ///
    /// # Arguments
    ///
    /// * `input` - Hex string representing the Sanad ID (with or without `0x` prefix)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is not valid hexadecimal
    /// - The decoded length is not exactly 32 bytes
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use csv_hash::sanad::SanadId;
    ///
    /// // Parse without 0x prefix
    /// let id1 = SanadId::parse_hex("abc123...")?;
    ///
    /// // Parse with 0x prefix
    /// let id2 = SanadId::parse_hex("0xabc123...")?;
    ///
    /// // Both produce the same SanadId
    /// assert_eq!(id1, id2);
    /// ```
    pub fn parse_hex(input: &str) -> Result<Self, ParseSanadIdError> {
        let trimmed = input.trim();
        let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);

        if hex_str.len() != 64 {
            return Err(ParseSanadIdError::InvalidLength {
                expected: 64,
                actual: hex_str.len(),
            });
        }

        let bytes = hex::decode(hex_str).map_err(|e| ParseSanadIdError::InvalidHex {
            message: e.to_string(),
        })?;

        if bytes.len() != 32 {
            return Err(ParseSanadIdError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self::new(array))
    }
}

/// Error type for parsing Sanad IDs from hex strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseSanadIdError {
    /// Input is not valid hexadecimal
    ///
    /// Contains the error message from the hex decoder
    InvalidHex {
        /// Error message describing why the hex is invalid
        message: String,
    },
    /// Decoded length does not match expected length
    ///
    /// Sanad IDs must be exactly 32 bytes (64 hex characters)
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },
}

impl std::fmt::Display for ParseSanadIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseSanadIdError::InvalidHex { message } => {
                write!(f, "Invalid hex input: {}", message)
            }
            ParseSanadIdError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for ParseSanadIdError {}

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
        let preimage = SanadIdPreimage::new([1u8; 32], [2u8; 32], vec![3u8; 16]);
        let bytes = preimage.to_canonical_bytes();
        assert_eq!(bytes.len(), 64 + 16);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(&bytes[64..80], &[3u8; 16]);
    }

    #[test]
    fn test_sanad_id_from_domain_canonical() {
        let preimage = SanadIdPreimage::new([1u8; 32], [2u8; 32], vec![3u8; 16]);
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
        assert_eq!(
            id1, id2,
            "Identical inputs must produce identical Sanad IDs"
        );
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
        assert_eq!(
            id1, id2,
            "from_descriptor_commitment_salt must use from_domain_canonical"
        );
    }

    #[test]
    fn test_parse_hex_valid_without_prefix() {
        // Test parsing valid hex without 0x prefix
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let sanad_id = SanadId::parse_hex(hex_str).unwrap();
        assert_eq!(sanad_id.as_bytes()[0], 0x01);
        assert_eq!(sanad_id.as_bytes()[31], 0x20);
    }

    #[test]
    fn test_parse_hex_valid_with_prefix() {
        // Test parsing valid hex with 0x prefix
        let hex_str = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let sanad_id = SanadId::parse_hex(hex_str).unwrap();
        assert_eq!(sanad_id.as_bytes()[0], 0x01);
        assert_eq!(sanad_id.as_bytes()[31], 0x20);
    }

    #[test]
    fn test_parse_hex_consistency() {
        // Test that 0x and non-0x forms produce the same SanadId
        let hex_without = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let hex_with = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

        let id1 = SanadId::parse_hex(hex_without).unwrap();
        let id2 = SanadId::parse_hex(hex_with).unwrap();

        assert_eq!(id1, id2, "0x prefix must not affect parsing");
    }

    #[test]
    fn test_parse_hex_invalid_length_too_short() {
        // Test that too-short hex strings fail
        let hex_str = "01020304";
        let result = SanadId::parse_hex(hex_str);
        assert!(result.is_err());
        match result {
            Err(ParseSanadIdError::InvalidLength { expected, actual }) => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 8);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_parse_hex_invalid_length_too_long() {
        // Test that too-long hex strings fail
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122";
        let result = SanadId::parse_hex(hex_str);
        assert!(result.is_err());
        match result {
            Err(ParseSanadIdError::InvalidLength { expected, actual }) => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 68);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_parse_hex_invalid_hex_characters() {
        // Test that non-hex characters fail
        let hex_str = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let result = SanadId::parse_hex(hex_str);
        assert!(result.is_err());
        match result {
            Err(ParseSanadIdError::InvalidHex { .. }) => {}
            _ => panic!("Expected InvalidHex error"),
        }
    }

    #[test]
    fn test_parse_hex_whitespace_handling() {
        // Test that leading/trailing whitespace is trimmed
        let hex_str = "  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20  ";
        let sanad_id = SanadId::parse_hex(hex_str).unwrap();
        assert_eq!(sanad_id.as_bytes()[0], 0x01);
        assert_eq!(sanad_id.as_bytes()[31], 0x20);
    }

    #[test]
    fn test_parse_hex_ascii_re_encoding_regression() {
        // Regression test: ensure we don't double-encode ASCII bytes
        // This test verifies that if someone mistakenly hex-encodes the hex string,
        // it will fail with a length error rather than producing a wrong ID
        let valid_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let id1 = SanadId::parse_hex(valid_hex).unwrap();

        // If someone does hex::encode(sanad_id.as_bytes()) and then tries to parse that,
        // they get a 64-char hex string (32 bytes encoded as hex = 64 hex chars)
        // This should actually succeed since it's the same as the original hex string
        let double_encoded = hex::encode(id1.as_bytes());
        assert_eq!(double_encoded.len(), 64);
        let id2 = SanadId::parse_hex(&double_encoded).unwrap();
        assert_eq!(
            id1, id2,
            "hex::encode(sanad_id.as_bytes()) should produce parseable hex"
        );

        // The real regression test: if someone treats the hex string as ASCII and hex-encodes THAT,
        // they would get 128 chars (64 ASCII chars encoded as hex = 128 hex chars)
        // This should fail with InvalidLength
        let ascii_bytes = valid_hex.as_bytes();
        let ascii_hex_encoded = hex::encode(ascii_bytes);
        assert_eq!(ascii_hex_encoded.len(), 128);
        let result = SanadId::parse_hex(&ascii_hex_encoded);
        assert!(result.is_err());
        match result {
            Err(ParseSanadIdError::InvalidLength { expected, actual }) => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 128);
            }
            _ => panic!("Expected InvalidLength error for ASCII hex-encoded input"),
        }
    }

    #[test]
    fn test_parse_hex_roundtrip() {
        // Test that we can parse a Sanad ID that was previously displayed as hex
        let original = SanadId::new([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ]);
        let hex_display = hex::encode(original.as_bytes());
        let parsed = SanadId::parse_hex(&hex_display).unwrap();
        assert_eq!(original, parsed);
    }
}
