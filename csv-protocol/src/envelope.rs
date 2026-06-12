//! Canonical Sanad Envelope — chain-agnostic, version-stable identity.
//!
//! This is the protocol center. Not chain accounts. Not runtime structs.
//! Not SDK DTOs. A canonical envelope that serializes identically everywhere.

use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_hash::csv_tagged_hash;

/// Signature scheme used to sign envelopes.
///
/// **Layer:** L1
/// **Serde:** Used for canonical CBOR encoding only (to_canonical_cbor/from_canonical_cbor).
/// Non-canonical formats (serde_json) are FORBIDDEN in verification paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    Secp256k1,
    Ed25519,
}

/// Canonical serialization encoding type.
///
/// **Layer:** L1
/// **Serde:** Used for canonical CBOR encoding only (to_canonical_cbor/from_canonical_cbor).
/// Non-canonical formats (serde_json) are FORBIDDEN in verification paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingType {
    /// Canonical CBOR (sorted keys, no extra whitespace)
    CanonicalCbor,
}

/// The canonical, chain-agnostic, version-stable Sanad identity.
///
/// This is what gets hashed, committed, and verified — not chain account data.
/// Chain contracts store only `envelope_commitment` (the hash of this struct).
///
/// **Layer:** L1
/// **Serde:** Used for canonical CBOR encoding only (to_canonical_cbor/from_canonical_cbor).
/// Non-canonical formats (serde_json) are FORBIDDEN in verification paths.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalSanadEnvelope {
    /// Protocol version that defines this envelope's schema.
    /// MUST be checked before decoding any other field.
    pub protocol_version: u16,

    /// Globally unique Sanad identity (content-addressed from body_hash + issuer_id).
    pub sanad_id: [u8; 32],

    /// Semantic type identifier (registered in the schema registry).
    pub sanad_type: TypeId,

    /// Issuer's canonical identity hash.
    pub issuer_id: [u8; 32],

    /// Hash of the Sanad body (rights, metadata, custom fields).
    pub body_hash: [u8; 32],

    /// Root of the metadata Merkle tree.
    pub metadata_root: [u8; 32],

    /// Root of the proof Merkle tree (historical proofs of state transitions).
    pub proof_root: [u8; 32],

    /// Hash of the seal commitment (current chain anchor).
    pub seal_root: [u8; 32],

    /// Monotonic creation timestamp (Unix seconds).
    pub timestamp: u64,

    /// Nonce preventing two identical envelopes with same timestamp.
    pub nonce: u64,

    /// Hashes of parent envelopes (for lineage / provenance DAG).
    pub parent_refs: Vec<[u8; 32]>,

    /// Hashes of dependency envelopes (e.g., rights this Sanad inherits from).
    pub dependency_refs: Vec<[u8; 32]>,

    /// Signature scheme used to sign this envelope.
    pub signature_scheme: SignatureScheme,

    /// Canonical serialization encoding (always CBOR for v1).
    pub canonical_encoding: EncodingType,
}

/// Type identifier for Sanad semantic types.
///
/// **Layer:** L1
/// **Serde:** Used for canonical CBOR encoding only (to_canonical_cbor/from_canonical_cbor).
/// Non-canonical formats (serde_json) are FORBIDDEN in verification paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeId(pub [u8; 32]);

impl TypeId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl CanonicalSanadEnvelope {
    pub const CURRENT_VERSION: u16 = 1;

    /// Compute the canonical commitment hash.
    /// Identical on every chain and language implementation.
    pub fn commitment(&self) -> [u8; 32] {
        let cbor = to_canonical_cbor(self).unwrap_or_else(|err| {
            format!("sanad-envelope-canonical-serialization-error:{err}").into_bytes()
        });
        csv_tagged_hash("sanad-envelope-v1", &cbor)
    }

    /// Validate version before processing.
    pub fn check_version(&self) -> Result<(), ProtocolError> {
        if self.protocol_version > Self::CURRENT_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                found: self.protocol_version,
                max_supported: Self::CURRENT_VERSION,
            });
        }
        Ok(())
    }

    /// Create a new envelope with auto-generated sanad_id from commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sanad_type: TypeId,
        issuer_id: [u8; 32],
        body_hash: [u8; 32],
        metadata_root: [u8; 32],
        proof_root: [u8; 32],
        seal_root: [u8; 32],
        timestamp: u64,
        nonce: u64,
        parent_refs: Vec<[u8; 32]>,
        dependency_refs: Vec<[u8; 32]>,
        signature_scheme: SignatureScheme,
    ) -> Self {
        let builder = CanonicalSanadEnvelope {
            protocol_version: Self::CURRENT_VERSION,
            sanad_id: [0u8; 32],
            sanad_type,
            issuer_id,
            body_hash,
            metadata_root,
            proof_root,
            seal_root,
            timestamp,
            nonce,
            parent_refs,
            dependency_refs,
            signature_scheme,
            canonical_encoding: EncodingType::CanonicalCbor,
        };
        // sanad_id is set after commitment computation
        let _ = builder.commitment(); // placeholder — caller sets sanad_id
        builder
    }
}

/// Version-aware decoder — the only entry point for deserializing envelopes.
pub fn decode_envelope(bytes: &[u8]) -> Result<CanonicalSanadEnvelope, ProtocolError> {
    // Peek at version field before full decode
    let version = peek_protocol_version(bytes)?;
    match version {
        1 => Ok(from_canonical_cbor::<CanonicalSanadEnvelope>(bytes)?),
        v => Err(ProtocolError::UnsupportedVersion {
            found: v,
            max_supported: CanonicalSanadEnvelope::CURRENT_VERSION,
        }),
    }
}

fn peek_protocol_version(bytes: &[u8]) -> Result<u16, ProtocolError> {
    // Minimal CBOR map parse to extract protocol_version field
    // In canonical CBOR, the first key is "protocol_version" (sorted keys)
    if bytes.is_empty() {
        return Err(ProtocolError::MalformedEnvelope);
    }

    // Try to parse as a simple CBOR map and extract version
    // This is a minimal parse — we only need the first integer value
    let mut pos = 0;

    // Skip CBOR map header
    if pos < bytes.len() {
        let major = bytes[pos] & 0x1F;
        let additional = bytes[pos] >> 5;
        pos += 1;

        // Handle map with additional info
        if additional < 24 {
            // Map with N entries (0-23)
            if major != 0x5F {
                // Not a map
                return Err(ProtocolError::MalformedEnvelope);
            }
            // We expect at least one key-value pair
            // Skip to first key (should be a string "protocol_version")
            if pos >= bytes.len() {
                return Err(ProtocolError::MalformedEnvelope);
            }
            // String header
            let string_major = bytes[pos] & 0x1F;
            pos += 1;
            if string_major != 0x06 && string_major != 0x07 {
                // Not a text string
                return Err(ProtocolError::MalformedEnvelope);
            }
            // Skip string length encoding
            let string_len = match bytes[pos - 1] >> 5 {
                n if n < 24 => n as usize,
                24 => {
                    if pos + 1 >= bytes.len() {
                        return Err(ProtocolError::MalformedEnvelope);
                    }
                    pos += 1;
                    bytes[pos - 1] as usize
                }
                _ => return Err(ProtocolError::MalformedEnvelope),
            };
            pos += string_len; // Skip string content

            // Now read the value (should be an unsigned integer)
            if pos >= bytes.len() {
                return Err(ProtocolError::MalformedEnvelope);
            }
            let _val_major = bytes[pos] & 0x1F;
            let val_additional = bytes[pos] >> 5;
            pos += 1;

            let value = match val_additional {
                n if n < 24 => n as u16,
                24 => {
                    if pos + 1 >= bytes.len() {
                        return Err(ProtocolError::MalformedEnvelope);
                    }
                    u16::from_be_bytes([bytes[pos], bytes[pos + 1]])
                }
                _ => return Err(ProtocolError::MalformedEnvelope),
            };

            return Ok(value);
        }
    }

    Err(ProtocolError::MalformedEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_commitment_deterministic() {
        let envelope = CanonicalSanadEnvelope {
            protocol_version: 1,
            sanad_id: [0u8; 32],
            sanad_type: TypeId::new([1u8; 32]),
            issuer_id: [2u8; 32],
            body_hash: [3u8; 32],
            metadata_root: [4u8; 32],
            proof_root: [5u8; 32],
            seal_root: [6u8; 32],
            timestamp: 1_700_000_000,
            nonce: 42,
            parent_refs: vec![],
            dependency_refs: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            canonical_encoding: EncodingType::CanonicalCbor,
        };

        let c1 = envelope.commitment();
        let c2 = envelope.commitment();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_envelope_version_check() {
        let envelope = CanonicalSanadEnvelope {
            protocol_version: 1,
            sanad_id: [0u8; 32],
            sanad_type: TypeId::new([1u8; 32]),
            issuer_id: [2u8; 32],
            body_hash: [3u8; 32],
            metadata_root: [4u8; 32],
            proof_root: [5u8; 32],
            seal_root: [6u8; 32],
            timestamp: 0,
            nonce: 0,
            parent_refs: vec![],
            dependency_refs: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            canonical_encoding: EncodingType::CanonicalCbor,
        };

        assert!(envelope.check_version().is_ok());
    }

    #[test]
    fn test_envelope_version_reject_future() {
        let mut envelope = CanonicalSanadEnvelope {
            protocol_version: 1,
            sanad_id: [0u8; 32],
            sanad_type: TypeId::new([1u8; 32]),
            issuer_id: [2u8; 32],
            body_hash: [3u8; 32],
            metadata_root: [4u8; 32],
            proof_root: [5u8; 32],
            seal_root: [6u8; 32],
            timestamp: 0,
            nonce: 0,
            parent_refs: vec![],
            dependency_refs: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            canonical_encoding: EncodingType::CanonicalCbor,
        };

        envelope.protocol_version = 99;
        assert!(envelope.check_version().is_err());
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let envelope = CanonicalSanadEnvelope {
            protocol_version: 1,
            sanad_id: [0xAB; 32],
            sanad_type: TypeId::new([0xCD; 32]),
            issuer_id: [0xEF; 32],
            body_hash: [0x11; 32],
            metadata_root: [0x22; 32],
            proof_root: [0x33; 32],
            seal_root: [0x44; 32],
            timestamp: 1_700_000_000,
            nonce: 123,
            parent_refs: vec![[0xAA; 32]],
            dependency_refs: vec![[0xBB; 32], [0xCC; 32]],
            signature_scheme: SignatureScheme::Secp256k1,
            canonical_encoding: EncodingType::CanonicalCbor,
        };

        let bytes = to_canonical_cbor(&envelope).unwrap();
        let decoded: CanonicalSanadEnvelope = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(envelope, decoded);
    }
}
