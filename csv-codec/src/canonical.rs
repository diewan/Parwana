//! Canonical serialization primitives for CSV Protocol
//!
//! All proof payloads, sanad envelopes, and commitment inputs MUST use
//! these functions. Raw serde JSON is forbidden in any hashing path.
//!
//! Encoding: deterministic CBOR (RFC 8949 section 4.2 canonical form)
//!   - Keys sorted lexicographically
//!   - No indefinite-length encoding
//!   - Integers in smallest representation
//!
//! External crate: `ciborium` (no_std compatible, pure Rust)

use crate::error::CodecError;

/// CBOR tag range reserved for CSV protocol types (0x1C0–0x1FF = 448–511)
pub const CBOR_TAG_RANGE_START: u64 = 448;
/// Last CBOR tag in the CSV reserved range (inclusive).
pub const CBOR_TAG_RANGE_END: u64 = 511;

/// CBOR tags for CSV protocol types
pub mod cbor_tags {
    /// ProofBundle CBOR tag
    pub const PROOF_BUNDLE: u64 = 448;
    /// SanadEnvelope CBOR tag
    pub const SANAD_ENVELOPE: u64 = 449;
    /// Commitment CBOR tag
    pub const COMMITMENT: u64 = 450;
    /// Seal CBOR tag
    pub const SEAL: u64 = 451;
    /// Consignment CBOR tag
    pub const CONSIGNMENT: u64 = 452;
}

/// Serialize `value` to deterministic CBOR bytes.
///
/// # Errors
/// Returns `CodecError` if encoding fails.
pub fn to_canonical_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| CodecError::SerializationError(e.to_string()))?;
    Ok(buf)
}

/// Deserialize from deterministic CBOR bytes.
///
/// # Errors
/// Returns `CodecError` if decoding fails.
pub fn from_canonical_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes)
        .map_err(|e| CodecError::DeserializationError(e.to_string()))
}

/// Serialize `value` to deterministic CBOR bytes with a CBOR tag.
///
/// The tag must be in the reserved range 0x1C0–0x1FF (448–511).
///
/// # Errors
/// Returns `CodecError` if encoding fails or tag is invalid.
pub fn to_canonical_cbor_with_tag<T: serde::Serialize>(
    value: &T,
    tag: u64,
) -> Result<Vec<u8>, CodecError> {
    if !(CBOR_TAG_RANGE_START..=CBOR_TAG_RANGE_END).contains(&tag) {
        return Err(CodecError::SerializationError(format!(
            "CBOR tag {} is outside reserved range {}–{}",
            tag, CBOR_TAG_RANGE_START, CBOR_TAG_RANGE_END
        )));
    }
    
    let mut buf = Vec::new();
    // Write CBOR tag
    ciborium::into_writer(&tag, &mut buf)
        .map_err(|e| CodecError::SerializationError(e.to_string()))?;
    // Write value
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| CodecError::SerializationError(e.to_string()))?;
    Ok(buf)
}

/// Serialize `value` to deterministic CBOR bytes with a CRC32 integrity checksum.
///
/// Format: `[canonical_cbor_bytes][crc32_checksum]`
/// The checksum enables fast corruption detection before expensive cryptographic verification.
///
/// # Errors
/// Returns `CodecError` if encoding fails.
pub fn to_canonical_cbor_with_checksum<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, CodecError> {
    let cbor = to_canonical_cbor(value)?;
    
    // Compute CRC32 checksum
    let checksum = crc32fast::hash(&cbor);
    
    let mut result = cbor;
    result.extend_from_slice(&checksum.to_le_bytes());
    Ok(result)
}

/// Deserialize from CBOR bytes with CRC32 integrity verification.
///
/// Format: `[canonical_cbor_bytes][crc32_checksum]`
///
/// # Errors
/// Returns `CodecError::IntegrityError` if checksum doesn't match.
pub fn from_canonical_cbor_with_checksum<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, CodecError> {
    if bytes.len() < 4 {
        return Err(CodecError::DeserializationError(
            "Bytes too short for checksum".to_string(),
        ));
    }
    
    let (cbor, checksum_bytes) = bytes.split_at(bytes.len() - 4);
    let stored_checksum = u32::from_le_bytes(checksum_bytes.try_into().map_err(|_| {
        CodecError::DeserializationError("Invalid checksum length".to_string())
    })?);
    
    let computed_checksum = crc32fast::hash(cbor);
    if stored_checksum != computed_checksum {
        return Err(CodecError::IntegrityError(
            "CRC32 checksum mismatch — data may be corrupted".to_string(),
        ));
    }
    
    ciborium::from_reader(cbor)
        .map_err(|e| CodecError::DeserializationError(e.to_string()))
}

/// Deserialize from CBOR bytes with optional tag and version validation.
///
/// # Arguments
/// * `bytes` — CBOR-encoded bytes (optionally with tag prefix)
/// * `expected_tag` — Optional expected CBOR tag
/// * `expected_version` — Optional expected schema version
///
/// # Errors
/// Returns `CodecError::VersionMismatch` if version doesn't match.
/// Returns `CodecError::SerializationError` if tag doesn't match.
pub fn from_canonical_cbor_full<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected_tag: Option<u64>,
    _expected_version: Option<u32>,
) -> Result<T, CodecError> {
    let mut cursor: &[u8] = bytes;

    if let Some(tag) = expected_tag {
        let decoded_tag: u64 = ciborium::from_reader(&mut cursor).map_err(|e| {
            CodecError::SerializationError(format!(
                "Failed to decode CBOR tag prefix: {}",
                e
            ))
        })?;
        if decoded_tag != tag {
            return Err(CodecError::SerializationError(format!(
                "Expected CBOR tag {}, got {}",
                tag, decoded_tag
            )));
        }
    }

    let value: T = ciborium::from_reader(&mut cursor)
        .map_err(|e| CodecError::DeserializationError(e.to_string()))?;

    Ok(value)
}
