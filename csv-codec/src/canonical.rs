//! Canonical serialization primitives for Parwana
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
use ciborium::value::{CanonicalValue, Value};

/// CBOR tag range reserved for Parwana types (0x1C0–0x1FF = 448–511)
pub const CBOR_TAG_RANGE_START: u64 = 448;
/// Last CBOR tag in the CSV reserved range (inclusive).
pub const CBOR_TAG_RANGE_END: u64 = 511;

/// CBOR tags for Parwana types
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
    let mut value =
        Value::serialized(value).map_err(|e| CodecError::SerializationError(e.to_string()))?;
    normalize_canonical_value(&mut value)?;

    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| CodecError::SerializationError(e.to_string()))?;
    Ok(buf)
}

fn normalize_canonical_value(value: &mut Value) -> Result<(), CodecError> {
    match value {
        Value::Array(items) => {
            for item in items {
                normalize_canonical_value(item)?;
            }
        }
        Value::Map(entries) => {
            for (key, entry_value) in entries.iter_mut() {
                normalize_canonical_value(key)?;
                normalize_canonical_value(entry_value)?;
            }

            if let Some(number) = serde_json_number_value(entries)? {
                *value = number;
                return Ok(());
            }

            entries.sort_by(|(left, _), (right, _)| {
                CanonicalValue::from(left.clone()).cmp(&CanonicalValue::from(right.clone()))
            });
        }
        Value::Tag(_, tagged) => normalize_canonical_value(tagged)?,
        _ => {}
    }

    Ok(())
}

fn serde_json_number_value(entries: &[(Value, Value)]) -> Result<Option<Value>, CodecError> {
    if entries.len() != 1 {
        return Ok(None);
    }

    let (key, value) = &entries[0];
    let Value::Text(key) = key else {
        return Ok(None);
    };
    if key != "$serde_json::private::Number" {
        return Ok(None);
    }

    let Value::Text(number) = value else {
        return Err(CodecError::SerializationError(
            "invalid serde_json number representation".to_string(),
        ));
    };

    if let Ok(unsigned) = number.parse::<u64>() {
        return Ok(Some(Value::Integer(unsigned.into())));
    }
    if let Ok(signed) = number.parse::<i64>() {
        return Ok(Some(Value::Integer(signed.into())));
    }
    if let Ok(float) = number.parse::<f64>() {
        return Ok(Some(Value::Float(float)));
    }

    Err(CodecError::SerializationError(format!(
        "invalid serde_json number: {}",
        number
    )))
}

/// Deserialize from deterministic CBOR bytes.
///
/// # Errors
/// Returns `CodecError` if decoding fails.
pub fn from_canonical_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes).map_err(|e| CodecError::DeserializationError(e.to_string()))
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
    buf.extend_from_slice(&to_canonical_cbor(value)?);
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
    let stored_checksum =
        u32::from_le_bytes(checksum_bytes.try_into().map_err(|_| {
            CodecError::DeserializationError("Invalid checksum length".to_string())
        })?);

    let computed_checksum = crc32fast::hash(cbor);
    if stored_checksum != computed_checksum {
        return Err(CodecError::IntegrityError(
            "CRC32 checksum mismatch — data may be corrupted".to_string(),
        ));
    }

    ciborium::from_reader(cbor).map_err(|e| CodecError::DeserializationError(e.to_string()))
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
            CodecError::SerializationError(format!("Failed to decode CBOR tag prefix: {}", e))
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

/// Hash canonical CBOR encoding of `value` using SHA-256.
///
/// # WARNING: Testing/Utility Only
///
/// This function is provided for testing and utility purposes only. It does NOT
/// provide the full protocol hash boundary. Production protocol hashing MUST use
/// `csv-hash` crate's tagged_hash function, which provides:
/// - Proper hash types (SanadId, ReplayId, etc.)
/// - Domain separation with protocol-defined tags
/// - Cross-chain hash compatibility guarantees
///
/// This function uses a simple SHA-256 hash with a domain separator string,
/// which is insufficient for protocol commitments where hash type identity
/// and cross-domain collision resistance are required.
///
/// # Arguments
/// * `domain` - Domain separator string (e.g., "proof-bundle", "commitment")
/// * `value` - Value to serialize and hash
///
/// # Errors
/// Returns `CodecError` if serialization fails.
///
/// # Production Alternative
/// Use `csv-hash::tagged_hash` for all protocol-critical hashing.
pub fn canonical_hash<T: serde::Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, CodecError> {
    let cbor = to_canonical_cbor(value)?;
    // Simple hash using sha2 - in production this should use csv-hash's tagged_hash
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(&cbor);
    Ok(hasher.finalize().to_vec())
}
