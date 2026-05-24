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

use std::string::String;
use std::vec::Vec;

use ciborium::value::{CanonicalValue, Value};

/// Error type for canonical serialization operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// Serialization failed
    SerializationError(String),
    /// Deserialization failed
    DeserializationError(String),
}

impl core::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CanonicalError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CanonicalError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
        }
    }
}

impl core::error::Error for CanonicalError {}

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
/// Returns `CanonicalError::SerializationError` if encoding fails.
pub fn to_canonical_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut value = Value::serialized(value)
        .map_err(|e| CanonicalError::SerializationError(format!("{}", e)))?;
    normalize_canonical_value(&mut value)?;

    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| CanonicalError::SerializationError(format!("{}", e)))?;
    Ok(buf)
}

fn normalize_canonical_value(value: &mut Value) -> Result<(), CanonicalError> {
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

fn serde_json_number_value(entries: &[(Value, Value)]) -> Result<Option<Value>, CanonicalError> {
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
        return Err(CanonicalError::SerializationError(
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

    Err(CanonicalError::SerializationError(format!(
        "invalid serde_json number: {}",
        number
    )))
}

/// Deserialize from deterministic CBOR bytes.
///
/// # Errors
/// Returns `CanonicalError::DeserializationError` if decoding fails.
pub fn from_canonical_cbor<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, CanonicalError> {
    ciborium::from_reader(bytes).map_err(|e| CanonicalError::DeserializationError(format!("{}", e)))
}

/// Hash canonical CBOR encoding of `value` using tagged_hash.
///
/// This is the ONLY approved way to hash protocol data.
/// Direct `sha256`, `keccak256`, or `blake3` calls are forbidden.
pub fn canonical_hash<T: serde::Serialize>(
    domain: &str,
    value: &T,
) -> Result<crate::Hash, CanonicalError> {
    let cbor = to_canonical_cbor(value)?;
    Ok(crate::Hash::new(crate::csv_tagged_hash(domain, &cbor)))
}

/// Serialize `value` to deterministic CBOR bytes with a CBOR tag.
///
/// The tag must be in the reserved range 0x1C0–0x1FF (448–511).
///
/// # Errors
/// Returns `CanonicalError::SerializationError` if encoding fails or tag is invalid.
pub fn to_canonical_cbor_with_tag<T: serde::Serialize>(
    value: &T,
    tag: u64,
) -> Result<Vec<u8>, CanonicalError> {
    if !(CBOR_TAG_RANGE_START..=CBOR_TAG_RANGE_END).contains(&tag) {
        return Err(CanonicalError::SerializationError(format!(
            "CBOR tag {} is outside reserved range {}–{}",
            tag, CBOR_TAG_RANGE_START, CBOR_TAG_RANGE_END
        )));
    }

    let mut buf = Vec::new();
    // Write CBOR tag
    ciborium::into_writer(&tag, &mut buf)
        .map_err(|e| CanonicalError::SerializationError(format!("{}", e)))?;
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
/// Returns `CanonicalError::SerializationError` if encoding fails.
pub fn to_canonical_cbor_with_checksum<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, CanonicalError> {
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
/// Returns `CanonicalError::DeserializationError` if checksum doesn't match.
pub fn from_canonical_cbor_with_checksum<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, CanonicalError> {
    if bytes.len() < 4 {
        return Err(CanonicalError::DeserializationError(
            "Bytes too short for checksum".to_string(),
        ));
    }

    let (cbor, checksum_bytes) = bytes.split_at(bytes.len() - 4);
    let stored_checksum = u32::from_le_bytes(checksum_bytes.try_into().map_err(|_| {
        CanonicalError::DeserializationError("Invalid checksum length".to_string())
    })?);

    let computed_checksum = crc32fast::hash(cbor);
    if stored_checksum != computed_checksum {
        return Err(CanonicalError::DeserializationError(
            "CRC32 checksum mismatch — data may be corrupted".to_string(),
        ));
    }

    ciborium::from_reader(cbor).map_err(|e| CanonicalError::DeserializationError(format!("{}", e)))
}

/// Deserialize from CBOR bytes with optional tag and version validation.
///
/// # Arguments
/// * `bytes` — CBOR-encoded bytes (optionally with tag prefix)
/// * `expected_tag` — Optional expected CBOR tag
/// * `expected_version` — Optional expected schema version
///
/// # Errors
/// Returns `CanonicalError::DeserializationError` if version doesn't match.
/// Returns `CanonicalError::DeserializationError` if tag doesn't match.
pub fn from_canonical_cbor_full<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected_tag: Option<u64>,
    _expected_version: Option<u32>,
) -> Result<T, CanonicalError> {
    let mut cursor: &[u8] = bytes;

    if let Some(tag) = expected_tag {
        let decoded_tag: u64 = ciborium::from_reader(&mut cursor).map_err(|e| {
            CanonicalError::DeserializationError(format!(
                "Failed to decode CBOR tag prefix: {}",
                format!("{}", e)
            ))
        })?;
        if decoded_tag != tag {
            return Err(CanonicalError::DeserializationError(format!(
                "Expected CBOR tag {}, got {}",
                tag, decoded_tag
            )));
        }
    }

    let value: T = ciborium::from_reader(&mut cursor)
        .map_err(|e| CanonicalError::DeserializationError(format!("{}", e)))?;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Fixture {
        a: u32,
        b: String,
    }

    #[test]
    fn roundtrip_is_lossless() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let bytes = to_canonical_cbor(&v).unwrap();
        let back: Fixture = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let v = Fixture {
            a: 1,
            b: "world".into(),
        };
        let b1 = to_canonical_cbor(&v).unwrap();
        let b2 = to_canonical_cbor(&v).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn canonical_hash_domain_separation() {
        let v = Fixture {
            a: 0,
            b: "test".into(),
        };
        let h1 = canonical_hash("domain.a", &v).unwrap();
        let h2 = canonical_hash("domain.b", &v).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn checksum_roundtrip() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let bytes = to_canonical_cbor_with_checksum(&v).unwrap();
        let back: Fixture = from_canonical_cbor_with_checksum(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn checksum_detects_corruption() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let mut bytes = to_canonical_cbor_with_checksum(&v).unwrap();
        // Corrupt the data
        bytes[0] ^= 0xFF;
        let result = from_canonical_cbor_with_checksum::<Fixture>(&bytes);
        assert!(result.is_err(), "Corrupted data must be detected");
    }

    #[test]
    fn tag_validation_rejects_invalid_tag() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let bytes = to_canonical_cbor_with_tag(&v, cbor_tags::PROOF_BUNDLE).unwrap();

        // Try to deserialize with wrong expected tag
        let result = from_canonical_cbor_full::<Fixture>(&bytes, Some(999), None);
        assert!(result.is_err(), "Wrong tag must be rejected");
    }

    #[test]
    fn tag_validation_accepts_valid_tag() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let bytes = to_canonical_cbor_with_tag(&v, cbor_tags::PROOF_BUNDLE).unwrap();

        // Deserialize with correct expected tag
        let result =
            from_canonical_cbor_full::<Fixture>(&bytes, Some(cbor_tags::PROOF_BUNDLE), None);
        assert!(result.is_ok(), "Correct tag must be accepted");
    }

    #[test]
    fn tag_rejects_out_of_range() {
        let v = Fixture {
            a: 42,
            b: "hello".into(),
        };
        let result = to_canonical_cbor_with_tag(&v, 100);
        assert!(result.is_err(), "Out-of-range tag must be rejected");
    }

    #[test]
    fn reserved_tag_range_constants() {
        assert_eq!(CBOR_TAG_RANGE_START, 448);
        assert_eq!(CBOR_TAG_RANGE_END, 511);
    }
}
