//! Schema validation
//!
//! This module provides schema validation for CSV protocol types.
//! It enforces structural constraints on schemas, descriptors, and
//! payload configurations to prevent malformed or malicious inputs.
//!
//! ## Validation Rules
//!
//! - Schema IDs must match the pattern `csv.<domain>.v[0-9]+`
//! - Schema versions must be in range 1-255
//! - Payload codecs must be recognized (CBOR=1, JSON=2, etc.)
//! - Resource limits must be within acceptable bounds
//! - Descriptor hashes must be non-zero

/// Schema validation error
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// Schema ID does not match the required pattern
    #[error("Invalid schema ID: {0}. Must match pattern 'csv.<domain>.v[0-9]+'")]
    InvalidSchemaId(String),

    /// Schema version is out of range
    #[error("Schema version {0} out of range. Must be 1-255")]
    InvalidVersion(u8),

    /// Unknown payload codec
    #[error("Unknown payload codec: {0}. Supported: CBOR(1), JSON(2), MessagePack(3)")]
    UnknownCodec(u8),

    /// Resource limit exceeds maximum
    #[error("Resource limit {field} ({value}) exceeds maximum ({max})")]
    ResourceLimitExceeded { field: &'static str, value: u64, max: u64 },

    /// Descriptor hash is zero (not computed)
    #[error("Descriptor hash is zero. Must be computed from canonical CBOR serialization")]
    ZeroDescriptorHash,

    /// Payload hash is zero (not computed)
    #[error("Payload hash is zero. Must be computed from payload content")]
    ZeroPayloadHash,

    /// Schema ID is empty
    #[error("Schema ID is empty")]
    EmptySchemaId,

    /// Generic validation error
    #[error("Schema validation failed: {0}")]
    Generic(String),
}

/// Supported payload codecs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCodec {
    /// Canonical CBOR (RFC 8949)
    Cbor = 1,
    /// JSON (not canonical — use only for human-readable formats)
    Json = 2,
    /// MessagePack
    MessagePack = 3,
}

impl PayloadCodec {
    /// Parse a codec from a u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(PayloadCodec::Cbor),
            2 => Some(PayloadCodec::Json),
            3 => Some(PayloadCodec::MessagePack),
            _ => None,
        }
    }

    /// Returns true if this codec is canonical (deterministic serialization).
    ///
    /// Only CBOR is canonical. JSON and MessagePack produce different
    /// byte sequences for the same data depending on field ordering.
    pub fn is_canonical(&self) -> bool {
        matches!(self, PayloadCodec::Cbor)
    }
}

/// Maximum allowed resource limits
pub mod limits {
    /// Maximum payload size in bytes (10 MB)
    pub const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024;
    /// Maximum Merkle tree depth
    pub const MAX_MERKLE_DEPTH: u64 = 64;
    /// Maximum number of leaves in a content tree
    pub const MAX_LEAVES: u64 = 1_000_000;
    /// Maximum number of attachments
    pub const MAX_ATTACHMENTS: u64 = 1000;
    /// Maximum proof bundle size in bytes (5 MB)
    pub const MAX_PROOF_SIZE: u64 = 5 * 1024 * 1024;
}

/// Validate a schema ID string.
///
/// ## Rules
///
/// - Must not be empty
/// - Must match pattern `csv.<domain>.v[0-9]+`
/// - Domain must be alphanumeric with dots and hyphens
/// - Version must be a positive integer
pub fn validate_schema_id(id: &str) -> Result<(), SchemaError> {
    if id.is_empty() {
        return Err(SchemaError::EmptySchemaId);
    }

    // Must start with "csv."
    if !id.starts_with("csv.") {
        return Err(SchemaError::InvalidSchemaId(id.to_string()));
    }

    // Must end with ".v[0-9]+"
    let parts: Vec<&str> = id.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(SchemaError::InvalidSchemaId(id.to_string()));
    }

    let version_part = parts[0];
    if !version_part.starts_with("v") {
        return Err(SchemaError::InvalidSchemaId(id.to_string()));
    }

    // Version must be a positive integer
    let version_str = &version_part[1..];
    if version_str.is_empty() {
        return Err(SchemaError::InvalidSchemaId(id.to_string()));
    }

    if let Ok(version) = version_str.parse::<u64>() {
        if version == 0 {
            return Err(SchemaError::InvalidSchemaId(id.to_string()));
        }
    } else {
        return Err(SchemaError::InvalidSchemaId(id.to_string()));
    }

    Ok(())
}

/// Validate a schema version number.
pub fn validate_schema_version(version: u8) -> Result<(), SchemaError> {
    if version == 0 {
        return Err(SchemaError::InvalidVersion(0));
    }
    Ok(())
}

/// Validate a payload codec identifier.
pub fn validate_payload_codec(codec: u8) -> Result<PayloadCodec, SchemaError> {
    PayloadCodec::from_u8(codec).ok_or(SchemaError::UnknownCodec(codec))
}

/// Validate resource limits against maximum bounds.
///
/// ## Arguments
///
/// * `payload_size` — Size of the payload in bytes
/// * `merkle_depth` — Depth of the Merkle tree
/// * `leaf_count` — Number of leaves in the content tree
/// * `attachment_count` — Number of attachments
pub fn validate_resource_limits(
    payload_size: u64,
    merkle_depth: u64,
    leaf_count: u64,
    attachment_count: u64,
) -> Result<(), SchemaError> {
    if payload_size > limits::MAX_PAYLOAD_SIZE {
        return Err(SchemaError::ResourceLimitExceeded {
            field: "payload_size",
            value: payload_size,
            max: limits::MAX_PAYLOAD_SIZE,
        });
    }

    if merkle_depth > limits::MAX_MERKLE_DEPTH {
        return Err(SchemaError::ResourceLimitExceeded {
            field: "merkle_depth",
            value: merkle_depth,
            max: limits::MAX_MERKLE_DEPTH,
        });
    }

    if leaf_count > limits::MAX_LEAVES {
        return Err(SchemaError::ResourceLimitExceeded {
            field: "leaf_count",
            value: leaf_count,
            max: limits::MAX_LEAVES,
        });
    }

    if attachment_count > limits::MAX_ATTACHMENTS {
        return Err(SchemaError::ResourceLimitExceeded {
            field: "attachment_count",
            value: attachment_count,
            max: limits::MAX_ATTACHMENTS,
        });
    }

    Ok(())
}

/// Validate a descriptor hash (must be non-zero).
pub fn validate_descriptor_hash(hash: &[u8; 32]) -> Result<(), SchemaError> {
    if hash.iter().all(|&b| b == 0) {
        return Err(SchemaError::ZeroDescriptorHash);
    }
    Ok(())
}

/// Validate a payload hash (must be non-zero).
pub fn validate_payload_hash(hash: &[u8; 32]) -> Result<(), SchemaError> {
    if hash.iter().all(|&b| b == 0) {
        return Err(SchemaError::ZeroPayloadHash);
    }
    Ok(())
}

/// Validate a complete schema configuration.
///
/// This is the main entry point for schema validation. It checks:
/// 1. Schema ID format
/// 2. Schema version
/// 3. Payload codec
/// 4. Resource limits
/// 5. Descriptor and payload hashes
///
/// ## Arguments
///
/// * `schema_id` — The schema identifier string
/// * `version` — The schema version (1-255)
/// * `codec` — The payload codec identifier
/// * `descriptor_hash` — The descriptor hash (must be non-zero)
/// * `payload_hash` — The payload hash (must be non-zero)
/// * `payload_size` — Size of the payload in bytes
/// * `merkle_depth` — Depth of the Merkle tree
/// * `leaf_count` — Number of leaves in the content tree
/// * `attachment_count` — Number of attachments
pub fn validate_schema(
    schema_id: &str,
    version: u8,
    codec: u8,
    descriptor_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    payload_size: u64,
    merkle_depth: u64,
    leaf_count: u64,
    attachment_count: u64,
) -> Result<(), SchemaError> {
    // Validate schema ID
    validate_schema_id(schema_id)?;

    // Validate version
    validate_schema_version(version)?;

    // Validate codec
    validate_payload_codec(codec)?;

    // Validate hashes
    validate_descriptor_hash(descriptor_hash)?;
    validate_payload_hash(payload_hash)?;

    // Validate resource limits
    validate_resource_limits(payload_size, merkle_depth, leaf_count, attachment_count)?;

    Ok(())
}

/// Validate a schema ID and return the parsed version.
///
/// Returns the version number if the schema ID is valid.
pub fn parse_schema_version(schema_id: &str) -> Result<u64, SchemaError> {
    validate_schema_id(schema_id)?;
    let parts: Vec<&str> = schema_id.rsplitn(2, '.').collect();
    let version_str = &parts[0][1..]; // Remove 'v' prefix
    version_str
        .parse::<u64>()
        .map_err(|_| SchemaError::InvalidSchemaId(schema_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_schema_id_valid() {
        assert!(validate_schema_id("csv.sanad.content.v1").is_ok());
        assert!(validate_schema_id("csv.transfer.state.v2").is_ok());
        assert!(validate_schema_id("csv.seal.anchor.v10").is_ok());
    }

    #[test]
    fn test_validate_schema_id_invalid() {
        assert!(validate_schema_id("").is_err());
        assert!(validate_schema_id("sanad.content.v1").is_err()); // missing csv. prefix
        assert!(validate_schema_id("csv.sanad.content").is_err()); // missing version
        assert!(validate_schema_id("csv.sanad.content.v").is_err()); // empty version
        assert!(validate_schema_id("csv.sanad.content.v0").is_err()); // version 0
        assert!(validate_schema_id("csv.sanad.content.vabc").is_err()); // non-numeric version
    }

    #[test]
    fn test_validate_schema_version() {
        assert!(validate_schema_version(1).is_ok());
        assert!(validate_schema_version(255).is_ok());
        assert!(validate_schema_version(0).is_err());
    }

    #[test]
    fn test_validate_payload_codec() {
        assert_eq!(validate_payload_codec(1), Ok(PayloadCodec::Cbor));
        assert_eq!(validate_payload_codec(2), Ok(PayloadCodec::Json));
        assert_eq!(validate_payload_codec(3), Ok(PayloadCodec::MessagePack));
        assert!(validate_payload_codec(0).is_err());
        assert!(validate_payload_codec(4).is_err());
    }

    #[test]
    fn test_payload_codec_canonical() {
        assert!(PayloadCodec::Cbor.is_canonical());
        assert!(!PayloadCodec::Json.is_canonical());
        assert!(!PayloadCodec::MessagePack.is_canonical());
    }

    #[test]
    fn test_validate_resource_limits_valid() {
        assert!(validate_resource_limits(1024, 10, 100, 5).is_ok());
    }

    #[test]
    fn test_validate_resource_limits_payload_too_large() {
        let result = validate_resource_limits(
            limits::MAX_PAYLOAD_SIZE + 1,
            10,
            100,
            5,
        );
        assert!(matches!(result, Err(SchemaError::ResourceLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_resource_limits_merkle_depth_too_deep() {
        let result = validate_resource_limits(
            1024,
            limits::MAX_MERKLE_DEPTH + 1,
            100,
            5,
        );
        assert!(matches!(result, Err(SchemaError::ResourceLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_descriptor_hash_zero() {
        let zero_hash = [0u8; 32];
        assert!(validate_descriptor_hash(&zero_hash).is_err());
    }

    #[test]
    fn test_validate_descriptor_hash_non_zero() {
        let hash = [1u8; 32];
        assert!(validate_descriptor_hash(&hash).is_ok());
    }

    #[test]
    fn test_validate_payload_hash_zero() {
        let zero_hash = [0u8; 32];
        assert!(validate_payload_hash(&zero_hash).is_err());
    }

    #[test]
    fn test_parse_schema_version() {
        assert_eq!(parse_schema_version("csv.sanad.v1").unwrap(), 1);
        assert_eq!(parse_schema_version("csv.transfer.v2").unwrap(), 2);
        assert_eq!(parse_schema_version("csv.anchor.v10").unwrap(), 10);
        assert!(parse_schema_version("invalid").is_err());
    }

    #[test]
    fn test_validate_schema_full() {
        let descriptor_hash = [1u8; 32];
        let payload_hash = [2u8; 32];

        assert!(validate_schema(
            "csv.sanad.content.v1",
            1,
            1, // CBOR
            &descriptor_hash,
            &payload_hash,
            1024,
            10,
            100,
            5,
        ).is_ok());
    }

    #[test]
    fn test_validate_schema_full_invalid_id() {
        let descriptor_hash = [1u8; 32];
        let payload_hash = [2u8; 32];

        assert!(validate_schema(
            "invalid",
            1,
            1,
            &descriptor_hash,
            &payload_hash,
            1024,
            10,
            100,
            5,
        ).is_err());
    }

    #[test]
    fn test_validate_schema_full_zero_hash() {
        let zero_hash = [0u8; 32];

        assert!(validate_schema(
            "csv.sanad.v1",
            1,
            1,
            &zero_hash,
            &zero_hash,
            1024,
            10,
            100,
            5,
        ).is_err());
    }
}
