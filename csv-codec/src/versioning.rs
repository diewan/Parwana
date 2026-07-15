//! Protocol versioning
//!
//! This module provides protocol versioning support for canonical serialization.

use crate::error::CodecError;

/// Current Parwana version
pub const PROTOCOL_VERSION_MAJOR: u16 = 1;
#[allow(missing_docs)]
pub const PROTOCOL_VERSION_MINOR: u16 = 0;
#[allow(missing_docs)]
pub const PROTOCOL_VERSION_PATCH: u16 = 0;

/// Protocol version tuple
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    /// Current protocol version
    pub const CURRENT: Self = Self {
        major: PROTOCOL_VERSION_MAJOR,
        minor: PROTOCOL_VERSION_MINOR,
        patch: PROTOCOL_VERSION_PATCH,
    };

    /// Create new version
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Encode as bytes (little-endian)
    pub fn encode(&self) -> [u8; 6] {
        let mut result = [0u8; 6];
        result[0..2].copy_from_slice(&self.major.to_le_bytes());
        result[2..4].copy_from_slice(&self.minor.to_le_bytes());
        result[4..6].copy_from_slice(&self.patch.to_le_bytes());
        result
    }

    /// Decode from bytes (little-endian)
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 6 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for version".to_string(),
            ));
        }
        let mut major_bytes = [0u8; 2];
        major_bytes.copy_from_slice(&bytes[0..2]);
        let mut minor_bytes = [0u8; 2];
        minor_bytes.copy_from_slice(&bytes[2..4]);
        let mut patch_bytes = [0u8; 2];
        patch_bytes.copy_from_slice(&bytes[4..6]);

        let major = u16::from_le_bytes(major_bytes);
        let minor = u16::from_le_bytes(minor_bytes);
        let patch = u16::from_le_bytes(patch_bytes);
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// Check if this version is compatible with another
    ///
    /// Compatibility rules:
    /// - Same major version: compatible
    /// - Different major version: incompatible
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
