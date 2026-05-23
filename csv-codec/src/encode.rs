//! Canonical encoding primitives
//!
//! This module provides encoding functions that enforce canonical serialization rules.

use crate::byte_order::{to_le_bytes, to_le_bytes_32};

/// Encode a u64 as little-endian bytes
pub fn encode_u64(value: u64) -> [u8; 8] {
    to_le_bytes(value)
}

/// Encode a u32 as little-endian bytes
pub fn encode_u32(value: u32) -> [u8; 4] {
    to_le_bytes_32(value)
}

/// Encode a string as canonical UTF-8 bytes
///
/// Canonical UTF-8: normalized to NFC form, no BOM, valid UTF-8 only
pub fn encode_string(value: &str) -> Vec<u8> {
    // TODO: Add NFC normalization
    value.as_bytes().to_vec()
}

/// Encode a vector with explicit length prefix (little-endian)
pub fn encode_vec<T: AsRef<[u8]>>(value: &T) -> Vec<u8> {
    let bytes = value.as_ref();
    let len = encode_u64(bytes.len() as u64);
    let mut result = Vec::with_capacity(8 + bytes.len());
    result.extend_from_slice(&len);
    result.extend_from_slice(bytes);
    result
}

/// Encode an enum variant with explicit tag
pub fn encode_enum(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + value.len());
    result.push(tag);
    result.extend_from_slice(value);
    result
}

/// Encode protocol version
pub fn encode_version(major: u16, minor: u16, patch: u16) -> [u8; 6] {
    let mut result = [0u8; 6];
    result[0..2].copy_from_slice(&major.to_le_bytes());
    result[2..4].copy_from_slice(&minor.to_le_bytes());
    result[4..6].copy_from_slice(&patch.to_le_bytes());
    result
}
