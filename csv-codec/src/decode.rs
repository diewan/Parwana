//! Canonical decoding primitives
//!
//! This module provides decoding functions that enforce canonical deserialization rules.

use crate::byte_order::{from_le_bytes, from_le_bytes_32};
use crate::error::CodecError;

/// Decode little-endian bytes as u64
pub fn decode_u64(bytes: &[u8]) -> Result<u64, CodecError> {
    if bytes.len() < 8 {
        return Err(CodecError::DeserializationError(
            "Insufficient bytes for u64".to_string(),
        ));
    }
    let arr: [u8; 8] = bytes[0..8].try_into().unwrap();
    Ok(from_le_bytes(arr))
}

/// Decode little-endian bytes as u32
pub fn decode_u32(bytes: &[u8]) -> Result<u32, CodecError> {
    if bytes.len() < 4 {
        return Err(CodecError::DeserializationError(
            "Insufficient bytes for u32".to_string(),
        ));
    }
    let arr: [u8; 4] = bytes[0..4].try_into().unwrap();
    Ok(from_le_bytes_32(arr))
}

/// Decode canonical UTF-8 bytes as string
pub fn decode_string(bytes: &[u8]) -> Result<String, CodecError> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| CodecError::DeserializationError(format!("Invalid UTF-8: {}", e)))
}

/// Decode a vector with explicit length prefix (little-endian)
pub fn decode_vec(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    if bytes.len() < 8 {
        return Err(CodecError::DeserializationError(
            "Insufficient bytes for length prefix".to_string(),
        ));
    }
    let len = decode_u64(bytes)? as usize;
    if bytes.len() < 8 + len {
        return Err(CodecError::DeserializationError(
            "Insufficient bytes for vector data".to_string(),
        ));
    }
    Ok(bytes[8..8 + len].to_vec())
}

/// Decode an enum variant with explicit tag
pub fn decode_enum(bytes: &[u8]) -> Result<(u8, Vec<u8>), CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::DeserializationError(
            "Empty bytes for enum".to_string(),
        ));
    }
    Ok((bytes[0], bytes[1..].to_vec()))
}

/// Decode protocol version
pub fn decode_version(bytes: &[u8]) -> Result<(u16, u16, u16), CodecError> {
    if bytes.len() < 6 {
        return Err(CodecError::DeserializationError(
            "Insufficient bytes for version".to_string(),
        ));
    }
    let major = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    let minor = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
    let patch = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    Ok((major, minor, patch))
}
