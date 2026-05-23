//! Byte ordering utilities
//!
//! This module provides byte ordering utilities for cross-chain compatibility.
//! CSV Protocol uses LITTLE ENDIAN exclusively for all protocol-critical data.

/// Convert to little-endian bytes
pub fn to_le_bytes<T: Into<u64>>(value: T) -> [u8; 8] {
    value.into().to_le_bytes()
}

/// Convert from little-endian bytes
pub fn from_le_bytes(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// Convert to little-endian bytes (32-bit)
pub fn to_le_bytes_32<T: Into<u32>>(value: T) -> [u8; 4] {
    value.into().to_le_bytes()
}

/// Convert from little-endian bytes (32-bit)
pub fn from_le_bytes_32(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}
