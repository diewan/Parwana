//! Canonical encoding primitives
//!
//! This module provides encoding functions that enforce canonical serialization rules.

use crate::byte_order::{to_le_bytes, to_le_bytes_32};
use unicode_normalization::UnicodeNormalization;

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
    value.nfc().collect::<String>().into_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_string_nfc_normalization() {
        // Test that canonically equivalent strings produce the same encoding
        // "é" can be represented as single codepoint (U+00E9) or as "e" + combining acute (U+0065 U+0301)
        let composed = "é"; // U+00E9 (composed form)
        let decomposed = "e\u{0301}"; // U+0065 U+0301 (decomposed form)

        let composed_bytes = encode_string(composed);
        let decomposed_bytes = encode_string(decomposed);

        // Both should normalize to NFC (composed form) and produce identical bytes
        assert_eq!(composed_bytes, decomposed_bytes);
    }

    #[test]
    fn test_encode_string_nfc_already_normalized() {
        // String already in NFC form should remain unchanged
        let already_nfc = "café";
        let bytes = encode_string(already_nfc);

        // Should be the NFC normalized bytes
        assert_eq!(bytes, "café".nfc().collect::<String>().into_bytes());
    }

    #[test]
    fn test_encode_string_ascii() {
        // ASCII strings should pass through unchanged
        let ascii = "hello world";
        let bytes = encode_string(ascii);

        assert_eq!(bytes, ascii.as_bytes());
    }

    #[test]
    fn test_encode_string_multiple_combining_marks() {
        // Test with multiple combining marks
        // "ñ" can be composed (U+00F1) or decomposed (U+006E U+0303)
        let composed = "ñ";
        let decomposed = "n\u{0303}";

        let composed_bytes = encode_string(composed);
        let decomposed_bytes = encode_string(decomposed);

        assert_eq!(composed_bytes, decomposed_bytes);
    }

    #[test]
    fn test_encode_string_mixed_normalization() {
        // Test a string with mixed normalization forms
        // "café" with decomposed "é"
        let mixed = "cafe\u{0301}";
        let composed = "café";

        let mixed_bytes = encode_string(mixed);
        let composed_bytes = encode_string(composed);

        assert_eq!(mixed_bytes, composed_bytes);
    }
}
