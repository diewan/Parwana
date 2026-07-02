//! Manual canonical encoding for L0/L1 types
//!
//! This module provides a unified encoding interface for types that cannot use serde.
//! Supports two encoding formats:
//! - MCE (Minimal Canonical Encoding): Fixed-width byte concatenation for on-chain use
//! - Manual Binary: Length-prefixed, little-endian encoding for off-chain use

use crate::error::{CodecError, Result as CodecResult};

/// Encoding format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingFormat {
    /// MCE (Minimal Canonical Encoding): Fixed-width byte concatenation
    /// Used for on-chain proof leaf hashing
    MCE,
    /// Manual Binary: Length-prefixed, little-endian encoding
    /// Used for off-chain serialization
    ManualBinary,
}

/// Canonical encoding trait for L0/L1 types
///
/// This trait provides a unified interface for manual canonical serialization,
/// supporting both MCE (for on-chain use) and manual binary (for off-chain use).
pub trait CanonicalEncoding {
    /// Encode to canonical bytes using the specified format
    fn encode(&self, format: EncodingFormat) -> CodecResult<Vec<u8>>;

    /// Decode from canonical bytes using the specified format
    fn decode(bytes: &[u8], format: EncodingFormat) -> CodecResult<Self>
    where
        Self: Sized;

    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> CodecResult<Vec<u8>> {
        self.encode(EncodingFormat::MCE)
    }

    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        Self::decode(bytes, EncodingFormat::MCE)
    }

    /// Encode using manual binary format (length-prefixed, little-endian)
    fn encode_manual(&self) -> CodecResult<Vec<u8>> {
        self.encode(EncodingFormat::ManualBinary)
    }

    /// Decode using manual binary format
    fn decode_manual(bytes: &[u8]) -> CodecResult<Self>
    where
        Self: Sized,
    {
        Self::decode(bytes, EncodingFormat::ManualBinary)
    }
}

/// Manual binary encoder helper
///
/// Provides helper methods for common encoding patterns in manual binary format.
pub struct ManualEncoder;

impl ManualEncoder {
    /// Encode u32 as little-endian bytes
    pub fn encode_u32_le(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    /// Encode u64 as little-endian bytes
    pub fn encode_u64_le(value: u64) -> [u8; 8] {
        value.to_le_bytes()
    }

    /// Encode bytes with length prefix (u32 little-endian)
    pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&Self::encode_u32_le(data.len() as u32));
        result.extend_from_slice(data);
        result
    }

    /// Encode optional bytes with length prefix (u32 little-endian)
    /// Uses 0u8 flag to indicate presence/absence
    pub fn encode_option_bytes(data: &Option<Vec<u8>>) -> Vec<u8> {
        match data {
            Some(bytes) => {
                let mut result = vec![1u8];
                result.extend_from_slice(&Self::encode_bytes(bytes));
                result
            }
            None => vec![0u8],
        }
    }

    /// Encode hash (32 bytes) - no length prefix needed
    pub fn encode_hash(hash: &[u8; 32]) -> Vec<u8> {
        hash.to_vec()
    }

    /// Decode u32 from little-endian bytes
    pub fn decode_u32_le(bytes: &[u8], pos: &mut usize) -> CodecResult<u32> {
        if bytes.len() < *pos + 4 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for u32".to_string(),
            ));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes[*pos..*pos + 4]);
        let value = u32::from_le_bytes(arr);
        *pos += 4;
        Ok(value)
    }

    /// Decode u64 from little-endian bytes
    pub fn decode_u64_le(bytes: &[u8], pos: &mut usize) -> CodecResult<u64> {
        if bytes.len() < *pos + 8 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for u64".to_string(),
            ));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*pos..*pos + 8]);
        let value = u64::from_le_bytes(arr);
        *pos += 8;
        Ok(value)
    }

    /// Decode bytes with length prefix
    pub fn decode_bytes(bytes: &[u8], pos: &mut usize) -> CodecResult<Vec<u8>> {
        let len = Self::decode_u32_le(bytes, pos)? as usize;
        if bytes.len() < *pos + len {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for data".to_string(),
            ));
        }
        let data = bytes[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(data)
    }

    /// Decode optional bytes with length prefix
    pub fn decode_option_bytes(bytes: &[u8], pos: &mut usize) -> CodecResult<Option<Vec<u8>>> {
        if bytes.len() < *pos + 1 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for option flag".to_string(),
            ));
        }
        let has_value = bytes[*pos] == 1;
        *pos += 1;

        if has_value {
            let data = Self::decode_bytes(bytes, pos)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Decode hash (32 bytes)
    pub fn decode_hash(bytes: &[u8], pos: &mut usize) -> CodecResult<[u8; 32]> {
        if bytes.len() < *pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for hash".to_string(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[*pos..*pos + 32]);
        *pos += 32;
        Ok(hash)
    }
}

/// MCE encoder helper
///
/// Provides helper methods for MCE (Minimal Canonical Encoding) format.
/// MCE uses fixed-width byte concatenation without length prefixes.
pub struct MCEEncoder;

impl MCEEncoder {
    /// Encode u32 as little-endian bytes (fixed-width)
    pub fn encode_u32_le(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    /// Encode u64 as little-endian bytes (fixed-width)
    pub fn encode_u64_le(value: u64) -> [u8; 8] {
        value.to_le_bytes()
    }

    /// Encode hash (32 bytes, fixed-width)
    pub fn encode_hash(hash: &[u8; 32]) -> Vec<u8> {
        hash.to_vec()
    }

    /// Encode fixed-width byte array
    pub fn encode_fixed_bytes<const N: usize>(data: &[u8; N]) -> Vec<u8> {
        data.to_vec()
    }

    /// Decode u32 from little-endian bytes
    pub fn decode_u32_le(bytes: &[u8], pos: &mut usize) -> CodecResult<u32> {
        if bytes.len() < *pos + 4 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for u32".to_string(),
            ));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes[*pos..*pos + 4]);
        let value = u32::from_le_bytes(arr);
        *pos += 4;
        Ok(value)
    }

    /// Decode u64 from little-endian bytes
    pub fn decode_u64_le(bytes: &[u8], pos: &mut usize) -> CodecResult<u64> {
        if bytes.len() < *pos + 8 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for u64".to_string(),
            ));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*pos..*pos + 8]);
        let value = u64::from_le_bytes(arr);
        *pos += 8;
        Ok(value)
    }

    /// Decode hash (32 bytes, fixed-width)
    pub fn decode_hash(bytes: &[u8], pos: &mut usize) -> CodecResult<[u8; 32]> {
        if bytes.len() < *pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for hash".to_string(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[*pos..*pos + 32]);
        *pos += 32;
        Ok(hash)
    }

    /// Decode fixed-width byte array
    pub fn decode_fixed_bytes<const N: usize>(
        bytes: &[u8],
        pos: &mut usize,
    ) -> CodecResult<[u8; N]> {
        if bytes.len() < *pos + N {
            return Err(CodecError::DeserializationError(format!(
                "Insufficient bytes for fixed-width array of {}",
                N
            )));
        }
        let mut data = [0u8; N];
        data.copy_from_slice(&bytes[*pos..*pos + N]);
        *pos += N;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_encoder_u32() {
        let value = 0x12345678u32;
        let encoded = ManualEncoder::encode_u32_le(value);
        assert_eq!(encoded, [0x78, 0x56, 0x34, 0x12]);

        let mut pos = 0;
        let decoded = ManualEncoder::decode_u32_le(&encoded, &mut pos).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_manual_encoder_bytes() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = ManualEncoder::encode_bytes(&data);
        assert_eq!(encoded, vec![0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]);

        let mut pos = 0;
        let decoded = ManualEncoder::decode_bytes(&encoded, &mut pos).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_manual_encoder_option_bytes() {
        let some_data = Some(vec![0x01, 0x02]);
        let encoded = ManualEncoder::encode_option_bytes(&some_data);
        assert_eq!(encoded, vec![1, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02]);

        let none_data: Option<Vec<u8>> = None;
        let encoded = ManualEncoder::encode_option_bytes(&none_data);
        assert_eq!(encoded, vec![0]);
    }

    #[test]
    fn test_mce_encoder_u32() {
        let value = 0x12345678u32;
        let encoded = MCEEncoder::encode_u32_le(value);
        assert_eq!(encoded, [0x78, 0x56, 0x34, 0x12]);

        let mut pos = 0;
        let decoded = MCEEncoder::decode_u32_le(&encoded, &mut pos).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_mce_encoder_hash() {
        let hash = [0xABu8; 32];
        let encoded = MCEEncoder::encode_hash(&hash);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, hash.to_vec());

        let mut pos = 0;
        let decoded = MCEEncoder::decode_hash(&encoded, &mut pos).unwrap();
        assert_eq!(decoded, hash);
    }
}
