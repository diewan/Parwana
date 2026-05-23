//! Sanad identifier types

use serde::{Deserialize, Serialize};
use crate::Hash;

/// A unique Sanad identifier.
///
/// Computed as `H(commitment || salt)` to ensure uniqueness
/// even when the same state is committed to multiple times.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SanadId(pub Hash);

impl SanadId {
    /// Creates a new SanadId from a 32-byte hash.
    #[inline]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Creates a new SanadId from a byte slice.
    /// Panics if the slice is not exactly 32 bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let array: [u8; 32] = bytes
            .try_into()
            .expect("SanadId::from_bytes requires exactly 32 bytes");
        Self::new(array)
    }

    /// Returns the underlying hash bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanad_id_creation() {
        let hash = Hash::new([1u8; 32]);
        let sanad_id = SanadId(hash);
        assert_eq!(sanad_id.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_sanad_id_from_bytes() {
        let bytes = [2u8; 32];
        let sanad_id = SanadId::from_bytes(&bytes);
        assert_eq!(sanad_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_sanad_id_new() {
        let bytes = [3u8; 32];
        let sanad_id = SanadId::new(bytes);
        assert_eq!(sanad_id.as_bytes(), &bytes);
    }
}
