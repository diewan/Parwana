//! Sanad identifier types

use crate::Hash;

/// A unique Sanad identifier.
///
/// Computed as `H(commitment || salt)` to ensure uniqueness
/// even when the same state is committed to multiple times.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SanadId(pub Hash);

impl SanadId {
    /// Creates a new SanadId from a 32-byte hash.
    #[inline]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Creates a new SanadId from a byte slice.
    ///
    /// Exact 32-byte inputs are used directly. Other lengths are hashed into a
    /// canonical 32-byte identifier.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 32 {
            return Self(Hash::sha256(bytes));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
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
