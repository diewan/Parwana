//! Chain identifier type

/// A chain identifier.
///
/// For the 100-chain goal, chain IDs are plain strings. This type is a thin
/// newtype over `String` that provides ergonomic comparison, display, and
/// serialization.
///
/// ### Adding a new chain
///
/// 1. Create a new `csv-{chain}` crate implementing `ChainBackend`
/// 2. The chain ID is specified in the chain's configuration file
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainId(pub String);

impl ChainId {
    /// Create a new ChainId from a string.
    pub fn new(id: &str) -> Self {
        Self(id.to_lowercase())
    }

    /// Get the raw chain ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the chain ID as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Convert to owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ChainId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Err(())
        } else {
            Ok(Self(s.to_lowercase()))
        }
    }
}

impl AsRef<str> for ChainId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ChainId {
    fn from(s: &str) -> Self {
        Self(s.to_lowercase())
    }
}

impl From<String> for ChainId {
    fn from(s: String) -> Self {
        Self(s.to_lowercase())
    }
}

impl PartialEq<&str> for ChainId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ChainId> for &str {
    fn eq(&self, other: &ChainId) -> bool {
        *self == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_creation() {
        let chain_id = ChainId::new("Bitcoin");
        assert_eq!(chain_id.as_str(), "bitcoin");
    }

    #[test]
    fn test_chain_id_case_insensitive() {
        let chain_id = ChainId::new("BITCOIN");
        assert_eq!(chain_id.as_str(), "bitcoin");
    }

    #[test]
    fn test_chain_id_from_str() {
        let chain_id: ChainId = "ethereum".parse().unwrap();
        assert_eq!(chain_id.as_str(), "ethereum");
    }

    #[test]
    fn test_chain_id_empty_rejected() {
        let result: Result<ChainId, ()> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_id_display() {
        let chain_id = ChainId::new("solana");
        assert_eq!(format!("{}", chain_id), "solana");
    }

    #[test]
    fn test_chain_id_eq_str() {
        let chain_id = ChainId::new("aptos");
        assert_eq!(chain_id, "aptos");
        assert_eq!("aptos", chain_id);
    }
}
