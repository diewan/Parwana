//! Replay constitution for CSV protocol
//!
//! This module defines the replay protection constitution that ensures
//! sanads cannot be replayed across chains. All replay nullifiers
//! MUST be registered in the centralized replay registry.
//!
//! # Replay Constitution
//!
//! - Every sanad lock generates a unique replay nullifier
//! - Nullifiers are registered before minting on destination chain
//! - Nullifiers are domain-separated by source chain
//! - Nullifiers have expiry based on lease timeout
//! - Registry is centralized across all runtime instances

use serde::{Deserialize, Serialize};
use csv_hash::{Hash, ReplayIdHash, HashDomain};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Replay constitution version.
pub const REPLAY_CONSTITUTION_VERSION: u32 = 1;

/// Nullifier expiry time in seconds (default: 24 hours).
pub const NULLIFIER_EXPIRY_SECONDS: u64 = 86400;

/// Replay nullifier entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifier {
    /// Unique nullifier hash
    pub nullifier: Hash,
    /// Associated sanad ID
    pub sanad_id: Hash,
    /// Source chain ID
    pub source_chain: u8,
    /// Source seal reference (transaction hash or seal point)
    pub source_seal_ref: Hash,
    /// Registration timestamp (Unix epoch seconds)
    pub registered_at: u64,
    /// Expiry timestamp (Unix epoch seconds)
    pub expires_at: u64,
    /// Whether the nullifier has been consumed
    pub consumed: bool,
}

impl ReplayNullifier {
    /// Create a new replay nullifier.
    pub fn new(
        sanad_id: Hash,
        source_chain: u8,
        source_seal_ref: Hash,
    ) -> Self {
        let nullifier = Self::compute_nullifier(sanad_id, source_chain, source_seal_ref);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + NULLIFIER_EXPIRY_SECONDS;

        Self {
            nullifier,
            sanad_id,
            source_chain,
            source_seal_ref,
            registered_at: now,
            expires_at,
            consumed: false,
        }
    }

    /// Compute the nullifier hash from sanad ID, source chain, and seal reference.
    pub fn compute_nullifier(sanad_id: Hash, source_chain: u8, source_seal_ref: Hash) -> Hash {
        use csv_hash::tagged_hash::tagged_hash;
        
        let mut data = Vec::new();
        data.extend_from_slice(sanad_id.as_ref());
        data.push(source_chain);
        data.extend_from_slice(source_seal_ref.as_ref());
        
        tagged_hash(HashDomain::ReplayIdV1, &data).hash
    }

    /// Check if the nullifier has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if the nullifier is valid (not expired and not consumed).
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.consumed
    }
}

/// Centralized replay registry for all nullifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRegistry {
    /// Constitution version
    pub version: u32,
    /// Nullifiers indexed by nullifier hash
    pub nullifiers: BTreeMap<String, ReplayNullifier>,
    /// Nullifiers indexed by sanad ID (for lookup)
    pub by_sanad_id: BTreeMap<String, Vec<String>>,
    /// Nullifiers indexed by source chain (for cleanup)
    pub by_source_chain: BTreeMap<u8, Vec<String>>,
}

impl Default for ReplayRegistry {
    fn default() -> Self {
        Self {
            version: REPLAY_CONSTITUTION_VERSION,
            nullifiers: BTreeMap::new(),
            by_sanad_id: BTreeMap::new(),
            by_source_chain: BTreeMap::new(),
        }
    }
}

impl ReplayRegistry {
    /// Create a new replay registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a replay nullifier.
    pub fn register(&mut self, nullifier: ReplayNullifier) -> Result<(), ReplayError> {
        let nullifier_key: String = hex::encode(nullifier.nullifier.as_ref() as &[u8]);
        
        // Check if nullifier already exists
        if self.nullifiers.contains_key(&nullifier_key) {
            return Err(ReplayError::AlreadyRegistered);
        }

        // Add to nullifiers map
        self.nullifiers.insert(nullifier_key.clone(), nullifier.clone());

        // Add to sanad ID index
        let sanad_key: String = hex::encode(nullifier.sanad_id.as_ref() as &[u8]);
        self.by_sanad_id
            .entry(sanad_key)
            .or_insert_with(Vec::new)
            .push(nullifier_key.clone());

        // Add to source chain index
        self.by_source_chain
            .entry(nullifier.source_chain)
            .or_insert_with(Vec::new)
            .push(nullifier_key);

        Ok(())
    }

    /// Check if a nullifier is registered.
    pub fn is_registered(&self, nullifier: &Hash) -> bool {
        let nullifier_key: String = hex::encode(nullifier.as_ref() as &[u8]);
        self.nullifiers.contains_key(&nullifier_key)
    }

    /// Get a nullifier by hash.
    pub fn get(&self, nullifier: &Hash) -> Option<&ReplayNullifier> {
        let nullifier_key: String = hex::encode(nullifier.as_ref() as &[u8]);
        self.nullifiers.get(&nullifier_key)
    }

    /// Get all nullifiers for a sanad ID.
    pub fn get_by_sanad_id(&self, sanad_id: &Hash) -> Vec<&ReplayNullifier> {
        let sanad_key: String = hex::encode(sanad_id.as_ref() as &[u8]);
        self.by_sanad_id
            .get(&sanad_key)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.nullifiers.get(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all nullifiers for a source chain.
    pub fn get_by_source_chain(&self, source_chain: u8) -> Vec<&ReplayNullifier> {
        self.by_source_chain
            .get(&source_chain)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.nullifiers.get(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mark a nullifier as consumed.
    pub fn consume(&mut self, nullifier: &Hash) -> Result<(), ReplayError> {
        let nullifier_key: String = hex::encode(nullifier.as_ref() as &[u8]);
        if let Some(entry) = self.nullifiers.get_mut(&nullifier_key) {
            if entry.consumed {
                return Err(ReplayError::AlreadyConsumed);
            }
            entry.consumed = true;
            Ok(())
        } else {
            Err(ReplayError::NotFound)
        }
    }

    /// Clean up expired nullifiers.
    pub fn cleanup_expired(&mut self) -> usize {
        let mut to_remove = Vec::new();
        
        for (key, nullifier) in &self.nullifiers {
            if nullifier.is_expired() {
                to_remove.push(key.clone());
            }
        }

        for key in &to_remove {
            self.remove(key);
        }

        to_remove.len()
    }

    /// Remove a nullifier from the registry.
    fn remove(&mut self, nullifier_key: &str) {
        if let Some(nullifier) = self.nullifiers.remove(nullifier_key) {
            // Remove from sanad ID index
            let sanad_key: String = hex::encode(nullifier.sanad_id.as_ref() as &[u8]);
            if let Some(keys) = self.by_sanad_id.get_mut(&sanad_key) {
                keys.retain(|k| k != nullifier_key);
                if keys.is_empty() {
                    self.by_sanad_id.remove(&sanad_key);
                }
            }

            // Remove from source chain index
            if let Some(keys) = self.by_source_chain.get_mut(&nullifier.source_chain) {
                keys.retain(|k| k != nullifier_key);
                if keys.is_empty() {
                    self.by_source_chain.remove(&nullifier.source_chain);
                }
            }
        }
    }

    /// Get statistics about the registry.
    pub fn stats(&self) -> ReplayRegistryStats {
        let total = self.nullifiers.len() as u64;
        let consumed = self.nullifiers.values().filter(|n| n.consumed).count() as u64;
        let expired = self.nullifiers.values().filter(|n| n.is_expired()).count() as u64;
        let valid = total - consumed - expired;

        ReplayRegistryStats {
            total,
            consumed,
            expired,
            valid,
        }
    }
}

/// Replay registry statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRegistryStats {
    /// Total nullifiers
    pub total: u64,
    /// Consumed nullifiers
    pub consumed: u64,
    /// Expired nullifiers
    pub expired: u64,
    /// Valid (not consumed, not expired) nullifiers
    pub valid: u64,
}

/// Replay protection errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReplayError {
    #[error("Nullifier already registered")]
    AlreadyRegistered,

    #[error("Nullifier already consumed")]
    AlreadyConsumed,

    #[error("Nullifier not found")]
    NotFound,

    #[error("Nullifier expired")]
    Expired,

    #[error("Invalid nullifier")]
    InvalidNullifier,

    #[error("Registry error: {0}")]
    RegistryError(String),
}

/// Replay constitution validator.
pub struct ReplayConstitutionValidator;

impl ReplayConstitutionValidator {
    /// Validate that a replay nullifier follows the constitution.
    pub fn validate_nullifier(nullifier: &ReplayNullifier) -> Result<(), ReplayError> {
        // Check nullifier is not zero
        if nullifier.nullifier == Hash::zero() {
            return Err(ReplayError::InvalidNullifier);
        }

        // Check sanad ID is not zero
        if nullifier.sanad_id == Hash::zero() {
            return Err(ReplayError::InvalidNullifier);
        }

        // Check source chain is valid
        if nullifier.source_chain > 7 {
            return Err(ReplayError::InvalidNullifier);
        }

        // Check timestamps are valid
        if nullifier.registered_at >= nullifier.expires_at {
            return Err(ReplayError::InvalidNullifier);
        }

        // Check nullifier hash matches computed value
        let computed = ReplayNullifier::compute_nullifier(
            nullifier.sanad_id,
            nullifier.source_chain,
            nullifier.source_seal_ref,
        );
        if computed != nullifier.nullifier {
            return Err(ReplayError::InvalidNullifier);
        }

        Ok(())
    }

    /// Validate that a replay registry follows the constitution.
    pub fn validate_registry(registry: &ReplayRegistry) -> Result<(), ReplayError> {
        // Check version
        if registry.version != REPLAY_CONSTITUTION_VERSION {
            return Err(ReplayError::RegistryError(
                "Invalid constitution version".to_string(),
            ));
        }

        // Validate all nullifiers
        for nullifier in registry.nullifiers.values() {
            Self::validate_nullifier(nullifier)?;
        }

        // Check index consistency
        let mut total_indexed = 0;
        for keys in registry.by_sanad_id.values() {
            total_indexed += keys.len();
        }
        if total_indexed != registry.nullifiers.len() {
            return Err(ReplayError::RegistryError(
                "Sanad ID index inconsistent".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_nullifier_creation() {
        let sanad_id = Hash::sha256(b"test_sanad");
        let source_chain = 1;
        let source_seal_ref = Hash::sha256(b"test_seal");

        let nullifier = ReplayNullifier::new(sanad_id, source_chain, source_seal_ref);
        
        assert!(!nullifier.is_expired());
        assert!(nullifier.is_valid());
        assert_ne!(nullifier.nullifier, Hash::zero());
    }

    #[test]
    fn test_replay_registry() {
        let mut registry = ReplayRegistry::new();
        let nullifier = ReplayNullifier::new(
            Hash::sha256(b"test_sanad"),
            1,
            Hash::sha256(b"test_seal"),
        );

        registry.register(nullifier.clone()).unwrap();
        assert!(registry.is_registered(&nullifier.nullifier));
        
        let retrieved = registry.get(&nullifier.nullifier);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_nullifier_consumption() {
        let mut registry = ReplayRegistry::new();
        let nullifier = ReplayNullifier::new(
            Hash::sha256(b"test_sanad"),
            1,
            Hash::sha256(b"test_seal"),
        );

        registry.register(nullifier.clone()).unwrap();
        registry.consume(&nullifier.nullifier).unwrap();
        
        let retrieved = registry.get(&nullifier.nullifier).unwrap();
        assert!(retrieved.consumed);
    }

    #[test]
    fn test_replay_validator() {
        let nullifier = ReplayNullifier::new(
            Hash::sha256(b"test_sanad"),
            1,
            Hash::sha256(b"test_seal"),
        );

        assert!(ReplayConstitutionValidator::validate_nullifier(&nullifier).is_ok());
    }

    #[test]
    fn test_registry_stats() {
        let mut registry = ReplayRegistry::new();
        
        let nullifier1 = ReplayNullifier::new(
            Hash::sha256(b"test_sanad1"),
            1,
            Hash::sha256(b"test_seal1"),
        );
        let nullifier2 = ReplayNullifier::new(
            Hash::sha256(b"test_sanad2"),
            2,
            Hash::sha256(b"test_seal2"),
        );

        registry.register(nullifier1).unwrap();
        registry.register(nullifier2).unwrap();

        let stats = registry.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.valid, 2);
    }
}
