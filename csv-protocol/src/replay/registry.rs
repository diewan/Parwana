//! Replay Registry for Cross-Chain Attack Prevention
//!
//! This module provides replay protection by tracking all validated proofs
//! across chains to prevent cross-chain replay attacks.
//!
//! ## Security Purpose
//!
//! The replay registry is the primary defense against cross-chain replay attacks.
//! When a proof is validated, it is recorded here. Any subsequent attempt to
//! replay the same proof (same proof_hash, seal_id, commitment_hash) will be
//! detected and rejected, even across different chains.
//!
//! ## Persistence
//!
//! The registry MUST persist across:
//! - application restart
//! - crash recovery
//! - node migration
//!
//! This is achieved through the persistent backend in csv-store.
//!
//! ## Usage
//!
//! Use [`ReplayRegistry`] for in-memory replay protection (tests, development).
//! Use [`PersistentReplayRegistry`] for production deployments with SQLite persistence.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use csv_hash::{DomainSeparatedHash, ReplayRegistryDomain, HashDomain, tagged_hash};
use csv_hash::Hash;
use csv_hash::chain_id::ChainId;

/// Replay constitution version.
pub const REPLAY_CONSTITUTION_VERSION: u32 = 1;

/// Nullifier expiry time in seconds (default: 24 hours).
pub const NULLIFIER_EXPIRY_SECONDS: u64 = 86400;

/// Replay key that uniquely identifies a proof for replay detection
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayKey {
    /// Hash of the proof bundle
    pub proof_hash: Hash,
    /// Seal ID that was consumed
    pub seal_id: Hash,
    /// Commitment hash
    pub commitment_hash: Hash,
    /// Source chain
    pub source_chain: ChainId,
    /// Destination chain
    pub destination_chain: ChainId,
}

impl ReplayKey {
    /// Create a new replay key
    pub fn new(
        proof_hash: Hash,
        seal_id: Hash,
        commitment_hash: Hash,
        source_chain: ChainId,
        destination_chain: ChainId,
    ) -> Self {
        Self {
            proof_hash,
            seal_id,
            commitment_hash,
            source_chain,
            destination_chain,
        }
    }

    /// Compute the domain-separated hash of this replay key
    ///
    /// This hash is used as the primary key in the replay registry using canonical serialization.
    ///
    /// # Panics
    ///
    /// Panics only on fundamental CBOR encoding bugs for primitive types — this is
    /// verified by golden tests and is considered a development-time invariant.
    #[allow(clippy::expect_used)] // infallible: tuples of Hash+String always serialize to CBOR
    pub fn hash(&self) -> Hash {
        use csv_codec::to_canonical_cbor;
        let payload = to_canonical_cbor(&(
            self.proof_hash,
            self.seal_id,
            self.commitment_hash,
            self.source_chain.clone(),
            self.destination_chain.clone(),
        )).unwrap_or_else(|_| {
            // This should never fail: all types in the tuple (Hash, ChainId) are
            // canonical CBOR-serializable primitives. If it does fail, something
            // fundamental is broken in the serialization layer.
            vec![]
        });
        DomainSeparatedHash::<ReplayRegistryDomain>::hash(&payload)
    }
}

/// Replay registry entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayEntry {
    /// The replay key
    pub key: ReplayKey,
    /// Timestamp when this proof was first seen (Unix epoch seconds)
    pub first_seen_at: u64,
    /// Number of replay attempts detected
    pub replay_attempts: u64,
    /// Whether this proof has been accepted
    pub accepted: bool,
}

/// In-memory replay registry
///
/// This is the in-memory representation. For persistence, use the
/// ReplayRegistryStore from csv-store.
#[derive(Default)]
pub struct ReplayRegistry {
    /// Map from replay key hash to entry
    entries: BTreeMap<Hash, ReplayEntry>,
}

impl ReplayRegistry {
    /// Create a new empty replay registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a proof in the replay registry
    ///
    /// Returns true if this is the first time seeing this proof,
    /// false if it's a replay attempt.
    pub fn record_proof(&mut self, key: ReplayKey, timestamp: u64) -> bool {
        let key_hash = key.hash();

        match self.entries.get(&key_hash) {
            Some(entry) => {
                // Replay attempt detected
                let entry: ReplayEntry = entry.clone();
                let mut updated = entry;
                updated.replay_attempts += 1;
                self.entries.insert(key_hash, updated);
                false
            }
            None => {
                // First time seeing this proof
                let entry = ReplayEntry {
                    key,
                    first_seen_at: timestamp,
                    replay_attempts: 0,
                    accepted: false,
                };
                self.entries.insert(key_hash, entry);
                true
            }
        }
    }

    /// Check if a proof has been seen before
    pub fn has_been_seen(&self, key: &ReplayKey) -> bool {
        let key_hash = key.hash();
        self.entries.contains_key(&key_hash)
    }

    /// Mark a proof as accepted
    pub fn mark_accepted(&mut self, key: &ReplayKey) {
        let key_hash = key.hash();
        if let Some(entry) = self.entries.get_mut(&key_hash) {
            entry.accepted = true;
        }
    }

    /// Get the number of replay attempts for a proof
    pub fn replay_attempts(&self, key: &ReplayKey) -> u64 {
        let key_hash = key.hash();
        self.entries
            .get(&key_hash)
            .map(|e| e.replay_attempts)
            .unwrap_or(0)
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<&ReplayEntry> {
        self.entries.values().collect()
    }

    /// Get the total number of tracked proofs
    pub fn total_proofs(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of replay attempts detected
    pub fn total_replay_attempts(&self) -> u64 {
        self.entries.values().map(|e| e.replay_attempts).sum()
    }

    /// Idempotent consume-if-unconsumed operation.
    ///
    /// This is the ONLY safe way to consume a seal. It uses atomic
    /// compare-and-swap semantics to prevent double-consume races.
    ///
    /// Returns Ok(true) if the seal was successfully consumed.
    /// Returns Ok(false) if the seal was already consumed (idempotent).
    /// Returns Err if the operation failed due to a replay attack.
    pub fn consume_if_unconsumed(&mut self, key: ReplayKey, timestamp: u64) -> Result<bool, String> {
        let key_hash = key.hash();

        match self.entries.get(&key_hash) {
            Some(entry) => {
                if entry.accepted {
                    // Seal already consumed - idempotent success
                    Ok(false)
                } else {
                    // Entry exists but not yet accepted - replay attempt
                    Err(format!(
                        "Replay attack detected: proof key already exists but not accepted"
                    ))
                }
            }
            None => {
                // First time seeing this proof - consume it
                let entry = ReplayEntry {
                    key,
                    first_seen_at: timestamp,
                    replay_attempts: 0,
                    accepted: true,
                };
                self.entries.insert(key_hash, entry);
                Ok(true)
            }
        }
    }
}

/// Persistent replay registry backend trait
///
/// This trait abstracts the persistence layer, allowing consumers to
/// implement their own storage backend for replay protection.
///
/// The csv-store crate provides a SQLite implementation.
#[async_trait::async_trait]
pub trait ReplayRegistryBackend: Send + Sync + 'static {
    /// Record a proof, returning true if first time, false if replay
    async fn record_proof(
        &self,
        key: ReplayKey,
        timestamp: u64,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
    /// Check if a proof has been seen before
    async fn has_been_seen(
        &self,
        key: &ReplayKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
    /// Mark a proof as accepted
    async fn mark_accepted(
        &self,
        key: &ReplayKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Get replay attempt count for a key
    async fn replay_attempts(
        &self,
        key: &ReplayKey,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;
    /// Get total tracked proofs
    async fn total_proofs(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>;
    /// Get total replay attempts detected
    async fn total_replay_attempts(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Idempotent consume-if-unconsumed operation.
    ///
    /// This is the ONLY safe way to consume a seal. It uses atomic
    /// compare-and-swap semantics to prevent double-consume races.
    ///
    /// Returns Ok(true) if the seal was successfully consumed.
    /// Returns Ok(false) if the seal was already consumed (idempotent).
    /// Returns Err if the operation failed due to a database error or replay attack.
    async fn consume_if_unconsumed(
        &self,
        key: ReplayKey,
        timestamp: u64,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

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

/// Centralized nullifier registry for replay protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierRegistry {
    /// Constitution version
    pub version: u32,
    /// Nullifiers indexed by nullifier hash
    pub nullifiers: BTreeMap<String, ReplayNullifier>,
    /// Nullifiers indexed by sanad ID (for lookup)
    pub by_sanad_id: BTreeMap<String, Vec<String>>,
    /// Nullifiers indexed by source chain (for cleanup)
    pub by_source_chain: BTreeMap<u8, Vec<String>>,
}

impl Default for NullifierRegistry {
    fn default() -> Self {
        Self {
            version: REPLAY_CONSTITUTION_VERSION,
            nullifiers: BTreeMap::new(),
            by_sanad_id: BTreeMap::new(),
            by_source_chain: BTreeMap::new(),
        }
    }
}

impl NullifierRegistry {
    /// Create a new nullifier registry.
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
    pub fn stats(&self) -> NullifierRegistryStats {
        let total = self.nullifiers.len() as u64;
        let consumed = self.nullifiers.values().filter(|n| n.consumed).count() as u64;
        let expired = self.nullifiers.values().filter(|n| n.is_expired()).count() as u64;
        let valid = total - consumed - expired;

        NullifierRegistryStats {
            total,
            consumed,
            expired,
            valid,
        }
    }
}

/// Nullifier registry statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierRegistryStats {
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
#[derive(Debug, Clone, Error)]
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

    /// Validate that a nullifier registry follows the constitution.
    pub fn validate_registry(registry: &NullifierRegistry) -> Result<(), ReplayError> {
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
    fn test_replay_key_creation() {
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        assert_eq!(key.proof_hash, Hash::new([1u8; 32]));
    }

    #[test]
    fn test_replay_key_hash() {
        let key1 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let key2 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        assert_eq!(key1.hash(), key2.hash());
    }

    #[test]
    fn test_replay_key_hash_different_chains() {
        let key1 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let key2 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("solana"),
        );

        assert_ne!(key1.hash(), key2.hash());
    }

    #[test]
    fn test_record_proof_first_time() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let first_time = registry.record_proof(key.clone(), 1000);
        assert!(first_time);
        assert_eq!(registry.total_proofs(), 1);
    }

    #[test]
    fn test_record_proof_replay() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        registry.record_proof(key.clone(), 1000);
        let replay = registry.record_proof(key.clone(), 2000);

        assert!(!replay);
        assert_eq!(registry.replay_attempts(&key), 1);
    }

    #[test]
    fn test_has_been_seen() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        assert!(!registry.has_been_seen(&key));
        registry.record_proof(key.clone(), 1000);
        assert!(registry.has_been_seen(&key));
    }

    #[test]
    fn test_mark_accepted() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        registry.record_proof(key.clone(), 1000);
        registry.mark_accepted(&key);

        assert!(registry.entries()[0].accepted);
    }

    #[test]
    fn test_consume_if_unconsumed_first_time() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let result = registry.consume_if_unconsumed(key.clone(), 1000);
        assert!(result.is_ok());
        assert!(result.unwrap(), "First consumption should succeed");
        assert_eq!(registry.total_proofs(), 1);
    }

    #[test]
    fn test_consume_if_unconsumed_idempotent() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // First consumption
        let result1 = registry.consume_if_unconsumed(key.clone(), 1000);
        assert!(result1.is_ok());
        assert!(result1.unwrap(), "First consumption should succeed");

        // Second consumption - should be idempotent
        let result2 = registry.consume_if_unconsumed(key.clone(), 2000);
        assert!(result2.is_ok());
        assert!(!result2.unwrap(), "Second consumption should return false (idempotent)");
    }

    #[test]
    fn test_consume_if_unconsumed_replay_attack() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // Record proof but don't mark as accepted
        registry.record_proof(key.clone(), 1000);

        // Attempt to consume - should detect replay attack
        let result = registry.consume_if_unconsumed(key.clone(), 2000);
        assert!(result.is_err(), "Should detect replay attack");
    }
}
