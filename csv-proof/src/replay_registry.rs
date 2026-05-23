//! Replay registry stub module

use async_trait::async_trait;
use csv_hash::Hash;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as StdHash, Hasher};

/// Replay key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    /// Chain ID
    pub chain_id: String,
    /// Transfer ID
    pub transfer_id: Vec<u8>,
}

impl ReplayKey {
    /// Create new replay key
    pub fn new(chain_id: String, transfer_id: Vec<u8>) -> Self {
        Self {
            chain_id,
            transfer_id,
        }
    }

    /// Create new replay key with additional parameters
    pub fn new_with_params(
        chain_id: String,
        transfer_id: Vec<u8>,
        block_height: u64,
        timestamp: u64,
        seal_id: Hash,
    ) -> Self {
        Self {
            chain_id,
            transfer_id,
        }
    }

    /// Get hash of the replay key
    pub fn hash(&self) -> Hash {
        let mut hasher = DefaultHasher::new();
        self.chain_id.hash(&mut hasher);
        self.transfer_id.hash(&mut hasher);
        Hash::from([hasher.finish() as u8; 32])
    }
}

/// Replay registry backend trait
#[async_trait]
pub trait ReplayRegistryBackend: Send + Sync {
    /// Check if a replay key exists
    async fn contains(&self, key: &ReplayKey) -> Result<bool, String>;
    
    /// Insert a replay key
    async fn insert(&self, key: ReplayKey) -> Result<(), String>;
    
    /// Consume if unconsumed
    async fn consume_if_unconsumed(&self, key: &ReplayKey, timestamp: u64) -> Result<bool, String>;
}
