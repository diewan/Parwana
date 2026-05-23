//! Cross-Chain Seal Registry - SECURITY CRITICAL
//!
//! Tracks consumed seals across all chains to detect double-consumption
//! attempts, including cross-chain double-spends.
//!
//! ## Security Purpose
//!
//! This registry is the **primary defense against double-spending** in the CSV protocol.
//! When a Sanad is consumed, the seal that enforced it is recorded here.
//! Any subsequent attempt to consume the same seal will be detected and rejected.
//!
//! ## Chain-Specific Seal Types
//!
//! | Chain | Seal Type | Identifier | Single-Use Enforcement |
//! |-------|-----------|------------|------------------------|
//! | Bitcoin | UTXO spend | txid:vout | Structural (output consumed) |
//! | Sui | Object deletion | object_id:version | Structural (object deleted) |
//! | Aptos | Resource destruction | resource_address:account | Type-enforced (Move linearity) |
//! | Ethereum | Nullifier registration | nullifier_hash | Contract-enforced (registry) |
//! | Solana | PDA closure | pda_address | Program-enforced (account closed) |
//!
//! ## Cross-Chain Double-Spend Detection
//!
//! The registry maps all seal types to a unified `SealIdentity` that can
//! be compared across chains. This detects:
//! - Same seal used twice on the same chain
//! - Equivalent seals used on different chains (cross-chain double-spend)
//!
//! ## Security Invariants
//!
//! 1. **At-Most-Once Consumption**: Each seal may appear in `consumed_seals`
//!    at most once with status `Unconsumed`. Subsequent consumption attempts
//!    result in `DoubleSpent` status.
//!
//! 2. **Immutable History**: Once a consumption is recorded, it cannot be
//!    removed or altered. This provides an audit trail for forensic analysis.
//!
//! 3. **Chain-Agnostic Detection**: The registry treats seals from different
//!    chains with the same identity as conflicts, preventing cross-chain replays.
//!
//! ## Audit Checklist
//!
//! - [ ] `record_consumption()` correctly detects and records double-spends
//! - [ ] `check_seal_status()` returns accurate status for all seal types
//! - [ ] Registry state persists across application restarts
//! - [ ] No path exists to remove or modify recorded consumptions
//! - [ ] Cross-chain seal identity collisions are properly handled

use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::{DomainSeparatedHash, ReplayRegistryDomain};
use crate::Hash;
use crate::sanad::SanadId;
use crate::seal::SealPoint;
pub use crate::chain_id::ChainId;

/// A seal consumption event recording when and where a seal was used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealConsumption {
    /// Which chain enforced this consumption
    pub chain: ChainId,
    /// The seal reference (chain-specific format)
    pub seal_ref: SealPoint,
    /// The Sanad that was consumed
    pub sanad_id: SanadId,
    /// Block height when this was consumed
    pub block_height: u64,
    /// Transaction/operation hash that consumed this seal
    pub tx_hash: Hash,
    /// Timestamp (Unix epoch seconds) when this was recorded
    pub recorded_at: u64,
}

/// Result of checking if a seal has been consumed.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum SealStatus {
    /// Seal has not been consumed
    Unconsumed,
    /// Seal was consumed on a specific chain
    ConsumedOnChain {
        chain: ChainId,
        consumption: SealConsumption,
    },
    /// Seal was consumed on multiple chains (double-spend detected)
    DoubleSpent { consumptions: Vec<SealConsumption> },
}

/// Cross-chain seal registry - **Critical Security Component**.
///
/// Tracks all consumed seals across all chains and provides
/// double-consumption detection. This is the primary defense against
/// double-spending in the CSV protocol.
///
/// # Security Properties
///
/// 1. **Append-Only Log**: Consumption records are never deleted, providing
///    an immutable audit trail of all seal consumption events.
///
/// 2. **Deterministic Lookup**: Seal identity is derived from normalized
///    bytes, ensuring consistent lookup regardless of chain origin.
///
/// 3. **Cross-Chain Correlation**: The `sanad_consumption_map` enables
///    tracking all seals consumed by a specific Sanad across all chains.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe by default. In multi-threaded contexts,
/// external synchronization (Mutex/RwLock) is required.
///
/// # Audit Note
///
/// The `consumed_seals` map is the critical data structure. Its key is
/// `seal_ref.to_vec()` and its value is a vector of consumption events.
/// - Empty vector: No consumption recorded
/// - One entry: Valid single consumption
/// - Multiple entries: Double-spend detected (preserved for forensics)
#[derive(Default)]
pub struct SealNullifier {
    /// Map from seal identity to consumption events
    consumed_seals: BTreeMap<Vec<u8>, Vec<SealConsumption>>,
    /// Map from Sanad ID to seals that consumed it
    sanad_consumption_map: BTreeMap<Hash, Vec<SealConsumption>>,
    /// Set of known chain identifiers
    known_chains: BTreeSet<ChainId>,
}

impl SealNullifier {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a seal consumption event.
    ///
    /// This is the **primary double-spend prevention method**. It atomically:
    /// 1. Checks if the seal has been consumed before
    /// 2. If not, records the consumption and returns Ok
    /// 3. If yes, records the attempted double-spend and returns Err
    ///
    /// # Security Requirements (CRITICAL)
    /// - MUST check existing consumptions before recording
    /// - MUST record double-spend attempts for forensic analysis
    /// - MUST update both `consumed_seals` and `sanad_consumption_map`
    /// - MUST be atomic (no race conditions between check and record)
    ///
    /// # Returns
    /// - `Err(DoubleSpendError)` if the seal was already consumed
    ///   (the new consumption is still recorded for auditing purposes)
    ///
    /// # Audit Note
    /// The double-spend detection logic must be carefully verified:
    /// 1. The `is_double_spend` check uses `contains_key()` and checks if
    ///    the existing entry is non-empty
    /// 2. Even on double-spend, we record the attempt for forensics
    /// 3. The error includes details of both the original and new consumption
    ///
    /// # Security Impact
    /// A bug in this method could allow double-spending. Verify:
    /// - No TOCTOU (time-of-check-time-of-use) race conditions
    /// - Proper handling of all seal reference types
    /// - Immutable recording of all consumption events
    pub fn record_consumption(
        &mut self,
        consumption: SealConsumption,
    ) -> Result<(), Box<DoubleSpendError>> {
        let seal_key = consumption.seal_ref.to_canonical_bytes()
            .unwrap_or_else(|_| consumption.seal_ref.to_canonical_bytes().unwrap_or_default());
        let is_double_spend = self.consumed_seals.contains_key(&seal_key)
            && !self
                .consumed_seals
                .get(&seal_key)
                .is_none_or(|v| v.is_empty());

        // Track known chains
        self.known_chains.insert(consumption.chain.clone());

        // Check if already consumed
        if is_double_spend {
            let existing = self.consumed_seals.get(&seal_key).unwrap();
            let is_cross_chain = existing.iter().any(|e| e.chain != consumption.chain);

            let err = DoubleSpendError {
                seal_ref: consumption.seal_ref.clone(),
                existing_consumptions: existing.clone(),
                new_consumption: consumption.clone(),
                is_cross_chain,
            };

            // Still record for auditing purposes
            self.consumed_seals
                .entry(seal_key)
                .or_default()
                .push(consumption.clone());

            self.sanad_consumption_map
                .entry(consumption.sanad_id.0)
                .or_default()
                .push(consumption.clone());

            return Err(Box::new(err));
        }

        // Record the consumption
        self.consumed_seals
            .entry(seal_key)
            .or_default()
            .push(consumption.clone());

        // Track by Sanad ID
        self.sanad_consumption_map
            .entry(consumption.sanad_id.0)
            .or_default()
            .push(consumption.clone());

        Ok(())
    }

    /// Check the status of a seal.
    ///
    /// This method queries the registry to determine if a seal has been
    /// consumed and on which chain(s).
    ///
    /// # Security Requirements
    /// - MUST accurately report all recorded consumptions
    /// - MUST distinguish between `Unconsumed`, `ConsumedOnChain`, and `DoubleSpent`
    /// - MUST handle all seal reference types correctly
    ///
    /// # Returns
    /// - `SealStatus::Unconsumed` - Seal has never been recorded
    /// - `SealStatus::ConsumedOnChain` - Seal consumed exactly once
    /// - `SealStatus::DoubleSpent` - Seal consumed multiple times (attack detected)
    ///
    /// # Audit Note
    /// Verify this method correctly handles edge cases:
    /// - Empty seal references
    /// - Seals consumed on multiple different chains
    /// - Seals consumed multiple times on the same chain
    pub fn check_seal_status(&self, seal_ref: &SealPoint) -> SealStatus {
        let key = seal_ref.to_canonical_bytes().unwrap_or_default();

        match self.consumed_seals.get(&key) {
            None => SealStatus::Unconsumed,
            Some(consumptions) if consumptions.len() == 1 => {
                let c = &consumptions[0];
                SealStatus::ConsumedOnChain {
                    chain: c.chain.clone(),
                    consumption: c.clone(),
                }
            }
            Some(consumptions) => SealStatus::DoubleSpent {
                consumptions: consumptions.clone(),
            },
        }
    }

    /// Check if a seal has been consumed (anywhere).
    pub fn is_seal_consumed(&self, seal_ref: &SealPoint) -> bool {
        self.consumed_seals.contains_key(
            &seal_ref.to_canonical_bytes().unwrap_or_default()
        )
    }

    /// Get all consumption events for a specific seal.
    pub fn get_consumption_history(&self, seal_ref: &SealPoint) -> Vec<SealConsumption> {
        self.consumed_seals
            .get(&seal_ref.to_canonical_bytes().unwrap_or_default())
            .cloned()
            .unwrap_or_default()
    }

    /// Get all seals consumed by a specific Sanad.
    pub fn get_seals_for_sanad(&self, sanad_id: &SanadId) -> Vec<SealConsumption> {
        self.sanad_consumption_map
            .get(&sanad_id.0)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all known chains.
    pub fn known_chains(&self) -> Vec<&ChainId> {
        self.known_chains.iter().collect()
    }

    /// Get total number of unique seals tracked.
    pub fn total_seals(&self) -> usize {
        self.consumed_seals.len()
    }

    /// Get number of double-spend incidents detected.
    pub fn double_spend_count(&self) -> usize {
        self.consumed_seals
            .values()
            .filter(|consumptions| consumptions.len() > 1)
            .count()
    }
}

/// Error returned when a double-spend is detected.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct DoubleSpendError {
    /// The seal that was double-spent
    pub seal_ref: SealPoint,
    /// Existing consumption events
    pub existing_consumptions: Vec<SealConsumption>,
    /// The new consumption attempt
    pub new_consumption: SealConsumption,
    /// Whether this is a cross-chain double-spend
    pub is_cross_chain: bool,
}

impl core::fmt::Display for DoubleSpendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_cross_chain {
            write!(
                f,
                "Cross-chain double-spend detected for seal {:?}",
                self.seal_ref
            )
        } else {
            write!(f, "Same-chain replay detected for seal {:?}", self.seal_ref)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_consumption(chain: ChainId, seal_bytes: Vec<u8>, sanad_id: SanadId) -> SealConsumption {
        SealConsumption {
            chain,
            seal_ref: SealPoint::new(seal_bytes, None).unwrap(),
            sanad_id,
            block_height: 100,
            tx_hash: Hash::new([0xAB; 32]),
            recorded_at: 1_000_000,
        }
    }

    #[test]
    fn test_record_single_consumption() {
        let mut registry = SealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let consumption = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id);

        assert!(registry.record_consumption(consumption).is_ok());
        assert_eq!(registry.total_seals(), 1);
        assert_eq!(registry.double_spend_count(), 0);
    }

    #[test]
    fn test_detect_same_chain_replay() {
        let mut registry = SealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal_bytes = vec![0x01];

        let consumption1 = make_consumption(ChainId::new("bitcoin"), seal_bytes.clone(), sanad_id);
        registry.record_consumption(consumption1).unwrap();

        // Try to consume the same seal again on Bitcoin
        let sanad_id2 = SanadId(Hash::new([0xEF; 32]));
        let consumption2 = make_consumption(ChainId::new("bitcoin"), seal_bytes, sanad_id2);
        let result = registry.record_consumption(consumption2);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.is_cross_chain);
    }

    #[test]
    fn test_detect_cross_chain_double_spend() {
        let mut registry = SealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal_bytes = vec![0x01];

        // Consume on Bitcoin
        let consumption1 = make_consumption(
            ChainId::new("bitcoin"),
            seal_bytes.clone(),
            sanad_id.clone(),
        );
        registry.record_consumption(consumption1).unwrap();

        // Try to consume on Ethereum (cross-chain double-spend)
        let consumption2 = make_consumption(ChainId::new("ethereum"), seal_bytes, sanad_id);
        let result = registry.record_consumption(consumption2);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_cross_chain);
        assert_eq!(err.existing_consumptions.len(), 1);
    }

    #[test]
    fn test_seal_status_unconsumed() {
        let registry = SealNullifier::new();
        let seal = SealPoint::new(vec![0x01], None).unwrap();

        assert!(matches!(
            registry.check_seal_status(&seal),
            SealStatus::Unconsumed
        ));
    }

    #[test]
    fn test_seal_status_consumed() {
        let mut registry = SealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal = SealPoint::new(vec![0x01], None).unwrap();

        let consumption = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id);
        registry.record_consumption(consumption).unwrap();

        match registry.check_seal_status(&seal) {
            SealStatus::ConsumedOnChain { chain, .. } => {
                assert_eq!(chain, ChainId::new("bitcoin"));
            }
            _ => panic!("Expected ConsumedOnChain"),
        }
    }

    #[test]
    fn test_seal_status_double_spent() {
        let mut registry = SealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal = SealPoint::new(vec![0x01], None).unwrap();
        let seal_bytes = vec![0x01];

        // Consume on Bitcoin
        let c1 = make_consumption(
            ChainId::new("bitcoin"),
            seal_bytes.clone(),
            sanad_id.clone(),
        );
        registry.record_consumption(c1).unwrap();

        // Try to consume on Ethereum (will be recorded in history but flagged as double-spend)
        let c2 = make_consumption(ChainId::new("ethereum"), seal_bytes, sanad_id.clone());

        // Note: record_consumption returns error, but we can still check status
        let _ = registry.record_consumption(c2);

        assert!(matches!(
            registry.check_seal_status(&seal),
            SealStatus::DoubleSpent { .. }
        ));
    }

    #[test]
    fn test_known_chains() {
        let mut registry = SealNullifier::new();
        assert_eq!(registry.known_chains().len(), 0);

        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let c1 = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id.clone());
        registry.record_consumption(c1).unwrap();

        assert_eq!(registry.known_chains().len(), 1);
    }
}

/// Filter statistics for bloom filter operations.
#[derive(Debug, Clone)]
pub struct FilterStats {
    /// Number of bits in the filter
    pub bit_count: usize,
    /// Number of hash functions used
    pub hash_count: usize,
    /// Configured false positive rate
    pub false_positive_rate: f64,
}

/// Bloom filter for fast seal registry lookups.
#[cfg(feature = "std")]
pub struct BloomFilter {
    filter: bloomfilter::Bloom<[u8]>,
    capacity: usize,
    false_positive_rate: f64,
}

#[cfg(feature = "std")]
impl BloomFilter {
    /// Create a new bloom filter with specified capacity and false positive rate.
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let filter = bloomfilter::Bloom::new_for_fp_rate_with_seed(
            capacity,
            false_positive_rate,
            &[0u8; 32],
        )
        .expect(
            "Invalid bloom filter parameters: capacity must be > 0, fp_rate must be 0 < rate < 1",
        );
        Self {
            filter,
            capacity,
            false_positive_rate,
        }
    }

    /// Check if a hash might exist in the filter.
    pub fn might_contain(&self, hash: &Hash) -> bool {
        self.filter.check(hash.as_slice())
    }

    /// Add a hash to the filter.
    pub fn insert(&mut self, hash: &Hash) {
        self.filter.set(hash.as_slice());
    }

    /// Get filter statistics.
    pub fn stats(&self) -> FilterStats {
        FilterStats {
            bit_count: bloomfilter::Bloom::<[u8]>::compute_bitmap_size(
                self.capacity,
                self.false_positive_rate,
            ),
            hash_count: self.filter.number_of_hash_functions() as usize,
            false_positive_rate: self.false_positive_rate,
        }
    }
}

/// Optimized cross-chain seal registry with O(1) lookups using HashMap and Bloom filter.
///
/// This is a high-performance version of `SealNullifier` that provides:
/// - O(1) seal existence checks via bloom filter for negative lookups
/// - O(1) exact lookups via HashMap for consumed seals
/// - Configurable capacity for pre-allocated storage
///
/// Use this when performance is critical and you need to handle large numbers of seals.
#[cfg(feature = "std")]
pub struct OptimizedSealNullifier {
    /// Map from seal identity to consumption events (HashMap for O(1) lookups)
    consumed_seals: std::collections::HashMap<Vec<u8>, Vec<SealConsumption>>,
    /// Map from Sanad ID to seals that consumed it
    sanad_consumption_map: std::collections::HashMap<Hash, Vec<SealConsumption>>,
    /// Set of known chain identifiers
    known_chains: BTreeSet<ChainId>,
    /// Bloom filter for fast negative lookups
    bloom_filter: BloomFilter,
    /// Cache for recent seal status checks
    status_cache: std::collections::HashMap<Vec<u8>, SealStatus>,
    /// Maximum cache size for status cache
    max_cache_size: usize,
}

#[cfg(feature = "std")]
impl OptimizedSealNullifier {
    /// Create a new optimized registry with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(100_000, 0.01)
    }

    /// Create a new optimized registry with specified bloom filter capacity.
    ///
    /// # Arguments
    /// * `capacity` - Expected number of seals (for bloom filter sizing)
    /// * `false_positive_rate` - Acceptable false positive rate for bloom filter (0.0-1.0)
    pub fn with_capacity(capacity: usize, false_positive_rate: f64) -> Self {
        let capacity = capacity.max(100);
        let false_positive_rate = false_positive_rate.clamp(0.0001, 0.5);

        Self {
            consumed_seals: std::collections::HashMap::with_capacity(capacity),
            sanad_consumption_map: std::collections::HashMap::with_capacity(capacity),
            known_chains: BTreeSet::new(),
            bloom_filter: BloomFilter::new(capacity, false_positive_rate),
            status_cache: std::collections::HashMap::with_capacity(1000),
            max_cache_size: 1000,
        }
    }

    /// Record a seal consumption event with optimized O(1) checks.
    pub fn record_consumption(
        &mut self,
        consumption: SealConsumption,
    ) -> Result<(), Box<DoubleSpendError>> {
        let seal_key = consumption.seal_ref.to_vec();
        let seal_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(&seal_key);

        let might_exist = self.bloom_filter.might_contain(&seal_hash);

        let is_double_spend = if might_exist {
            self.consumed_seals.contains_key(&seal_key)
                && !self
                    .consumed_seals
                    .get(&seal_key)
                    .is_none_or(|v| v.is_empty())
        } else {
            false
        };

        self.known_chains.insert(consumption.chain.clone());

        self.bloom_filter.insert(&seal_hash);

        self.status_cache.remove(&seal_key);

        if is_double_spend {
            let existing = self.consumed_seals.get(&seal_key).unwrap();
            let is_cross_chain = existing.iter().any(|e| e.chain != consumption.chain);

            let err = DoubleSpendError {
                seal_ref: consumption.seal_ref.clone(),
                existing_consumptions: existing.clone(),
                new_consumption: consumption.clone(),
                is_cross_chain,
            };

            self.consumed_seals
                .entry(seal_key)
                .or_default()
                .push(consumption.clone());

            self.sanad_consumption_map
                .entry(consumption.sanad_id.0)
                .or_default()
                .push(consumption.clone());

            return Err(Box::new(err));
        }

        self.consumed_seals
            .entry(seal_key)
            .or_default()
            .push(consumption.clone());

        self.sanad_consumption_map
            .entry(consumption.sanad_id.0)
            .or_default()
            .push(consumption.clone());

        Ok(())
    }

    /// Check the status of a seal with bloom filter optimization.
    pub fn check_seal_status(&mut self, seal_ref: &SealPoint) -> SealStatus {
        let key = seal_ref.to_canonical_bytes()
            .unwrap_or_else(|_| seal_ref.to_vec());

        if let Some(cached) = self.status_cache.get(&key) {
            return cached.clone();
        }

        let seal_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(&key);

        if !self.bloom_filter.might_contain(&seal_hash) {
            let status = SealStatus::Unconsumed;
            self.cache_status(key, status.clone());
            return status;
        }

        let status = match self.consumed_seals.get(&key) {
            None => SealStatus::Unconsumed,
            Some(consumptions) if consumptions.len() == 1 => {
                let c = &consumptions[0];
                SealStatus::ConsumedOnChain {
                    chain: c.chain.clone(),
                    consumption: c.clone(),
                }
            }
            Some(consumptions) => SealStatus::DoubleSpent {
                consumptions: consumptions.clone(),
            },
        };

        self.cache_status(key, status.clone());
        status
    }

    /// Immutable version of check_seal_status (no caching).
    pub fn check_seal_status_immutable(&self, seal_ref: &SealPoint) -> SealStatus {
        let key = seal_ref.to_canonical_bytes().unwrap_or_default();
        let seal_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(&key);

        if !self.bloom_filter.might_contain(&seal_hash) {
            return SealStatus::Unconsumed;
        }

        match self.consumed_seals.get(&key) {
            None => SealStatus::Unconsumed,
            Some(consumptions) if consumptions.len() == 1 => {
                let c = &consumptions[0];
                SealStatus::ConsumedOnChain {
                    chain: c.chain.clone(),
                    consumption: c.clone(),
                }
            }
            Some(consumptions) => SealStatus::DoubleSpent {
                consumptions: consumptions.clone(),
            },
        }
    }

    /// Cache a status result.
    fn cache_status(&mut self, key: Vec<u8>, status: SealStatus) {
        if self.status_cache.len() >= self.max_cache_size {
            let keys_to_remove: Vec<_> = self
                .status_cache
                .keys()
                .take(self.max_cache_size / 2)
                .cloned()
                .collect();
            for k in keys_to_remove {
                self.status_cache.remove(&k);
            }
        }
        self.status_cache.insert(key, status);
    }

    /// Check if a seal has been consumed (anywhere) with O(1) bloom filter check.
    pub fn is_seal_consumed(&self, seal_ref: &SealPoint) -> bool {
        let seal_key = seal_ref.to_canonical_bytes()
            .unwrap_or_else(|_| seal_ref.to_vec());
        let seal_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(&seal_key);

        if !self.bloom_filter.might_contain(&seal_hash) {
            return false;
        }

        self.consumed_seals.contains_key(&seal_key)
    }

    /// Get all consumption events for a specific seal.
    pub fn get_consumption_history(&self, seal_ref: &SealPoint) -> Vec<SealConsumption> {
        let key = seal_ref.to_canonical_bytes()
            .unwrap_or_else(|_| seal_ref.to_vec());
        self.consumed_seals.get(&key).cloned().unwrap_or_default()
    }

    /// Get all seals consumed by a specific Sanad.
    pub fn get_seals_for_sanad(&self, sanad_id: &SanadId) -> Vec<SealConsumption> {
        self.sanad_consumption_map
            .get(&sanad_id.0)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all known chains.
    pub fn known_chains(&self) -> Vec<&ChainId> {
        self.known_chains.iter().collect()
    }

    /// Get total number of unique seals tracked.
    pub fn total_seals(&self) -> usize {
        self.consumed_seals.len()
    }

    /// Get number of double-spend incidents detected.
    pub fn double_spend_count(&self) -> usize {
        self.consumed_seals
            .values()
            .filter(|consumptions| consumptions.len() > 1)
            .count()
    }

    /// Get bloom filter statistics.
    pub fn bloom_stats(&self) -> FilterStats {
        self.bloom_filter.stats()
    }

    /// Clear the status cache.
    pub fn clear_cache(&mut self) {
        self.status_cache.clear();
    }

    /// Pre-populate the bloom filter from existing seals.
    pub fn rebuild_bloom_filter(&mut self) {
        let capacity = self.consumed_seals.len().max(1000);
        let mut new_filter = BloomFilter::new(capacity, 0.01);

        for key in self.consumed_seals.keys() {
            let seal_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(key);
            new_filter.insert(&seal_hash);
        }

        self.bloom_filter = new_filter;
    }
}

#[cfg(feature = "std")]
impl Default for OptimizedSealNullifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "std"))]
mod optimized_tests {
    use super::*;

    fn make_consumption(chain: ChainId, seal_bytes: Vec<u8>, sanad_id: SanadId) -> SealConsumption {
        SealConsumption {
            chain,
            seal_ref: SealPoint::new(seal_bytes, None).unwrap(),
            sanad_id,
            block_height: 100,
            tx_hash: Hash::new([0xAB; 32]),
            recorded_at: 1_000_000,
        }
    }

    #[test]
    fn test_optimized_registry_basic() {
        let mut registry = OptimizedSealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let consumption = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id);

        assert!(registry.record_consumption(consumption).is_ok());
        assert_eq!(registry.total_seals(), 1);
        assert_eq!(registry.double_spend_count(), 0);

        let stats = registry.bloom_stats();
        assert!(stats.bit_count > 0);
        assert!(stats.hash_count > 0);
    }

    #[test]
    fn test_optimized_registry_bloom_filter_negative_lookup() {
        let mut registry = OptimizedSealNullifier::new();
        let seal = SealPoint::new(vec![0x99], None).unwrap();

        let status = registry.check_seal_status(&seal);
        assert!(matches!(status, SealStatus::Unconsumed));

        let stats = registry.bloom_stats();
        assert!(stats.bit_count > 0);
    }

    #[test]
    fn test_optimized_registry_double_spend_detection() {
        let mut registry = OptimizedSealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal_bytes = vec![0x01];

        let c1 = make_consumption(
            ChainId::new("bitcoin"),
            seal_bytes.clone(),
            sanad_id.clone(),
        );
        registry.record_consumption(c1).unwrap();

        let c2 = make_consumption(
            ChainId::new("bitcoin"),
            seal_bytes.clone(),
            sanad_id.clone(),
        );
        let result = registry.record_consumption(c2);
        assert!(result.is_err());

        let c3 = make_consumption(ChainId::new("ethereum"), seal_bytes, sanad_id);
        let result = registry.record_consumption(c3);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_cross_chain);
    }

    #[test]
    fn test_optimized_registry_status_caching() {
        let mut registry = OptimizedSealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal = SealPoint::new(vec![0x01], None).unwrap();

        let _ = registry.check_seal_status(&seal);

        let c1 = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id);
        registry.record_consumption(c1).unwrap();

        let _ = registry.check_seal_status(&seal);

        registry.clear_cache();
    }

    #[test]
    fn test_optimized_registry_is_seal_consumed() {
        let mut registry = OptimizedSealNullifier::new();
        let sanad_id = SanadId(Hash::new([0xCD; 32]));
        let seal = SealPoint::new(vec![0x01], None).unwrap();

        assert!(!registry.is_seal_consumed(&seal));

        let c1 = make_consumption(ChainId::new("bitcoin"), vec![0x01], sanad_id);
        registry.record_consumption(c1).unwrap();

        assert!(registry.is_seal_consumed(&seal));
    }

    #[test]
    fn test_optimized_registry_rebuild_bloom_filter() {
        let mut registry = OptimizedSealNullifier::new();

        for i in 0..100u8 {
            let sanad_id = SanadId(Hash::new([i; 32]));
            let c = make_consumption(ChainId::new("bitcoin"), vec![i], sanad_id);
            registry.record_consumption(c).unwrap();
        }

        registry.rebuild_bloom_filter();

        for i in 0..100u8 {
            let seal = SealPoint::new(vec![i], None).unwrap();
            assert!(
                registry.is_seal_consumed(&seal),
                "Seal {} should be consumed",
                i
            );
        }

        let unconsumed = SealPoint::new(vec![0xFF], None).unwrap();
        assert!(!registry.is_seal_consumed(&unconsumed));
    }
}
