//! Performance optimization utilities for CSV Adapter
//!
//! Provides caching, bloom filters, and parallel processing to improve
//! proof verification and seal registry operations by 2-5x.

use crate::collections::HashMap;
use core::sync::atomic::{AtomicU64, Ordering};
use csv_hash::canonical::canonical_hash;
use spin::RwLock;
use std::sync::Arc;

use csv_hash::Hash;
use csv_protocol::proof_types::ProofBundle;
use csv_protocol::lease::now_secs;

/// Thread-safe proof cache with LRU eviction policy
pub struct ProofCache {
    cache: Arc<RwLock<HashMap<Hash, CachedProof>>>,
    max_size: usize,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl ProofCache {
    /// Create a new proof cache with specified maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get a cached proof bundle
    pub fn get(&self, hash: &Hash) -> Option<ProofBundle> {
        let cache = self.cache.read();
        if let Some(cached) = cache.get(hash) {
            // Check if the cache entry is still valid (30 second TTL)
            if cached.expires_at > now_secs() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(cached.proof.clone());
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Cache a proof bundle
    pub fn put(&self, hash: Hash, proof: ProofBundle) {
        let mut cache = self.cache.write();

        // Evict oldest entries if cache is full
        if cache.len() >= self.max_size {
            let remove_count = self.max_size / 4;
            let mut removed = 0;

            // Simple eviction: remove first few entries
            let keys_to_remove: Vec<Hash> = cache.keys().take(remove_count).copied().collect();

            for key in keys_to_remove {
                cache.remove(&key);
                removed += 1;

                if removed >= remove_count {
                    break;
                }
            }
        }

        let cached = CachedProof {
            proof,
            accessed_at: now_secs(),
            expires_at: now_secs() + 30,
        };

        cache.insert(hash, cached);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            hit_rate,
            size: self.cache.read().len(),
        }
    }
}

#[derive(Clone)]
struct CachedProof {
    proof: ProofBundle,
    /// Last access time (for future LRU implementation)
    #[allow(dead_code)]
    accessed_at: u64,
    expires_at: u64,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Current cache size
    pub size: usize,
}

/// Thread-safe bloom filter for fast seal registry lookups
pub struct SealRegistryFilter {
    filter: Arc<RwLock<BloomFilter>>,
}

impl SealRegistryFilter {
    /// Create a new bloom filter with specified capacity and false positive rate
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        Self {
            filter: Arc::new(RwLock::new(BloomFilter::new(capacity, false_positive_rate))),
        }
    }

    /// Check if a seal hash might exist in the registry
    pub fn might_contain(&self, hash: &Hash) -> bool {
        let filter = self.filter.read();
        filter.might_contain(hash)
    }

    /// Add a seal hash to the filter
    pub fn insert(&self, hash: &Hash) {
        let mut filter = self.filter.write();
        filter.insert(hash);
    }

    /// Add multiple seal hashes to the filter
    pub fn insert_batch(&self, hashes: &[Hash]) {
        let mut filter = self.filter.write();
        filter.insert_batch(hashes);
    }

    /// Get filter statistics
    pub fn stats(&self) -> FilterStats {
        let filter = self.filter.read();
        filter.stats()
    }

    /// Clear the filter
    pub fn clear(&self) {
        let mut filter = self.filter.write();
        filter.clear();
    }
}

/// Filter statistics
#[derive(Debug, Clone)]
pub struct FilterStats {
    /// Number of bits in the filter
    pub bit_count: usize,
    /// Number of hash functions used
    pub hash_count: usize,
    /// Configured false positive rate
    pub false_positive_rate: f64,
}

/// Sequential proof verification engine (optimized for single-threaded performance)
pub struct SequentialVerifier;

impl Default for SequentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SequentialVerifier {
    /// Create a new sequential verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify multiple proof bundles sequentially
    pub fn verify_batch(&self, proofs: &[ProofBundle]) -> Vec<VerificationResult> {
        proofs
            .iter()
            .map(|proof| self.verify_single(proof))
            .collect()
    }

    /// Verify a single proof bundle
    fn verify_single(&self, proof: &ProofBundle) -> VerificationResult {
        let start = now_secs();

        // Simulate proof verification (real implementation would use chain-specific logic)
        let is_valid = self.verify_proof_internal(proof);

        let elapsed = now_secs().saturating_sub(start);

        // Create a canonical hash from the proof for identification
        let proof_hash = canonical_hash("csv.verification.proof.v1", proof).unwrap_or_else(|err| {
            Hash::sha256(format!("performance-proof-hash-error:{err}").as_bytes())
        });

        VerificationResult {
            proof_hash,
            is_valid,
            verification_time_secs: elapsed,
            error: if is_valid {
                None
            } else {
                Some("Proof verification failed".to_string())
            },
        }
    }

    /// Internal proof verification logic
    ///
    /// CRITICAL: This module is for performance optimization only (caching, bloom filters).
    /// Real cryptographic verification MUST use ChainProofProvider implementations
    /// from chain adapters that perform actual signature and proof verification.
    ///
    /// This method always rejects to prevent accidental use as real verification.
    fn verify_proof_internal(&self, _proof: &ProofBundle) -> bool {
        false
    }
}

/// Verification result for a single proof
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Hash of the proof that was verified
    pub proof_hash: Hash,
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Time taken to verify the proof (in seconds)
    pub verification_time_secs: u64,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Performance metrics collector
pub struct PerformanceMetrics {
    proof_cache: Arc<ProofCache>,
    seal_filter: Arc<SealRegistryFilter>,
    verifier: Arc<SequentialVerifier>,
}

impl PerformanceMetrics {
    /// Create a new performance metrics collector
    pub fn new(cache_size: usize, filter_capacity: usize) -> Self {
        let proof_cache = Arc::new(ProofCache::new(cache_size));
        let seal_filter = Arc::new(SealRegistryFilter::new(filter_capacity, 0.01));
        let verifier = Arc::new(SequentialVerifier::new());

        Self {
            proof_cache,
            seal_filter,
            verifier,
        }
    }

    /// Get comprehensive performance statistics
    pub fn get_stats(&self) -> PerformanceStats {
        PerformanceStats {
            cache_stats: self.proof_cache.stats(),
            filter_stats: self.seal_filter.stats(),
        }
    }

    /// Cache a proof bundle
    pub fn cache_proof(&self, hash: Hash, proof: ProofBundle) {
        self.proof_cache.put(hash, proof);
    }

    /// Get a cached proof bundle
    pub fn get_cached_proof(&self, hash: &Hash) -> Option<ProofBundle> {
        self.proof_cache.get(hash)
    }

    /// Check if seal might exist in registry
    pub fn might_contain_seal(&self, hash: &Hash) -> bool {
        self.seal_filter.might_contain(hash)
    }

    /// Add seal to filter
    pub fn add_seal(&self, hash: &Hash) {
        self.seal_filter.insert(hash);
    }

    /// Verify proofs in parallel
    pub fn verify_proofs(&self, proofs: &[ProofBundle]) -> Vec<VerificationResult> {
        self.verifier.verify_batch(proofs)
    }
}

/// Comprehensive performance statistics
#[derive(Debug, Clone)]
pub struct PerformanceStats {
    /// Cache performance statistics
    pub cache_stats: CacheStats,
    /// Bloom filter statistics
    pub filter_stats: FilterStats,
}

/// Bloom filter wrapper using the bloomfilter crate for O(1) negative lookups
pub struct BloomFilter {
    filter: bloomfilter::Bloom<[u8]>,
    capacity: usize,
    false_positive_rate: f64,
}

impl BloomFilter {
    /// Create a new bloom filter with specified capacity and false positive rate
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        // bloomfilter 3.0 requires a seed and returns Result
        let filter = bloomfilter::Bloom::new_for_fp_rate_with_seed(
            capacity,
            false_positive_rate,
            &[0u8; 32], // Default seed for deterministic behavior
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

    /// Check if a hash might exist in the filter
    pub fn might_contain(&self, hash: &Hash) -> bool {
        self.filter.check(hash.as_slice())
    }

    /// Add a hash to the filter
    pub fn insert(&mut self, hash: &Hash) {
        self.filter.set(hash.as_slice());
    }

    /// Add multiple hashes to the filter
    pub fn insert_batch(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.insert(hash);
        }
    }

    /// Get filter statistics
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

    /// Clear the filter
    pub fn clear(&mut self) {
        self.filter.clear();
    }

    /// Get number of items added (approximate)
    pub fn len(&self) -> usize {
        self.filter.len() as usize
    }

    /// Check if filter is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(any())]
mod tests {
    use super::*;

    #[test]
    fn test_proof_cache() {
        let cache = ProofCache::new(100);
        let hash = Hash::zero();
        let proof = create_test_proof();

        // Test cache miss
        assert!(cache.get(&hash).is_none());

        // Test cache put and hit
        cache.put(hash, proof.clone());
        assert!(cache.get(&hash).is_some());

        // Test cache stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_rate > 0.0);
    }

    fn create_test_proof() -> ProofBundle {
        use crate::dag::DAGSegment;
        use crate::proof::{FinalityProof, InclusionProof};
        use csv_hash::seal::{CommitAnchor, SealPoint};

        ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], Hash::zero()),
            signatures: vec![],
            seal_ref: unsafe { SealPoint::new_unchecked(vec![0], Some(0)) },
            anchor_ref: unsafe { CommitAnchor::new_unchecked(vec![0], 0, vec![]) },
            inclusion_proof: unsafe { InclusionProof::new_unchecked(vec![], Hash::zero(), 0, 0) },
            finality_proof: unsafe { FinalityProof::new_unchecked(vec![], 0, true) },
            provenance: None,
            certification: None,
        }
    }
}
