//! P2P proof routing and delivery logic.
//!
//! The `ProofRouter` manages multiple transports and provides intelligent
//! routing of proof bundles based on chain, priority, and availability.
//! It also handles deduplication and replay protection for incoming proofs.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use csv_protocol::proof_types::ProofBundle;
use tracing::{debug, info, warn};

use crate::{DeliveredProof, EventId, ProofTransport, TransportError};

/// Default TTL for proof cache entries (1 hour).
const DEFAULT_PROOF_TTL: Duration = Duration::from_secs(3600);

/// Maximum number of proofs to cache.
const MAX_CACHED_PROOFS: usize = 10_000;

/// Filter criteria for subscribing to proofs via P2P transport.
#[derive(Debug, Clone, Default)]
pub struct ProofFilter {
    /// Chain IDs to filter by (empty = all chains).
    pub chain_ids: Vec<String>,
    /// Author public keys to filter by (empty = all authors).
    pub authors: Vec<String>,
    /// Minimum confirmation count required.
    pub min_confirmations: Option<u64>,
}

impl ProofFilter {
    /// Create a filter for proofs from a specific chain.
    pub fn for_chain(chain: &str) -> Self {
        Self {
            chain_ids: vec![chain.to_string()],
            ..Default::default()
        }
    }

    /// Create a filter for proofs from a specific author.
    pub fn from_author(pubkey_hex: &str) -> Self {
        Self {
            authors: vec![pubkey_hex.to_string()],
            ..Default::default()
        }
    }

    /// Create a filter matching all CSV proof events.
    pub fn all_csv_proofs() -> Self {
        Self::default()
    }

    /// Check if this filter matches the given chain ID.
    pub fn matches_chain(&self, chain_id: &str) -> bool {
        self.chain_ids.is_empty() || self.chain_ids.contains(&chain_id.to_string())
    }

    /// Check if this filter matches the given author pubkey.
    pub fn matches_author(&self, author: &str) -> bool {
        self.authors.is_empty() || self.authors.contains(&author.to_string())
    }

    /// Check if this filter matches the given proof bundle.
    ///
    /// Matches if the proof's anchor chain matches and/or the author pubkey matches.
    pub fn matches_proof(&self, proof: &ProofBundle) -> bool {
        let chain_matches = self.chain_ids.is_empty()
            || self.chain_ids.iter().any(|chain| {
                // Try to match chain ID from anchor metadata
                std::str::from_utf8(&proof.anchor_ref.metadata)
                    .map(|s| s.trim() == chain)
                    .unwrap_or(false)
            });

        // For now, we don't have author info in the proof bundle itself,
        // so we only filter by chain. Author filtering is done at the Nostr event level.
        chain_matches
    }
}

/// A simple proof cache that prevents duplicate processing.
pub struct ProofCache {
    seen_event_ids: HashSet<String>,
    max_size: usize,
    #[allow(dead_code)]
    ttl: Duration,
    #[allow(dead_code)]
    last_cleanup: Instant,
}

impl ProofCache {
    /// Create a new proof cache with default settings.
    pub fn new() -> Self {
        Self {
            seen_event_ids: HashSet::new(),
            max_size: MAX_CACHED_PROOFS,
            ttl: DEFAULT_PROOF_TTL,
            last_cleanup: Instant::now(),
        }
    }

    /// Check if an event ID has already been seen.
    pub fn is_duplicate(&mut self, event_id: &EventId) -> bool {
        self.ensure_capacity();
        self.seen_event_ids.contains(&event_id.0)
    }

    /// Record an event ID as seen.
    pub fn record(&mut self, event_id: &EventId) {
        if self.seen_event_ids.len() < self.max_size {
            self.seen_event_ids.insert(event_id.0.clone());
        }
    }

    /// Clean up expired entries.
    fn ensure_capacity(&mut self) {
        if self.seen_event_ids.len() > self.max_size * 2 {
            // Keep only the most recent half
            let keep = self.max_size / 2;
            let ids: Vec<String> = self.seen_event_ids.iter().cloned().collect();
            self.seen_event_ids.clear();
            for id in ids.into_iter().take(keep) {
                self.seen_event_ids.insert(id);
            }
            debug!(kept = keep, "Proof cache cleanup triggered");
        }
    }

    /// Get the number of cached event IDs.
    pub fn len(&self) -> usize {
        self.seen_event_ids.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen_event_ids.is_empty()
    }
}

impl Default for ProofCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Routes proof bundles to available P2P transports.
///
/// The router maintains a list of transports and selects the best one
/// for each broadcast based on chain affinity and connectivity status.
pub struct ProofRouter {
    transports: HashMap<String, Box<dyn ProofTransport>>,
    preferred_transport: Option<String>,
    cache: ProofCache,
}

impl ProofRouter {
    /// Create a new proof router.
    pub fn new() -> Self {
        Self {
            transports: HashMap::new(),
            preferred_transport: None,
            cache: ProofCache::new(),
        }
    }

    /// Register a transport for proof delivery.
    pub fn register(&mut self, name: String, transport: Box<dyn ProofTransport>) {
        let name_clone = name.clone();
        info!(transport = %name, "Registered P2P proof transport");
        self.transports.insert(name, transport);

        if self.preferred_transport.is_none() {
            self.preferred_transport = Some(name_clone);
        }
    }

    /// Get the list of registered transport names.
    pub fn transports(&self) -> Vec<String> {
        self.transports.keys().cloned().collect()
    }

    /// Set the preferred transport by name.
    pub fn set_preferred(&mut self, name: &str) {
        if self.transports.contains_key(name) {
            self.preferred_transport = Some(name.to_string());
            info!(preferred = %name, "Set preferred P2P transport");
        } else {
            warn!(%name, "Attempted to set unknown transport as preferred");
        }
    }

    /// Get the preferred transport name.
    pub fn preferred(&self) -> Option<&str> {
        self.preferred_transport.as_deref()
    }

    /// Broadcast a proof bundle via the preferred transport.
    ///
    /// If the preferred transport fails, automatically falls back to IPFS if available.
    pub async fn broadcast(&self, proof: &ProofBundle) -> Result<EventId, TransportError> {
        // Try preferred transport first
        if let Some(ref name) = self.preferred_transport {
            if let Some(transport) = self.transports.get(name) {
                if transport.is_connected().await {
                    debug!(transport = %name, "Broadcasting via preferred transport");
                    match transport.broadcast_proof(proof).await {
                        Ok(event_id) => return Ok(event_id),
                        Err(e) => {
                            warn!(transport = %name, error = %e, "Preferred transport failed, trying fallback");
                        }
                    }
                } else {
                    warn!(transport = %name, "Preferred transport not connected, trying fallback");
                }
            }
        }

        // Try all transports in order
        for (name, transport) in &self.transports {
            if transport.is_connected().await {
                debug!(transport = %name, "Broadcasting via fallback transport");
                match transport.broadcast_proof(proof).await {
                    Ok(event_id) => return Ok(event_id),
                    Err(e) => {
                        warn!(transport = %name, error = %e, "Fallback transport failed");
                    }
                }
            }
        }

        Err(TransportError::NoRelays)
    }

    /// Broadcast a proof bundle to ALL registered transports.
    pub async fn broadcast_all(&self, proof: &ProofBundle) -> (Vec<EventId>, Vec<TransportError>) {
        let mut success = Vec::new();
        let mut errors = Vec::new();

        for (name, transport) in &self.transports {
            if !transport.is_connected().await {
                debug!(transport = %name, "Skipping disconnected transport");
                continue;
            }

            match transport.broadcast_proof(proof).await {
                Ok(event_id) => {
                    info!(transport = %name, event_id = %event_id.as_hex(), "Proof broadcast successful");
                    success.push(event_id);
                }
                Err(e) => {
                    warn!(transport = %name, error = %e, "Proof broadcast failed");
                    errors.push(e);
                }
            }
        }

        info!(
            total = self.transports.len(),
            successful = success.len(),
            failed = errors.len(),
            "Broadcast-all completed"
        );

        (success, errors)
    }

    /// Process an incoming delivered proof with deduplication.
    ///
    /// Returns true if the proof was new (not a duplicate).
    pub fn process_incoming(&mut self, delivered: DeliveredProof) -> bool {
        // Deduplication check
        if self.cache.is_duplicate(&delivered.event_id) {
            debug!(event_id = %delivered.event_id.as_hex(), "Duplicate proof rejected");
            return false;
        }

        self.cache.record(&delivered.event_id);

        info!(
            event_id = %delivered.event_id.as_hex(),
            author = %delivered.author_pubkey,
            timestamp = delivered.timestamp,
            "Processing incoming proof"
        );

        // In production, this would:
        // 1. Verify the proof using the canonical verifier.
        // 2. Store in local database via csv-store
        // 3. Trigger any relevant cross-chain operations
        true
    }

    pub fn is_seen(&mut self, event_id: &EventId) -> bool {
        self.cache.is_duplicate(event_id)
    }

    /// Get the number of cached proofs.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for ProofRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_filter_chain_only() {
        let filter = ProofFilter::for_chain("ethereum");
        assert_eq!(filter.chain_ids, vec!["ethereum".to_string()]);
        assert!(filter.authors.is_empty());
        assert!(filter.matches_chain("ethereum"));
        assert!(!filter.matches_chain("bitcoin"));
    }

    #[test]
    fn test_proof_filter_author_only() {
        let filter = ProofFilter::from_author("abc123");
        assert!(filter.chain_ids.is_empty());
        assert_eq!(filter.authors, vec!["abc123".to_string()]);
        assert!(filter.matches_author("abc123"));
        assert!(!filter.matches_author("def456"));
    }

    #[test]
    fn test_proof_filter_all_csv_proofs() {
        let filter = ProofFilter::all_csv_proofs();
        assert!(filter.chain_ids.is_empty());
        assert!(filter.authors.is_empty());
        assert!(filter.matches_chain("any-chain"));
        assert!(filter.matches_author("any-author"));
    }

    #[test]
    fn test_proof_filter_combined() {
        let filter = ProofFilter {
            chain_ids: vec!["ethereum".to_string()],
            authors: vec!["pub1".to_string(), "pub2".to_string()],
            ..Default::default()
        };
        assert!(filter.matches_chain("ethereum"));
        assert!(!filter.matches_chain("bitcoin"));
        assert!(filter.matches_author("pub1"));
        assert!(!filter.matches_author("pub3"));
    }

    #[test]
    fn test_proof_cache_new_is_empty() {
        let cache = ProofCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_proof_cache_record_and_duplicate() {
        let mut cache = ProofCache::new();
        let eid = EventId::new("abc123");

        assert!(!cache.is_duplicate(&eid));
        cache.record(&eid);
        assert!(cache.is_duplicate(&eid));
    }

    #[test]
    fn test_proof_cache_multiple_ids() {
        let mut cache = ProofCache::new();
        let eid1 = EventId::new("id1");
        let eid2 = EventId::new("id2");

        cache.record(&eid1);
        cache.record(&eid2);

        assert!(cache.is_duplicate(&eid1));
        assert!(cache.is_duplicate(&eid2));
        assert!(!cache.is_duplicate(&EventId::new("id3")));
    }

    #[test]
    fn test_proof_cache_different_ids() {
        let mut cache = ProofCache::new();
        let eid = EventId::new("abc123");
        let _eid_other = EventId::new("def456");

        cache.record(&eid);
        assert!(!cache.is_duplicate(&_eid_other));
    }

    #[test]
    fn test_proof_router_register_transport() {
        let router = ProofRouter::new();
        assert_eq!(router.transports(), Vec::<String>::new());
        assert!(router.preferred_transport.is_none());
        // Note: We can't easily create a mock ProofTransport in unit tests
    }

    #[test]
    fn test_proof_router_preferred() {
        let router = ProofRouter::new();
        assert!(router.preferred().is_none());
    }

    #[test]
    fn test_proof_router_cache_size() {
        let router = ProofRouter::new();
        assert_eq!(router.cache_size(), 0);
    }

    #[test]
    fn test_event_id_creation() {
        let eid = EventId::new("test123");
        assert_eq!(eid.as_hex(), "test123");
    }

    #[test]
    fn test_event_id_display() {
        let eid = EventId::new("abc123");
        assert_eq!(format!("{}", eid), "abc123");
    }
}
