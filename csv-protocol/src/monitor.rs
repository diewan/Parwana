//! Reorg monitoring and censorship detection
//!
//! Cross-cutting components that track chain state across all adapters:
//! - Reorg detection and anchor invalidation
//! - Publication timeout tracking (censorship detection)

use std::collections::BTreeMap;
use csv_hash::Hash;

/// Reorg event detected on a chain
#[derive(Clone, Debug)]
pub struct ReorgEvent {
    /// Chain identifier
    pub chain: String,
    /// Fork point (last common block height)
    pub fork_height: u64,
    /// Depth of the reorg (blocks invalidated)
    pub depth: u64,
    /// Old chain tip hash (now orphaned)
    pub old_tip: [u8; 32],
    /// New chain tip hash (current best chain)
    pub new_tip: [u8; 32],
}

/// Chain tip tracker for detecting blockchain reorganizations
pub struct ReorgMonitor {
    /// Known chain tips (chain → (height, hash))
    tips: BTreeMap<String, (u64, [u8; 32])>,
    /// Recent reorg events
    reorgs: Vec<ReorgEvent>,
}

impl ReorgMonitor {
    /// Create a new reorg monitor with empty state
    pub fn new() -> Self {
        Self {
            tips: BTreeMap::new(),
            reorgs: Vec::new(),
        }
    }

    /// Update the chain tip. Returns `Some(ReorgEvent)` if a reorg is detected.
    pub fn update_tip(
        &mut self,
        chain: &str,
        height: u64,
        tip_hash: [u8; 32],
    ) -> Option<ReorgEvent> {
        if let Some(&(prev_height, prev_hash)) = self.tips.get(chain) {
            if height <= prev_height {
                // New tip is at or below previous height → reorg
                let depth = prev_height.saturating_sub(height) + 1;
                let event = ReorgEvent {
                    chain: chain.to_string(),
                    fork_height: height,
                    depth,
                    old_tip: prev_hash,
                    new_tip: tip_hash,
                };
                self.tips.insert(chain.to_string(), (height, tip_hash));
                self.reorgs.push(event.clone());
                return Some(event);
            }
            // Check for gap (reorg + reorg)
            if height > prev_height + 1 {
                // Chain jumped forward (normal case, not a reorg)
            }
        }
        self.tips.insert(chain.to_string(), (height, tip_hash));
        None
    }

    /// Get recent reorgs for a specific chain
    pub fn recent_reorgs(&self, chain: &str) -> Vec<&ReorgEvent> {
        self.reorgs.iter().filter(|r| r.chain == chain).collect()
    }

    /// Get the current tip for a chain
    pub fn tip(&self, chain: &str) -> Option<(u64, [u8; 32])> {
        self.tips.get(chain).copied()
    }
}

impl Default for ReorgMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Publication tracker for detecting censorship or stuck transactions
///
/// Tracks pending publications and flags them if not included
/// within the configured timeout period.
pub struct PublicationTracker {
    /// Pending publications (chain → Vec)
    pending: BTreeMap<String, Vec<PendingPublication>>,
    /// Publication timeout in seconds
    pub timeout_seconds: u64,
}

/// Represents a transaction awaiting on-chain inclusion
#[derive(Clone, Debug)]
pub struct PendingPublication {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    /// Commitment hash being published
    pub commitment_hash: Hash,
    /// Unix epoch seconds when submission occurred
    pub submitted_at: u64,
}

impl PublicationTracker {
    /// Create a new tracker with the given timeout
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            pending: BTreeMap::new(),
            timeout_seconds,
        }
    }

    /// Record a new publication submission
    pub fn track_publication(
        &mut self,
        chain: &str,
        tx_hash: Vec<u8>,
        commitment_hash: Hash,
        submitted_at: u64,
    ) {
        self.pending
            .entry(chain.to_string())
            .or_default()
            .push(PendingPublication {
                tx_hash,
                commitment_hash,
                submitted_at,
            });
    }

    /// Confirm a publication was included
    pub fn confirm_publication(&mut self, chain: &str, tx_hash: &[u8]) -> bool {
        if let Some(pending) = self.pending.get_mut(chain) {
            let before = pending.len();
            pending.retain(|p| p.tx_hash != tx_hash);
            return pending.len() < before;
        }
        false
    }

    /// Get timed-out publications (censorship candidates)
    pub fn timed_out(&self, chain: &str, current_time: u64) -> Vec<&PendingPublication> {
        self.pending
            .get(chain)
            .map(|p: &Vec<PendingPublication>| {
                p.iter()
                    .filter(|pp| {
                        current_time.saturating_sub(pp.submitted_at) > self.timeout_seconds
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get count of pending publications
    pub fn pending_count(&self, chain: &str) -> usize {
        self.pending.get(chain).map(|p: &Vec<PendingPublication>| p.len()).unwrap_or(0)
    }

    /// Clear all pending publications for a chain
    pub fn clear_chain(&mut self, chain: &str) {
        self.pending.remove(chain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reorg_monitor_normal_update() {
        let mut monitor = ReorgMonitor::new();
        assert!(monitor.update_tip("bitcoin", 100, [1u8; 32]).is_none());
        assert!(monitor.update_tip("bitcoin", 101, [2u8; 32]).is_none());
    }

    #[test]
    fn test_reorg_monitor_detect_reorg() {
        let mut monitor = ReorgMonitor::new();
        monitor.update_tip("bitcoin", 100, [1u8; 32]);
        monitor.update_tip("bitcoin", 101, [2u8; 32]);
        // New tip is lower → reorg
        let event = monitor.update_tip("bitcoin", 99, [3u8; 32]);
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.chain, "bitcoin");
        assert_eq!(event.fork_height, 99);
        assert_eq!(event.old_tip, [2u8; 32]);
        assert_eq!(event.new_tip, [3u8; 32]);
    }

    #[test]
    fn test_publication_tracker_lifecycle() {
        let mut tracker = PublicationTracker::new(3600);
        tracker.track_publication("bitcoin", vec![1, 2, 3], Hash::new([0xAA; 32]), 1700000000);
        assert_eq!(tracker.pending_count("bitcoin"), 1);

        // Confirm
        assert!(tracker.confirm_publication("bitcoin", &[1, 2, 3]));
        assert_eq!(tracker.pending_count("bitcoin"), 0);
    }

    #[test]
    fn test_publication_tracker_timeout() {
        let mut tracker = PublicationTracker::new(3600);
        tracker.track_publication("bitcoin", vec![1, 2, 3], Hash::new([0xAA; 32]), 1700000000);

        // Within timeout
        assert!(tracker.timed_out("bitcoin", 1700003000).is_empty());

        // Past timeout
        let timed_out = tracker.timed_out("bitcoin", 1700004000);
        assert_eq!(timed_out.len(), 1);
    }

    #[test]
    fn test_publication_tracker_multiple() {
        let mut tracker = PublicationTracker::new(3600);
        tracker.track_publication("bitcoin", vec![1], Hash::new([1u8; 32]), 1700000000);
        tracker.track_publication("bitcoin", vec![2], Hash::new([2u8; 32]), 1700000000);
        tracker.track_publication("ethereum", vec![3], Hash::new([3u8; 32]), 1700000000);

        assert_eq!(tracker.pending_count("bitcoin"), 2);
        assert_eq!(tracker.pending_count("ethereum"), 1);

        tracker.confirm_publication("bitcoin", &[1]);
        assert_eq!(tracker.pending_count("bitcoin"), 1);

        tracker.clear_chain("bitcoin");
        assert_eq!(tracker.pending_count("bitcoin"), 0);
    }
}
