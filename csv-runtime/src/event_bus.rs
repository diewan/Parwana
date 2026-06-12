//! Event bus for structured transfer lifecycle events.

#![allow(missing_docs)]

use csv_hash::Hash;
use csv_protocol::verification_results::VerificationAssurance;
use std::string::String;
use uuid::Uuid;

/// Forensic context for transfer events
///
/// Contains all debugging information needed for forensic analysis
/// of transfer execution and failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferContext {
    /// Transfer identifier
    pub transfer_id: String,
    /// Replay ID (if available, stored as Hash for serialization compatibility)
    pub replay_id: Option<Hash>,
    /// Proof hash (if available)
    pub proof_hash: Option<[u8; 32]>,
    /// Coordinator instance identifier
    pub coordinator_id: Uuid,
    /// Lease identifier (if available)
    pub lease_id: Option<Uuid>,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub dest_chain: String,
    /// Finality state
    pub finality_state: FinalityState,
    /// Recovery attempt count
    pub recovery_attempt: u32,
}

/// Finality state for forensic tracking
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalityState {
    /// Finality not yet checked
    NotChecked,
    /// Awaiting finality
    Awaiting,
    /// Finality confirmed
    Confirmed,
    /// Finality failed
    Failed(String),
}

/// Structured events emitted during transfer execution
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// Transfer is being locked on source chain
    Locking(TransferContext),
    /// Waiting for chain finality
    AwaitingFinality(TransferContext),
    /// Building inclusion proof
    BuildingProof(TransferContext),
    /// Proof verified by canonical verifier
    ProofVerified(TransferContext),
    /// Proof is ready for verification
    ProofReady(TransferContext),
    /// Minting on destination chain
    Minting(TransferContext),
    /// Transfer complete with mint tx hash
    Complete(TransferContext),
    /// Rollback was triggered
    RollbackTriggered {
        ctx: TransferContext,
        reason: String,
    },
    /// Replay was detected
    ReplayDetected(TransferContext),
    /// Verification assurance was downgraded
    VerificationDowngraded {
        ctx: TransferContext,
        from: VerificationAssurance,
    },
}

/// Subscriber callback type
pub type EventSubscriber = Box<dyn Fn(TransferEvent) + Send + Sync>;

/// Emits structured events for observability. Applications subscribe to these
/// to update UI, metrics, and logs. The coordinator never calls UI directly.
pub struct EventBus {
    subscribers: Vec<EventSubscriber>,
}

impl EventBus {
    /// Create a new event bus
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    /// Register an event subscriber
    pub fn subscribe(&mut self, subscriber: EventSubscriber) {
        self.subscribers.push(subscriber);
    }

    /// Emit an event to all subscribers.
    pub fn emit(&self, event: TransferEvent) {
        for subscriber in &self.subscribers {
            subscriber(event.clone());
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_emits_to_subscribers() {
        let mut bus = EventBus::new();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_clone = received.clone();

        bus.subscribe(Box::new(move |event| {
            received_clone.lock().unwrap().push(event);
        }));

        let ctx = TransferContext {
            transfer_id: "test-1".to_string(),
            replay_id: None,
            proof_hash: None,
            coordinator_id: Uuid::new_v4(),
            lease_id: None,
            source_chain: "bitcoin".to_string(),
            dest_chain: "ethereum".to_string(),
            finality_state: FinalityState::NotChecked,
            recovery_attempt: 0,
        };

        bus.emit(TransferEvent::Locking(ctx.clone()));

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], TransferEvent::Locking(_)));
    }

    #[test]
    fn test_event_bus_multiple_subscribers() {
        let mut bus = EventBus::new();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count1 = std::sync::Arc::new(AtomicUsize::new(0));
        let count2 = std::sync::Arc::new(AtomicUsize::new(0));
        let count1_clone = count1.clone();
        let count2_clone = count2.clone();

        bus.subscribe(Box::new(move |_| {
            count1_clone.fetch_add(1, Ordering::SeqCst);
        }));
        bus.subscribe(Box::new(move |_| {
            count2_clone.fetch_add(1, Ordering::SeqCst);
        }));

        let ctx = TransferContext {
            transfer_id: "test-1".to_string(),
            replay_id: None,
            proof_hash: None,
            coordinator_id: Uuid::new_v4(),
            lease_id: None,
            source_chain: "bitcoin".to_string(),
            dest_chain: "ethereum".to_string(),
            finality_state: FinalityState::Confirmed,
            recovery_attempt: 0,
        };

        bus.emit(TransferEvent::Complete(ctx));

        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }
}
