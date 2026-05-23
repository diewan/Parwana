//! Event bus for structured transfer lifecycle events.

#![allow(missing_docs)]

use csv_core::verified::VerificationAssurance;
use std::string::String;

/// Structured events emitted during transfer execution
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// Transfer is being locked on source chain
    Locking { transfer_id: String },
    /// Waiting for chain finality
    AwaitingFinality { transfer_id: String },
    /// Building inclusion proof
    BuildingProof { transfer_id: String },
    /// Proof verified by canonical verifier
    ProofVerified { transfer_id: String },
    /// Proof is ready for verification
    ProofReady { transfer_id: String },
    /// Minting on destination chain
    Minting { transfer_id: String },
    /// Transfer complete with mint tx hash
    Complete {
        transfer_id: String,
        mint_tx_hash: String,
    },
    /// Rollback was triggered
    RollbackTriggered {
        transfer_id: String,
        reason: String,
    },
    /// Replay was detected
    ReplayDetected { transfer_id: String },
    /// Verification assurance was downgraded
    VerificationDowngraded {
        transfer_id: String,
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

        bus.emit(TransferEvent::Locking {
            transfer_id: "test-1".to_string(),
        });

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], TransferEvent::Locking { .. }));
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

        bus.emit(TransferEvent::Complete {
            transfer_id: "test-1".to_string(),
            mint_tx_hash: "0xabc".to_string(),
        });

        assert_eq!(
            count1.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            count2.load(Ordering::SeqCst),
            1
        );
    }
}
