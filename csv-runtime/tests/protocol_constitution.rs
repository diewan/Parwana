//! Protocol constitution integration tests (must never break).

#[path = "protocol_constitution/hash_stability.rs"]
mod hash_stability;
#[path = "protocol_constitution/proof_domain_separation.rs"]
mod proof_domain_separation;
#[path = "protocol_constitution/replay_protection.rs"]
mod replay_protection;
#[path = "protocol_constitution/serialization_canonical.rs"]
mod serialization_canonical;
#[path = "protocol_constitution/state_transitions.rs"]
mod state_transitions;
