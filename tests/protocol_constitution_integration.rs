//! Protocol constitution integration tests (must never break).

mod hash_stability;
mod serialization_canonical;
mod replay_protection;
mod state_transitions;
mod proof_domain_separation;

#[path = "contracts_equivalence/mod.rs"]
mod contracts_equivalence;
