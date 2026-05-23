// Protocol Constitution Tests
//
// These tests enforce protocol invariants that MUST NEVER BREAK.
// Any change that causes these tests to fail requires explicit
// protocol version bump and RFC approval.

mod hash_stability;
mod serialization_canonical;
mod replay_protection;
mod state_transitions;
mod proof_domain_separation;
