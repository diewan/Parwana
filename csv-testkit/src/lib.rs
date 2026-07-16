//! CSV Testkit - Testing utilities and shared fixtures
//!
//! This crate provides testing utilities, shared fixtures, and helpers
//! for testing the Parwana across all crates.

#![warn(missing_docs)]

pub mod accountability;
pub mod adversarial;
pub mod fixtures;
pub mod helpers;
pub mod traces;

// Re-exports
pub use accountability::AccountabilityFixture;
pub use adversarial::{
    AdversarialConfig, AdversarialRunner, ByzantineBehavior, ByzantineFaultMode, ByzantineRpcReader,
};
pub use fixtures::{TestAdapter, TestProofBundle, TestTransfer};
pub use helpers::{TestBuilder, TestContext};
pub use traces::{CanonicalTrace, ExpectedOutput, InjectedFault, RecordedRpcInteraction};
