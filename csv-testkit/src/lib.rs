//! CSV Testkit - Testing utilities and shared fixtures
//!
//! This crate provides testing utilities, shared fixtures, and helpers
//! for testing the CSV protocol across all crates.

#![warn(missing_docs)]

pub mod adversarial;
pub mod fixtures;
pub mod helpers;

// Re-exports
pub use adversarial::{AdversarialConfig, AdversarialRunner, ByzantineBehavior};
pub use fixtures::{TestProofBundle, TestTransfer};
pub use helpers::{TestBuilder, TestContext};
