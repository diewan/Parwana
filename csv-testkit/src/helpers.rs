//! Test helpers
//!
//! This module provides helper functions and builders for testing.

use csv_core::signature::SignatureScheme;
use csv_verifier::{CanonicalVerifierImpl, VerificationContext};

/// Test context for integration tests
pub struct TestContext {
    /// Canonical verifier implementation
    pub verifier: CanonicalVerifierImpl,
}

impl TestContext {
    /// Create a new test context
    pub fn new() -> Self {
        Self {
            verifier: CanonicalVerifierImpl::default(),
        }
    }

    /// Create a verification context for a specific chain
    pub fn verification_context(chain_id: impl Into<String>) -> VerificationContext {
        VerificationContext {
            chain_id: chain_id.into(),
            signature_scheme: SignatureScheme::Secp256k1,
            required_confirmations: 6,
            current_block_height: Some(100),
            seal_registry: None,
            chain_data: None,
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Test builder for constructing test data
pub struct TestBuilder {
    /// Test data
    data: Vec<u8>,
}

impl TestBuilder {
    /// Create a new test builder
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Add data to the builder
    pub fn add_data(mut self, data: Vec<u8>) -> Self {
        self.data.extend(data);
        self
    }

    /// Build the test data
    pub fn build(self) -> Vec<u8> {
        self.data
    }
}

impl Default for TestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
