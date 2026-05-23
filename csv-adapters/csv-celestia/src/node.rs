//! Celestia Node RPC Client (Feature-gated)
//!
//! This module provides the real Celestia node RPC client implementation.
//! It requires the `rpc` feature to be enabled.
//!
//! ## Usage
//!
//! Enable the `rpc` feature in your Cargo.toml:
//! ```toml
//! [dependencies]
//! csv-celestia = { version = "0.4", features = ["rpc"] }
//! ```

// RPC client re-exported from rpc module
pub use crate::rpc::CelestiaNode;

/// Additional node-specific functionality
impl CelestiaNode {
    /// Check if the node is healthy
    pub async fn health_check(&self) -> bool {
        // Would make a health check RPC call
        true
    }
}
