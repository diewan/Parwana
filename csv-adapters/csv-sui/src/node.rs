//! Sui gRPC client using sui-rust-sdk
//!
//! Implements Sui blockchain communication using the official sui-rust-sdk gRPC client.

use sui_rpc::Client;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Sui gRPC client wrapper
pub struct SuiNode {
    /// The underlying sui-rust-sdk gRPC client
    client: Arc<Mutex<Client>>,
    /// RPC URL for the Sui node
    rpc_url: String,
}

impl SuiNode {
    /// Create a new Sui gRPC client
    pub fn new(rpc_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::new(rpc_url)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Get the underlying sui-rust-sdk client
    pub fn client(&self) -> Arc<Mutex<Client>> {
        Arc::clone(&self.client)
    }

    /// Get the RPC URL
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}
