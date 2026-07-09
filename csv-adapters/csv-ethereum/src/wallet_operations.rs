//! Ethereum wallet operations implementing the WalletOperations trait
//!
//! This module provides chain-specific wallet operations for Ethereum,
//! implementing the generic WalletOperations trait from csv-wallet.

use async_trait::async_trait;
use csv_hash::chain_id::ChainId;
use csv_keys::bip44::{derive_address_from_key, derive_all_chain_keys};
use csv_wallet::error::WalletError;
use csv_wallet::wallet_traits::WalletOperations;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "rpc")]
use reqwest::Client as ReqwestClient;
#[cfg(feature = "rpc")]
use serde_json::Value;

/// Network type for wallet operations
#[derive(Debug, Clone, Copy)]
pub enum Network {
    Main,
    Test,
    Dev,
}

impl Network {
    fn rpc_url(&self) -> &'static str {
        match self {
            Network::Main => "https://eth.llamarpc.com",
            Network::Test => "https://rpc.sepolia.org",
            Network::Dev => "http://localhost:8545",
        }
    }
}

/// Ethereum wallet operations implementation
pub struct EthereumWalletOperations {
    network: Network,
    #[cfg(feature = "rpc")]
    rpc_client: Option<Arc<ReqwestClient>>,
}

impl EthereumWalletOperations {
    /// Create new Ethereum wallet operations
    pub fn new(network: Network) -> Self {
        Self {
            network,
            #[cfg(feature = "rpc")]
            rpc_client: None,
        }
    }

    /// Create new Ethereum wallet operations with RPC client
    #[cfg(feature = "rpc")]
    pub fn with_rpc(network: Network, _rpc_url: Option<String>) -> Self {
        let client = ReqwestClient::new();
        Self {
            network,
            rpc_client: Some(Arc::new(client)),
        }
    }

    /// Get the RPC client if configured
    #[cfg(feature = "rpc")]
    fn rpc_client(&self) -> Result<&Arc<ReqwestClient>, WalletError> {
        self.rpc_client
            .as_ref()
            .ok_or_else(|| WalletError::RpcNotConfigured("Ethereum".to_string()))
    }
}

#[async_trait]
impl WalletOperations for EthereumWalletOperations {
    fn chain_id(&self) -> ChainId {
        ChainId::new("ethereum")
    }

    fn derive_address(
        &self,
        seed: &[u8],
        account: u32,
        _index: u32,
    ) -> Result<String, WalletError> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(format!(
                "Seed must be at least 64 bytes, got {}",
                seed.len()
            )));
        }

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for Ethereum
        let core_chain = ChainId::new("ethereum");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| WalletError::UnsupportedChain("ethereum".to_string()))?;

        // Derive address from key
        let address = derive_address_from_key(key.expose_secret(), &core_chain)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;

        Ok(address)
    }

    async fn get_balance(&self, address: &str) -> Result<String, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = self.network.rpc_url();

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 1
            });

            let response = client
                .post(url)
                .json(&request)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get balance: {}", e)))?;

            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            let balance = data["result"]
                .as_str()
                .ok_or_else(|| WalletError::RpcError("No balance in response".to_string()))?;

            Ok(balance.to_string())
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Ethereum".to_string()))
        }
    }

    async fn sign_transaction(
        &self,
        _seed: &[u8],
        _tx_data: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        // Fail closed. The previous implementation signed the raw `tx_data`
        // blob directly with a seed-derived key: no EIP-155 chain-id binding,
        // no nonce, no RLP transaction envelope. Such a signature is not a
        // valid Ethereum transaction and is replayable across chains, so it
        // must never be produced. A real implementation must construct and
        // sign a properly encoded EIP-1559/EIP-155 transaction.
        Err(WalletError::Signing(
            "Ethereum transaction signing is not implemented: refusing to \
             produce a raw, chain-unbound signature. Use a real EIP-155 \
             transaction signing path before broadcasting."
                .to_string(),
        ))
    }

    async fn broadcast_transaction(&self, signed_tx: &[u8]) -> Result<String, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = self.network.rpc_url();

            let tx_hex = hex::encode(signed_tx);

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [format!("0x{}", tx_hex)],
                "id": 1
            });

            let response = client.post(url).json(&request).send().await.map_err(|e| {
                WalletError::RpcError(format!("Failed to broadcast transaction: {}", e))
            })?;

            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            let tx_hash = data["result"].as_str().ok_or_else(|| {
                WalletError::RpcError("No transaction hash in response".to_string())
            })?;

            Ok(tx_hash.to_string())
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Ethereum".to_string()))
        }
    }

    async fn get_transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<HashMap<String, String>, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = self.network.rpc_url();

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            });

            let response =
                client.post(url).json(&request).send().await.map_err(|e| {
                    WalletError::RpcError(format!("Failed to get transaction: {}", e))
                })?;

            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            let mut status = HashMap::new();
            status.insert("txid".to_string(), tx_hash.to_string());

            if let Some(receipt) = data["result"].as_object() {
                let success = receipt["status"]
                    .as_str()
                    .map(|s| s == "0x1")
                    .unwrap_or(false);
                status.insert(
                    "status".to_string(),
                    if success {
                        "success".to_string()
                    } else {
                        "failed".to_string()
                    },
                );
                status.insert(
                    "block_number".to_string(),
                    receipt["blockNumber"].as_str().unwrap_or("0").to_string(),
                );
                status.insert(
                    "gas_used".to_string(),
                    receipt["gasUsed"].as_str().unwrap_or("0").to_string(),
                );
            } else {
                status.insert("status".to_string(), "pending".to_string());
            }

            Ok(status)
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Ethereum".to_string()))
        }
    }
}

/// Additional Ethereum-specific wallet operations
impl EthereumWalletOperations {
    /// Derive an Ethereum funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        let ops = Self::new(network);
        ops.derive_address(seed, account, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id() {
        let ops = EthereumWalletOperations::new(Network::Test);
        assert_eq!(ops.chain_id().as_str(), "ethereum");
    }

    #[test]
    fn test_derive_address() {
        let ops = EthereumWalletOperations::new(Network::Test);
        let seed = [42u8; 64];
        let address = ops.derive_address(&seed, 0, 0);
        assert!(address.is_ok());
        let addr_str = address.unwrap();
        // Ethereum addresses start with "0x"
        assert!(addr_str.starts_with("0x"));
        assert_eq!(addr_str.len(), 42); // 0x + 40 hex chars
    }
}
