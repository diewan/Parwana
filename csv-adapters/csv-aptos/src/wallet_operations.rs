//! Aptos wallet operations implementing the WalletOperations trait
//!
//! This module provides chain-specific wallet operations for Aptos,
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
    fn to_rpc_url(&self) -> &'static str {
        match self {
            Network::Main => "https://fullnode.mainnet.aptoslabs.com",
            Network::Test => "https://fullnode.testnet.aptoslabs.com",
            Network::Dev => "https://fullnode.devnet.aptoslabs.com",
        }
    }
}

/// Aptos wallet operations implementation
pub struct AptosWalletOperations {
    network: Network,
    #[cfg(feature = "rpc")]
    rpc_client: Option<Arc<ReqwestClient>>,
}

impl AptosWalletOperations {
    /// Create new Aptos wallet operations
    pub fn new(network: Network) -> Self {
        Self {
            network,
            #[cfg(feature = "rpc")]
            rpc_client: None,
        }
    }

    /// Create new Aptos wallet operations with RPC client
    #[cfg(feature = "rpc")]
    pub fn with_rpc(network: Network, rpc_url: Option<String>) -> Self {
        let client = ReqwestClient::new();
        Self {
            network,
            rpc_client: Some(Arc::new(client)),
        }
    }

    /// Get the RPC client if configured
    #[cfg(feature = "rpc")]
    fn rpc_client(&self) -> Result<&Arc<ReqwestClient>, WalletError> {
        self.rpc_client.as_ref().ok_or_else(|| {
            WalletError::RpcNotConfigured("Aptos".to_string())
        })
    }
}

#[async_trait]
impl WalletOperations for AptosWalletOperations {
    fn chain_id(&self) -> ChainId {
        ChainId::new("aptos")
    }

    fn derive_address(
        &self,
        seed: &[u8],
        account: u32,
        index: u32,
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

        // Get the key for Aptos
        let core_chain = ChainId::new("aptos");
        let key = keys
            .get(&core_chain)
            .ok_or_else(|| WalletError::UnsupportedChain("aptos".to_string()))?;

        // Derive address from key
        let address = derive_address_from_key(key.expose_secret(), &core_chain)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;

        Ok(address)
    }

    async fn get_balance(&self, address: &str) -> Result<String, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = format!("{}/accounts/{}", self.network.to_rpc_url(), address);
            
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get balance: {}", e)))?;
            
            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;
            
            let balance = data["coin"]["value"]
                .as_str()
                .unwrap_or("0");
            
            Ok(balance.to_string())
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Aptos".to_string()))
        }
    }

    async fn sign_transaction(&self, seed: &[u8], tx_data: &[u8]) -> Result<Vec<u8>, WalletError> {
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(format!(
                "Seed must be at least 64 bytes, got {}",
                seed.len()
            )));
        }

        // Derive Ed25519 signing key from seed
        use ed25519_dalek::{SigningKey, Signature, Signer};
        let signing_key: SigningKey = seed_array[..32]
            .try_into()
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive signing key: {:?}", e)))?;
        
        // Sign the transaction data
        let signature: Signature = signing_key.sign(tx_data);
        
        Ok(signature.to_bytes().to_vec())
    }

    async fn broadcast_transaction(&self, signed_tx: &[u8]) -> Result<String, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = format!("{}/transactions", self.network.to_rpc_url());
            
            let response = client
                .post(&url)
                .header("Content-Type", "application/x.aptos.signed_transaction+bcs")
                .body(signed_tx.to_vec())
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to broadcast transaction: {}", e)))?;
            
            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;
            
            let tx_hash = data["hash"]
                .as_str()
                .ok_or_else(|| WalletError::RpcError("No transaction hash in response".to_string()))?;
            
            Ok(tx_hash.to_string())
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Aptos".to_string()))
        }
    }

    async fn get_transaction_status(&self, tx_hash: &str) -> Result<HashMap<String, String>, WalletError> {
        #[cfg(feature = "rpc")]
        {
            let client = self.rpc_client()?;
            let url = format!("{}/transactions/by_hash/{}", self.network.to_rpc_url(), tx_hash);
            
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get transaction: {}", e)))?;
            
            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;
            
            let mut status = HashMap::new();
            status.insert("txid".to_string(), tx_hash.to_string());
            
            let success = data["success"]
                .as_bool()
                .unwrap_or(false);
            status.insert("status".to_string(), if success { "success".to_string() } else { "failed".to_string() });
            status.insert("vm_status".to_string(), data["vm_status"].as_str().unwrap_or("unknown").to_string());
            
            Ok(status)
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            Err(WalletError::RpcNotConfigured("Aptos".to_string()))
        }
    }
}

/// Additional Aptos-specific wallet operations
impl AptosWalletOperations {
    /// Derive an Aptos funding address from seed
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
        let ops = AptosWalletOperations::new(Network::Test);
        assert_eq!(ops.chain_id().as_str(), "aptos");
    }

    #[test]
    fn test_derive_address() {
        let ops = AptosWalletOperations::new(Network::Test);
        let seed = [42u8; 64];
        let address = ops.derive_address(&seed, 0, 0);
        assert!(address.is_ok());
        let addr_str = address.unwrap();
        // Aptos addresses are hex-encoded
        assert!(!addr_str.is_empty());
    }
}
