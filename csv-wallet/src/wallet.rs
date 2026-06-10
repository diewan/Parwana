//! Wallet manager for unified wallet operations

use crate::error::{Result, WalletError};
use crate::keystore::{KeyStore, KeyPurpose};
use crate::signer::{MemorySigner, Signer, SignerRef};
use csv_hash::chain_id::ChainId;
use csv_keys::{
    Mnemonic, MnemonicType, Passphrase, Seed, derive_key,
    bip44::{derive_address_from_key, derive_all_chain_keys},
};
use csv_protocol::signature::SignatureScheme;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Wallet configuration
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Wallet ID
    pub id: String,
    /// Chains this wallet supports
    pub chains: Vec<String>,
    /// Whether to use test mode (for development)
    pub test_mode: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            chains: vec![
                "bitcoin".to_string(),
                "ethereum".to_string(),
                "solana".to_string(),
                "sui".to_string(),
                "aptos".to_string(),
            ],
            test_mode: false,
        }
    }
}

/// Unified wallet manager
///
/// This provides a centralized wallet interface that consolidates
/// wallet logic from csv-keys, csv-coordinator, csv-sdk, and chain adapters.
pub struct WalletManager {
    /// Wallet configuration
    config: WalletConfig,
    /// Key store for managing secrets
    keystore: Arc<RwLock<KeyStore>>,
    /// Signers for each chain
    signers: Arc<RwLock<HashMap<String, Box<dyn Signer>>>>,
}

impl WalletManager {
    /// Create a new wallet manager
    ///
    /// # Arguments
    /// * `config` - Wallet configuration
    pub fn new(config: WalletConfig) -> Self {
        Self {
            config,
            keystore: Arc::new(RwLock::new(KeyStore::new())),
            signers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize a wallet from a mnemonic phrase
    ///
    /// # Arguments
    /// * `config` - Wallet configuration
    /// * `mnemonic` - BIP-39 mnemonic phrase
    /// * `passphrase` - Optional BIP-39 passphrase
    ///
    /// # Returns
    /// The wallet manager with initialized keys
    pub fn from_mnemonic(
        config: WalletConfig,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        // Parse mnemonic and derive seed using csv-keys
        let seed = csv_keys::restore_from_mnemonic(mnemonic, passphrase)
            .map_err(|e| WalletError::KeyGeneration(format!("Failed to restore from mnemonic: {}", e)))?;
        
        let wallet = Self::new(config);
        
        // Derive keys for each configured chain
        let mut signers_map = HashMap::new();
        for chain in &wallet.config.chains {
            let chain_id = ChainId::new(chain);
            let key = derive_key(seed.as_bytes(), &chain_id, 0, 0)
                .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive key for {}: {}", chain, e)))?;
            
            // Store the key in the keystore
            let mut keystore = wallet.keystore.write().unwrap();
            keystore.add_key(
                format!("{}:0:0", chain),
                key.to_vec(),
                KeyPurpose::Signing,
                chain.clone(),
            );
            
            // Create a signer for this chain
            let scheme = match chain.as_str() {
                "ethereum" => SignatureScheme::Secp256k1,
                "bitcoin" => SignatureScheme::Secp256k1,
                "solana" => SignatureScheme::Ed25519,
                "sui" => SignatureScheme::Ed25519,
                "aptos" => SignatureScheme::Ed25519,
                _ => SignatureScheme::Secp256k1,
            };
            
            let signer = Box::new(MemorySigner::new(
                format!("{}:0:0", chain),
                chain.clone(),
                key.to_vec(),
                vec![0u8; 32], // Placeholder public key
                scheme,
            ));
            
            signers_map.insert(chain.clone(), signer);
        }
        
        // Now insert all signers at once
        {
            let mut signers = wallet.signers.write().unwrap();
            for (chain, signer) in signers_map {
                signers.insert(chain, signer);
            }
        } // Drop the write guard before returning
        
        Ok(wallet)
    }

    /// Create a new wallet with a randomly generated mnemonic
    ///
    /// # Arguments
    /// * `config` - Wallet configuration
    ///
    /// # Returns
    /// Tuple of (wallet manager, mnemonic phrase)
    pub fn generate(config: WalletConfig) -> Result<(Self, String)> {
        // Generate mnemonic using csv-keys
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        
        let wallet = Self::from_mnemonic(config, &phrase, None)?;
        Ok((wallet, phrase))
    }

    /// Add a signer for a specific chain
    ///
    /// # Arguments
    /// * `chain` - Chain identifier
    /// * `signer` - Signer implementation
    pub fn add_signer(&self, chain: String, signer: Box<dyn Signer>) {
        let mut signers = self.signers.write().unwrap();
        signers.insert(chain, signer);
    }

    /// Get a signer for a specific chain
    ///
    /// # Arguments
    /// * `chain` - Chain identifier
    ///
    /// # Returns
    /// The signer if found
    pub fn get_signer(&self, chain: &str) -> Option<Box<dyn Signer>> {
        let signers = self.signers.read().unwrap();
        // Clone the signer reference (actual implementation would need proper cloning)
        // For now, return None as we can't clone trait objects
        None
    }

    /// Get a signer reference for a specific chain
    ///
    /// # Arguments
    /// * `chain` - Chain identifier
    ///
    /// # Returns
    /// The signer reference if found
    pub fn get_signer_ref(&self, chain: &str) -> Option<SignerRef> {
        let signers = self.signers.read().unwrap();
        signers.get(chain).map(|s| Signer::as_ref(s.as_ref()))
    }

    /// Sign a message using the appropriate chain's signer
    ///
    /// # Arguments
    /// * `chain` - Chain identifier
    /// * `message` - Message bytes to sign
    ///
    /// # Returns
    /// The signature
    pub async fn sign(&self, chain: &str, message: &[u8]) -> Result<crate::signer::Signature> {
        let signers = self.signers.read().unwrap();
        let signer = signers.get(chain)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;
        signer.sign(message).await
    }

    /// Get the wallet configuration
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Get the key store
    pub fn keystore(&self) -> Arc<RwLock<KeyStore>> {
        Arc::clone(&self.keystore)
    }
}

/// Static wallet operations for address derivation (similar to csv-coordinator)
///
/// These functions take seed as input and don't require a WalletManager instance.
/// This is useful for CLI operations where the mnemonic/seed is already available.
pub mod address {
    use super::*;
    use csv_keys::bip44::{derive_all_chain_keys, derive_address_from_key};

    /// Derive a funding address for a specific chain from seed
    ///
    /// # Arguments
    /// * `seed` - 64-byte BIP-39 seed
    /// * `chain` - Chain identifier
    /// * `account` - Account index
    /// * `index` - Address index
    ///
    /// # Returns
    /// The derived address as a string
    pub fn derive_funding_address(
        seed: &[u8],
        chain: &str,
        account: u32,
        index: u32,
    ) -> Result<String> {
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

        let chain_id = ChainId::new(chain);

        // Derive keys for all chains
        let keys = derive_all_chain_keys(&seed_array, account);

        // Get the key for the requested chain
        let key = keys
            .get(&chain_id)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;

        // Derive address from key
        let address = derive_address_from_key(key.expose_secret(), &chain_id)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;

        Ok(address)
    }
}

/// Bitcoin-specific wallet operations
pub mod bitcoin {
    use super::*;
    use csv_keys::bip44::{derive_all_chain_keys, derive_address_from_key};

    /// Network type for Bitcoin wallet operations
    #[derive(Debug, Clone, Copy)]
    pub enum Network {
        Main,
        Test,
        Dev,
    }

    /// UTXO data structure
    #[derive(Debug, Clone)]
    pub struct WalletUtxo {
        pub txid: String,
        pub vout: u32,
        pub value: u64,
        pub scriptpubkey_hex: Option<String>,
    }

    /// Derive a Bitcoin funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<String> {
        // Use the generic address derivation with Bitcoin-specific network handling
        // Note: csv-keys handles network internally for Bitcoin
        address::derive_funding_address(seed, "bitcoin", account, index)
    }

    /// Scan for UTXOs on Bitcoin network
    ///
    /// # Arguments
    /// * `seed` - 64-byte BIP-39 seed
    /// * `network` - Bitcoin network
    /// * `account` - Account index
    /// * `gap_limit` - Number of addresses to scan
    /// * `rpc_url` - RPC URL for UTXO queries
    ///
    /// # Returns
    /// Vector of found UTXOs
    pub async fn scan_utxos(
        seed: &[u8],
        network: Network,
        account: u32,
        gap_limit: usize,
        rpc_url: &str,
    ) -> Result<Vec<WalletUtxo>> {
        let mut wallet_utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let address = derive_funding_address(seed, network, account, index)?;

            // Fetch UTXOs for this address using mempool RPC
            let url = format!("{}/address/{}/utxo", rpc_url, address);
            let response = reqwest::get(&url).await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let utxo_list: Vec<serde_json::Value> = resp
                        .json()
                        .await
                        .map_err(|e| WalletError::SigningFailed(format!("Failed to parse UTXO response: {}", e)))?;

                    for utxo in utxo_list {
                        let txid = utxo
                            .get("txid")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| WalletError::InvalidFormat("Missing txid".to_string()))?
                            .to_string();
                        let vout = utxo
                            .get("vout")
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| WalletError::InvalidFormat("Missing vout".to_string()))? as u32;
                        let value = utxo
                            .get("value")
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| WalletError::InvalidFormat("Missing value".to_string()))?;
                        let scriptpubkey_hex = utxo.get("scriptpubkey").and_then(|v| v.as_str()).map(|s| s.to_string());

                        wallet_utxos.push(WalletUtxo {
                            txid,
                            vout,
                            value,
                            scriptpubkey_hex,
                        });
                    }
                }
                Ok(resp) => {
                    log::warn!("Failed to fetch UTXOs for address {}: HTTP {}", address, resp.status());
                }
                Err(e) => {
                    log::warn!("Failed to fetch UTXOs for address {}: {}", address, e);
                }
            }
        }

        Ok(wallet_utxos)
    }
}

/// Wallet interface for chain-agnostic operations
pub trait Wallet: Send + Sync {
    /// Sign a message
    async fn sign(&self, chain: &str, message: &[u8]) -> Result<crate::signer::Signature>;

    /// Get public key for a chain
    fn public_key(&self, chain: &str) -> Result<Vec<u8>>;

    /// Get wallet ID
    fn id(&self) -> &str;
}

impl Wallet for WalletManager {
    async fn sign(&self, chain: &str, message: &[u8]) -> Result<crate::signer::Signature> {
        self.sign(chain, message).await
    }

    fn public_key(&self, chain: &str) -> Result<Vec<u8>> {
        let signers = self.signers.read().unwrap();
        let signer = signers.get(chain)
            .ok_or_else(|| WalletError::UnsupportedChain(chain.to_string()))?;
        Ok(signer.public_key().to_vec())
    }

    fn id(&self) -> &str {
        &self.config.id
    }
}
