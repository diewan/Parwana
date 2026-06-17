//! Wallet manager for unified wallet operations

use crate::error::{Result, WalletError};
use crate::keystore::{KeyStore, KeyPurpose};
use crate::signer::{MemorySigner, Signer, SignerRef};
use csv_hash::chain_id::ChainId;
use csv_keys::{
    Mnemonic, MnemonicType, Passphrase, Seed, derive_key,
    bip44::{derive_address_from_key, derive_all_chain_keys},
};
use csv_protocol::secret::SharedSecretHandle;
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
    /// Signers for each chain (Arc for cheap cloning)
    signers: Arc<RwLock<HashMap<String, Arc<dyn Signer>>>>,
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

    /// Derive the public key from a secret key for the given chain/scheme
    fn derive_public_key(secret_key: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>> {
        match scheme {
            SignatureScheme::Secp256k1 => {
                use secp256k1::{SecretKey, PublicKey, Secp256k1};
                let sk = SecretKey::from_slice(secret_key)
                    .map_err(|e| WalletError::KeyDerivation(format!("Invalid secp256k1 secret key: {}", e)))?;
                let secp = Secp256k1::new();
                let pk = PublicKey::from_secret_key(&secp, &sk);
                Ok(pk.serialize().to_vec())
            }
            SignatureScheme::Ed25519 => {
                use ed25519_dalek::{SigningKey, VerifyingKey};
                let sk = SigningKey::from_bytes(
                    secret_key.try_into().map_err(|_| {
                        WalletError::KeyDerivation("Invalid Ed25519 secret key: must be 32 bytes".to_string())
                    })?,
                );
                Ok(VerifyingKey::from(&sk).to_bytes().to_vec())
            }
            SignatureScheme::MlDsa65 => {
                Err(WalletError::KeyDerivation(
                    "ML-DSA-65 public key derivation not yet implemented".to_string(),
                ))
            }
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
            
            // Determine signature scheme for this chain
            let scheme = match chain.as_str() {
                "ethereum" => SignatureScheme::Secp256k1,
                "bitcoin" => SignatureScheme::Secp256k1,
                "solana" => SignatureScheme::Ed25519,
                "sui" => SignatureScheme::Ed25519,
                "aptos" => SignatureScheme::Ed25519,
                _ => SignatureScheme::Secp256k1,
            };
            
            // Derive the real public key from the secret key
            let public_key = Self::derive_public_key(&key.to_vec(), scheme)?;
            
            let signer = Arc::new(MemorySigner::new(
                format!("{}:0:0", chain),
                chain.clone(),
                key.to_vec(),
                public_key,
                scheme,
            ));
            
            signers_map.insert(chain.clone(), signer);
        }
        
        // Insert all signers at once
        {
            let mut signers = wallet.signers.write().unwrap();
            for (chain, signer) in signers_map {
                signers.insert(chain, signer);
            }
        }
        
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
    /// * `signer` - Signer implementation (wrapped in Arc)
    pub fn add_signer(&self, chain: String, signer: Arc<dyn Signer>) {
        let mut signers = self.signers.write().unwrap();
        signers.insert(chain, signer);
    }

    /// Get a signer for a specific chain
    ///
    /// # Arguments
    /// * `chain` - Chain identifier
    ///
    /// # Returns
    /// The signer wrapped in Arc if found, None if not found
    pub fn get_signer(&self, chain: &str) -> Option<Arc<dyn Signer>> {
        let signers = self.signers.read().unwrap();
        signers.get(chain).cloned()
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
        signers.get(chain).map(|arc| Signer::as_ref(arc.as_ref()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet_config() -> WalletConfig {
        WalletConfig {
            id: "test-wallet".to_string(),
            chains: vec!["ethereum".to_string(), "solana".to_string()],
            test_mode: true,
        }
    }

    #[test]
    fn test_wallet_generate() {
        let config = test_wallet_config();
        let (wallet, _mnemonic) = WalletManager::generate(config.clone()).unwrap();
        assert_eq!(wallet.config.id, "test-wallet");
        assert_eq!(wallet.config.chains, config.chains);
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();
        assert_eq!(wallet.config.id, "test-wallet");
    }

    #[test]
    fn test_get_signer_returns_arc() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        // get_signer should return Some(Arc<dyn Signer>) for configured chains
        let signer = wallet.get_signer("ethereum");
        assert!(signer.is_some(), "get_signer should return Some for ethereum");

        let signer = signer.unwrap();
        // Verify the signer has a real public key (not all zeros)
        let pk = signer.public_key();
        assert!(!pk.is_empty(), "Public key should not be empty");
        assert!(pk.iter().any(|&b| b != 0), "Public key should not be all zeros");
    }

    #[test]
    fn test_get_signer_unsupported_chain() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        // get_signer should return None for unsupported chains
        let signer = wallet.get_signer("bitcoin");
        assert!(signer.is_none(), "get_signer should return None for unsupported chain");
    }

    #[test]
    fn test_signer_public_key_not_placeholder() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        // Ethereum signer (secp256k1) should have a 33-byte compressed public key
        let eth_signer = wallet.get_signer("ethereum").unwrap();
        let eth_pk = eth_signer.public_key();
        assert_eq!(eth_pk.len(), 33, "secp256k1 compressed public key should be 33 bytes");
        assert!(eth_pk[0] == 0x02 || eth_pk[0] == 0x03, "secp256k1 compressed key should start with 0x02 or 0x03");

        // Solana signer (ed25519) should have a 32-byte public key
        let sol_signer = wallet.get_signer("solana").unwrap();
        let sol_pk = sol_signer.public_key();
        assert_eq!(sol_pk.len(), 32, "Ed25519 public key should be 32 bytes");
    }

    #[tokio::test]
    async fn test_sign_and_verify_roundtrip() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        // secp256k1 requires a 32-byte hash; Ed25519 accepts arbitrary length
        let message_32 = [0xABu8; 32];
        let message_ed = b"test message for ed25519 signing";

        // Sign with ethereum (secp256k1) - requires 32-byte hash
        let eth_sig = wallet.sign("ethereum", &message_32).await.unwrap();
        assert!(!eth_sig.bytes.is_empty(), "secp256k1 signature should not be empty");
        assert_eq!(eth_sig.scheme, SignatureScheme::Secp256k1);

        // Sign with solana (ed25519) - accepts arbitrary length
        let sol_sig = wallet.sign("solana", message_ed).await.unwrap();
        assert!(!sol_sig.bytes.is_empty(), "Ed25519 signature should not be empty");
        assert_eq!(sol_sig.scheme, SignatureScheme::Ed25519);
    }

    #[tokio::test]
    async fn test_sign_unsupported_chain_fails() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        let message = b"test message";
        let result = wallet.sign("bitcoin", message).await;
        assert!(result.is_err(), "Signing for unsupported chain should fail");
        match result.unwrap_err() {
            WalletError::UnsupportedChain(c) => assert_eq!(c, "bitcoin"),
            other => panic!("Expected UnsupportedChain error, got: {:?}", other),
        }
    }

    #[test]
    fn test_get_signer_ref() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        let ref_ = wallet.get_signer_ref("ethereum");
        assert!(ref_.is_some());
        let ref_ = ref_.unwrap();
        assert_eq!(ref_.chain, "ethereum");
        assert!(!ref_.public_key.is_empty());
    }

    #[test]
    fn test_wallet_public_key() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        let pk = wallet.public_key("ethereum").unwrap();
        assert!(!pk.is_empty());
        assert!(pk.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_wallet_public_key_unsupported() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        let result = wallet.public_key("bitcoin");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_signer() {
        let config = test_wallet_config();
        let wallet = WalletManager::new(config);

        // Add a signer for bitcoin (not in original config)
        let scheme = SignatureScheme::Secp256k1;
        let secret_key = vec![2u8; 32];
        let public_key = WalletManager::derive_public_key(&secret_key, scheme).unwrap();
        let signer = Arc::new(MemorySigner::new(
            "bitcoin:0:0".to_string(),
            "bitcoin".to_string(),
            secret_key,
            public_key,
            scheme,
        ));
        wallet.add_signer("bitcoin".to_string(), signer);

        // Verify we can retrieve it
        let retrieved = wallet.get_signer("bitcoin");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.chain(), "bitcoin");
    }

    #[test]
    fn test_signer_arc_cloning() {
        let config = test_wallet_config();
        let mnemonic = Mnemonic::generate(MnemonicType::Words24);
        let phrase = mnemonic.as_str().to_string();
        let wallet = WalletManager::from_mnemonic(config, &phrase, None).unwrap();

        // Get two references to the same signer
        let signer1 = wallet.get_signer("ethereum").unwrap();
        let signer2 = wallet.get_signer("ethereum").unwrap();

        // They should be the same Arc (same strong count)
        assert!(Arc::ptr_eq(&signer1, &signer2), "get_signer should return cloned Arc pointing to same signer");
    }
}
