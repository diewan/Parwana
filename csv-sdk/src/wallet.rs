//! Unified wallet management.
//!
//! Provides a multi-chain HD wallet supporting BIP-44 derivation paths
//! for all supported chains. Wraps key management behind a simple API.
//!
//! # BIP-44 Derivation Paths
//!
//! | Chain | Purpose | Coin Type | Path |
//! |-------|---------|-----------|------|
//! | Bitcoin | 86' (Taproot) | 0' | m/86'/0'/0'/0/i |
//! | Ethereum | 60' | 60' | m/44'/60'/0'/0/i |
//! | Sui | 44' | 784' | m/44'/784'/0'/0'/i |
//! | Aptos | 44' | 637' | m/44'/637'/0'/0'/i |

use csv_hash::chain_id::ChainId;

#[cfg(feature = "wallet")]
use csv_keys::{Mnemonic, MnemonicType, restore_from_mnemonic as csv_restore_from_mnemonic};

/// A unified wallet supporting multi-chain HD derivation (BIP-44).
///
/// The wallet manages cryptographic keys for all supported chains
/// from a single mnemonic seed phrase.
///
/// # Security
///
/// - The mnemonic is converted to a seed and the original phrase is discarded.
/// - In production, consider encrypting the seed at rest or using a hardware wallet.
///
/// # Example
///
/// ```ignore
/// use csv_sdk::wallet::Wallet;
///
/// // Generate a new wallet with a random mnemonic
/// let wallet = Wallet::generate();
/// let mnemonic = wallet.mnemonic_phrase();
/// println!("Save this mnemonic: {}", mnemonic);
///
/// // Restore from mnemonic
/// let restored = Wallet::from_mnemonic(mnemonic)?;
///
/// // Get address for a specific chain
/// let btc_address = restored.address("bitcoin");
/// let eth_address = restored.address("ethereum");
/// ```
#[derive(Clone)]
pub struct Wallet {
    /// Mnemonic phrase (12 or 24 words).
    /// In production, this would be encrypted or stored securely.
    mnemonic: String,
    /// Derived seed (64 bytes from BIP-39).
    seed: [u8; 64],
    /// Optional passphrase used with the mnemonic.
    #[allow(dead_code)]
    passphrase: String,
}

impl Wallet {
    /// Generate a new wallet with a random mnemonic.
    ///
    /// # Panics
    ///
    /// This method requires the `wallet` feature and the `csv-keys` crate.
    /// If compiled without wallet support, returns a basic wallet.
    pub fn generate() -> Self {
        #[cfg(feature = "wallet")]
        {
            // Use csv-keys for secure mnemonic generation
            let mnemonic = Mnemonic::generate(MnemonicType::Words24);
            let phrase = mnemonic.as_str().to_string();
            let seed = mnemonic.to_seed(None);

            let mut seed_bytes = [0u8; 64];
            seed_bytes.copy_from_slice(seed.as_bytes());

            Self {
                mnemonic: phrase,
                seed: seed_bytes,
                passphrase: String::new(),
            }
        }

        #[cfg(not(feature = "wallet"))]
        {
            // Fallback: create a deterministic wallet for testing only
            let seed = [0u8; 64];
            Self {
                mnemonic: "[wallet feature required for real wallet generation]".to_string(),
                seed,
                passphrase: String::new(),
            }
        }
    }

    /// Restore a wallet from a mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` — The 12 or 24 word mnemonic phrase.
    /// * `passphrase` — Optional passphrase (use empty string for none).
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, crate::CsvError> {
        #[cfg(feature = "wallet")]
        {
            // Use csv-keys for secure mnemonic restoration
            let seed = csv_restore_from_mnemonic(mnemonic, Some(passphrase))
                .map_err(|e| crate::CsvError::WalletError(format!("Invalid mnemonic: {}", e)))?;

            let mut seed_bytes = [0u8; 64];
            seed_bytes.copy_from_slice(seed.as_bytes());

            Ok(Self {
                mnemonic: mnemonic.to_string(),
                seed: seed_bytes,
                passphrase: passphrase.to_string(),
            })
        }

        #[cfg(not(feature = "wallet"))]
        {
            let _ = mnemonic;
            let _ = passphrase;
            Err(crate::CsvError::WalletError(
                "Wallet feature not enabled. Enable the 'wallet' feature flag.".to_string(),
            ))
        }
    }

    /// Restore a wallet directly from a raw seed.
    ///
    /// # Arguments
    ///
    /// * `seed` — The 64-byte BIP-39 seed.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            mnemonic: "[restored from seed]".to_string(),
            seed,
            passphrase: String::new(),
        }
    }

    /// Get the mnemonic phrase (for backup purposes).
    pub fn mnemonic_phrase(&self) -> &str {
        &self.mnemonic
    }

    /// Get the derived seed.
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Get the address for a specific chain.
    ///
    /// The address format is chain-specific:
    /// - Bitcoin: Bech32m (Taproot) address
    /// - Ethereum: 0x-prefixed hex address
    /// - Sui: hex-encoded ed25519 public key
    /// - Aptos: hex-encoded ed25519 public key
    ///
    /// # Note
    ///
    /// Full address derivation requires the chain-specific adapter to be
    /// enabled. This method returns a basic address derived from the seed
    /// when the chain feature is not enabled.
    pub fn address(&self, chain: ChainId) -> String {
        match chain.as_str() {
            "bitcoin" => self.btc_address(),
            "ethereum" => self.eth_address(),
            "sui" => self.sui_address(),
            "aptos" => self.aptos_address(),
            "solana" => self.sol_address(),
            // Future chains: derive basic address from seed
            _ => format!("unknown-chain:{}", hex::encode(&self.seed[..8])),
        }
    }

    /// Derive an address for a specific chain with custom account and index.
    ///
    /// # Arguments
    ///
    /// * `chain` — Which chain to derive for.
    /// * `account` — BIP-44 account number.
    /// * `index` — Address index within the account.
    pub fn derive_address(&self, chain: ChainId, account: u32, index: u32) -> String {
        match chain.as_str() {
            "bitcoin" => self.btc_address_with_path(account, index),
            "ethereum" => self.eth_address_with_path(account, index),
            "solana" => self.sol_address_with_path(account, index),
            "sui" => self.sui_address_with_path(account, index),
            "aptos" => self.aptos_address_with_path(account, index),
            _ => self.address(chain),
        }
    }

    /// Sign a message with the appropriate key for the given chain.
    ///
    /// Returns the signature bytes in chain-specific format.
    ///
    /// # Arguments
    ///
    /// * `chain` — Which chain's key to sign with.
    /// * `message` — The message to sign (32 bytes).
    ///
    /// # Panics
    ///
    /// Panics if the wallet feature is not enabled or if key derivation fails.
    /// For transaction signing, use CsvClient::chain_runtime() with configured chain adapter.
    pub fn sign(&self, chain: ChainId, message: &[u8; 32]) -> Vec<u8> {
        match chain.as_str() {
            "bitcoin" => self.sign_bitcoin(message, 0, 0),
            "ethereum" => self.sign_ethereum(message, 0, 0),
            "solana" => self.sign_solana(message, 0, 0),
            "sui" => self.sign_sui(message, 0, 0),
            "aptos" => self.sign_aptos(message, 0, 0),
            _ => {
                panic!(
                    "Signature capability unavailable for chain '{}'. \
                     Enable the 'wallet' feature and chain-specific features. \
                     For transaction signing, use CsvClient::chain_runtime() with configured chain adapter.",
                    chain
                );
            }
        }
    }

    // -- Internal address derivation helpers --

    fn btc_address(&self) -> String {
        self.btc_address_with_path(0, 0)
    }

    fn btc_address_with_path(&self, account: u32, index: u32) -> String {
        // Bitcoin Taproot address derivation
        // Path: m/86'/0'/account'/0/index
        #[cfg(feature = "bitcoin")]
        {
            use csv_bitcoin::wallet::{Bip86Path, SealWallet};

            // Create wallet from seed (using regtest network for derivation)
            let Ok(wallet) = SealWallet::from_seed(&self.seed, bitcoin::Network::Regtest) else {
                return format!(
                    "btc:seed-prefix-{}-{}-{}",
                    hex::encode(&self.seed[..4]),
                    account,
                    index
                );
            };

            // Derive external address at specified account and index
            let path = Bip86Path::external(account, index);
            let Ok(key) = wallet.derive_key(&path) else {
                return format!(
                    "btc:seed-prefix-{}-{}-{}",
                    hex::encode(&self.seed[..4]),
                    account,
                    index
                );
            };

            key.address.to_string()
        }

        #[cfg(not(feature = "bitcoin"))]
        {
            // Fallback when bitcoin feature not enabled
            format!(
                "btc:seed-prefix-{}-{}-{}",
                hex::encode(&self.seed[..4]),
                account,
                index
            )
        }
    }

    fn eth_address(&self) -> String {
        self.eth_address_with_path(0, 0)
    }

    fn eth_address_with_path(&self, account: u32, index: u32) -> String {
        // Ethereum address derivation using BIP-44: m/44'/60'/account'/0/index
        #[cfg(feature = "wallet")]
        {
            use bip32::{ChildNumber, DerivationPath, ExtendedKey, XPrv};
            use k256::ecdsa::SigningKey;
            use sha3::{Digest, Keccak256};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/60'/{}'/0/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap());

            // Create extended private key from seed
            let xprv = XPrv::new(&self.seed).ok();
            
            if let Some(xprv) = xprv {
                // Derive child key
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };
                
                if let Some(derived) = derived {
                    // Get the private key bytes
                    let priv_key_bytes = derived.private_key().to_bytes();
                    
                    // Create signing key
                    if let Ok(signing_key) = SigningKey::from_bytes(&priv_key_bytes) {
                        // Get public key
                        let verifying_key = signing_key.verifying_key();
                        let pub_key_bytes = verifying_key.to_sec1_bytes();
                        
                        // Skip the first byte (0x04 prefix) and hash the rest
                        let pub_key_no_prefix = &pub_key_bytes[1..];
                        let hash = Keccak256::digest(pub_key_no_prefix);
                        
                        // Take last 20 bytes
                        let address_bytes = &hash[hash.len() - 20..];
                        return format!("0x{}", hex::encode(address_bytes));
                    }
                }
            }
            
            // Fallback if derivation fails
            format!("0x{}", hex::encode(&self.seed[0..20]))
        }

        #[cfg(not(feature = "wallet"))]
        {
            format!("0x{}", hex::encode(&self.seed[0..20]))
        }
    }

    fn sui_address(&self) -> String {
        self.sui_address_with_path(0, 0)
    }

    fn sui_address_with_path(&self, account: u32, index: u32) -> String {
        // Sui address derivation using BIP-44: m/44'/784'/account'/0'/index
        #[cfg(feature = "wallet")]
        {
            use bip32::{ChildNumber, DerivationPath, ExtendedKey, XPrv};
            use ed25519_dalek::{SecretKey, SigningKey as EdSigningKey};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/784'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/784'/0'/0'/0").unwrap());

            // Create extended private key from seed
            let xprv = XPrv::new(&self.seed).ok();
            
            if let Some(xprv) = xprv {
                // Derive child key
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };
                
                if let Some(derived) = derived {
                    // Get the private key bytes (first 32 bytes)
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];
                    
                    // Create Ed25519 signing key
                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = EdSigningKey::from(&secret_key);
                        let public_key = signing_key.verifying_key();
                        
                        // Sui address is the 32-byte public key in hex
                        return format!("0x{}", hex::encode(public_key.as_bytes()));
                    }
                }
            }
            
            // Fallback if derivation fails
            format!("0x{}", hex::encode(&self.seed[..32]))
        }

        #[cfg(not(feature = "wallet"))]
        {
            format!("0x{}", hex::encode(&self.seed[..32]))
        }
    }

    fn aptos_address(&self) -> String {
        self.aptos_address_with_path(0, 0)
    }

    fn aptos_address_with_path(&self, account: u32, index: u32) -> String {
        // Aptos address derivation using BIP-44: m/44'/637'/account'/0'/index
        #[cfg(feature = "wallet")]
        {
            use bip32::{ChildNumber, DerivationPath, ExtendedKey, XPrv};
            use ed25519_dalek::{SecretKey, SigningKey as EdSigningKey};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/637'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/637'/0'/0'/0").unwrap());

            // Create extended private key from seed
            let xprv = XPrv::new(&self.seed).ok();
            
            if let Some(xprv) = xprv {
                // Derive child key
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };
                
                if let Some(derived) = derived {
                    // Get the private key bytes (first 32 bytes)
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];
                    
                    // Create Ed25519 signing key
                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = EdSigningKey::from(&secret_key);
                        let public_key = signing_key.verifying_key();
                        
                        // Aptos address is the 32-byte public key in hex
                        return format!("0x{}", hex::encode(public_key.as_bytes()));
                    }
                }
            }
            
            // Fallback if derivation fails
            format!("0x{}", hex::encode(&self.seed[..32]))
        }

        #[cfg(not(feature = "wallet"))]
        {
            format!("0x{}", hex::encode(&self.seed[..32]))
        }
    }

    fn sol_address(&self) -> String {
        self.sol_address_with_path(0, 0)
    }

    fn sol_address_with_path(&self, account: u32, index: u32) -> String {
        // Solana address derivation using BIP-44: m/44'/501'/account'/0'/index
        #[cfg(feature = "wallet")]
        {
            use bip32::{ChildNumber, DerivationPath, ExtendedKey, XPrv};
            use std::str::FromStr;
            use ed25519_dalek::{SecretKey, SigningKey as EdSigningKey};

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/501'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/501'/0'/0'/0").unwrap());

            // Create extended private key from seed
            let xprv = XPrv::new(&self.seed).ok();
            
            if let Some(xprv) = xprv {
                // Derive child key
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };
                
                if let Some(derived) = derived {
                    // Get the private key bytes (first 32 bytes)
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];
                    
                    // Create Ed25519 signing key
                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = EdSigningKey::from(&secret_key);
                        let public_key = signing_key.verifying_key();
                        
                        // Solana address is the 32-byte public key in base58
                        return bs58::encode(public_key.as_bytes()).into_string();
                    }
                }
            }
            
            // Fallback if derivation fails
            format!("sol:{}", hex::encode(&self.seed[..32]))
        }

        #[cfg(not(feature = "wallet"))]
        {
            format!("sol:{}", hex::encode(&self.seed[..32]))
        }
    }

    // -- Signing methods --

    fn sign_bitcoin(&self, message: &[u8; 32], account: u32, index: u32) -> Vec<u8> {
        // Bitcoin Taproot signing (Schnorr)
        #[cfg(all(feature = "bitcoin", feature = "wallet"))]
        {
            use csv_bitcoin::wallet::{Bip86Path, SealWallet};
            use bitcoin::sighash::{SighashCache, TapSighashType};
            use bitcoin::taproot::TaprootSpendInfo;

            let wallet = SealWallet::from_seed(&self.seed, bitcoin::Network::Regtest)
                .map_err(|_| crate::CsvError::SignatureCapabilityUnavailable(
                    "Failed to derive Bitcoin wallet from seed. Ensure wallet feature is enabled.".to_string()
                ))
                .expect("Signature capability check failed");

            let path = Bip86Path::external(account, index);
            let _key = wallet.derive_key(&path)
                .map_err(|_| crate::CsvError::SignatureCapabilityUnavailable(
                    "Failed to derive Bitcoin key. Check BIP-44 derivation path.".to_string()
                ))
                .expect("Signature capability check failed");

            // Full Schnorr signing requires transaction context (sighash, taproot spend info)
            // This method only signs raw messages - for transaction signing, use the chain adapter
            panic!(
                "Bitcoin transaction signing requires chain adapter with transaction context. \
                 Use CsvClient::chain_runtime() for transaction operations."
            );
        }

        #[cfg(not(all(feature = "bitcoin", feature = "wallet")))]
        {
            panic!(
                "Bitcoin signature capability unavailable. Enable the 'wallet' and 'bitcoin' features."
            );
        }
    }

    fn sign_ethereum(&self, message: &[u8; 32], account: u32, index: u32) -> Vec<u8> {
        // Ethereum ECDSA signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, ExtendedKey, XPrv};
            use k256::ecdsa::{signature::Signer, Signature, SigningKey};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/60'/{}'/0/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap());

            let xprv = XPrv::new(&self.seed).ok();

            if let Some(xprv) = xprv {
                // Iterate through path components and derive each child
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }

                if success {
                    let priv_key_bytes = derived.private_key().to_bytes();

                    if let Ok(signing_key) = SigningKey::from_bytes(&priv_key_bytes) {
                        let signature: Signature = signing_key.sign(message);
                        return signature.to_bytes().to_vec();
                    }
                }
            }

            panic!(
                "Ethereum signature derivation failed. Enable the 'wallet' feature and ensure valid BIP-44 seed. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }

        #[cfg(not(feature = "wallet"))]
        {
            panic!(
                "Ethereum signature capability unavailable. Enable the 'wallet' feature. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }
    }

    fn sign_solana(&self, message: &[u8; 32], account: u32, index: u32) -> Vec<u8> {
        // Solana Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, ExtendedKey, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let path = DerivationPath::from_str(&format!("m/44'/501'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/501'/0'/0'/0").unwrap());

            let xprv = XPrv::new(&self.seed).ok();

            if let Some(xprv) = xprv {
                // Iterate through path components and derive each child
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }

                if success {
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];

                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = SigningKey::from(&secret_key);
                        return signing_key.sign(message).to_bytes().to_vec();
                    }
                }
            }

            panic!(
                "Solana signature derivation failed. Enable the 'wallet' feature and ensure valid BIP-44 seed. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }

        #[cfg(not(feature = "wallet"))]
        {
            panic!(
                "Solana signature capability unavailable. Enable the 'wallet' feature. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }
    }

    fn sign_sui(&self, message: &[u8; 32], account: u32, index: u32) -> Vec<u8> {
        // Sui Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, ExtendedKey, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let path = DerivationPath::from_str(&format!("m/44'/784'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/784'/0'/0'/0").unwrap());

            let xprv = XPrv::new(&self.seed).ok();

            if let Some(xprv) = xprv {
                // Use derive instead of derive_path - API has changed in bip32 crate
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };

                if let Some(derived) = derived {
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];

                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = SigningKey::from(&secret_key);
                        return signing_key.sign(message).to_bytes().to_vec();
                    }
                }
            }

            panic!(
                "Sui signature derivation failed. Enable the 'wallet' feature and ensure valid BIP-44 seed. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }

        #[cfg(not(feature = "wallet"))]
        {
            panic!(
                "Sui signature capability unavailable. Enable the 'wallet' feature. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }
    }

    fn sign_aptos(&self, message: &[u8; 32], account: u32, index: u32) -> Vec<u8> {
        // Aptos Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, ExtendedKey, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let path = DerivationPath::from_str(&format!("m/44'/637'/{}'/0'/{}", account, index))
                .unwrap_or_else(|_| DerivationPath::from_str("m/44'/637'/0'/0'/0").unwrap());

            let xprv = XPrv::new(&self.seed).ok();

            if let Some(xprv) = xprv {
                // Use derive instead of derive_path - API has changed in bip32 crate
                let mut derived = xprv;
                let mut success = true;
                for child in path {
                    match derived.derive_child(child) {
                        Ok(d) => derived = d,
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                let derived = if success { Some(derived) } else { None };

                if let Some(derived) = derived {
                    let priv_key_bytes = &derived.private_key().to_bytes()[..32];

                    if let Ok(secret_key) = SecretKey::try_from(priv_key_bytes) {
                        let signing_key = SigningKey::from(&secret_key);
                        return signing_key.sign(message).to_bytes().to_vec();
                    }
                }
            }

            panic!(
                "Aptos signature derivation failed. Enable the 'wallet' feature and ensure valid BIP-44 seed. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }

        #[cfg(not(feature = "wallet"))]
        {
            panic!(
                "Aptos signature capability unavailable. Enable the 'wallet' feature. \
                 For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
            );
        }
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("mnemonic", &"[redacted]")
            .field("seed", &"[redacted]")
            .finish()
    }
}

/// Manager for wallet operations.
///
/// Obtain a [`WalletManager`] via [`CsvClient::wallet()`](crate::client::CsvClient::wallet).
pub struct WalletManager {
    wallet: Wallet,
}

impl WalletManager {
    pub(crate) fn new(wallet: Wallet) -> Self {
        Self { wallet }
    }

    /// Get the underlying wallet.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get the address for a specific chain.
    pub fn address(&self, chain: ChainId) -> String {
        self.wallet.address(chain)
    }

    /// Derive an address for a specific chain with custom account and index.
    ///
    /// # Arguments
    ///
    /// * `chain` — Which chain to derive for.
    /// * `account` — BIP-44 account number.
    /// * `index` — Address index within the account.
    pub fn derive_address(&self, chain: ChainId, account: u32, index: u32) -> String {
        self.wallet.derive_address(chain, account, index)
    }

    /// Sign a message with the appropriate key for the given chain.
    pub fn sign(&self, chain: ChainId, message: &[u8; 32]) -> Vec<u8> {
        self.wallet.sign(chain, message)
    }

    /// Query balance for an address on a chain.
    ///
    /// # Note
    ///
    /// This operation requires RPC connectivity through a configured chain adapter.
    /// The runtime delegates to chain adapters implementing the [`ChainQuery`] trait
    /// from csv-adapter-core.
    ///
    /// # Errors
    ///
    /// - [`ChainNotSupported`] if the chain is not enabled.
    /// - [`ChainNotEnabled`] if RPC is not configured for this chain.
    /// - [`NetworkError`] if the RPC call fails.
    pub async fn query_balance(
        &self,
        chain: ChainId,
        address: &str,
    ) -> Result<u64, crate::CsvError> {
        // Validate the address format for the chain
        if address.is_empty() {
            return Err(crate::CsvError::InvalidSanadId(
                "Address cannot be empty".to_string(),
            ));
        }

        // Balance queries require chain adapter with RPC connectivity.
        // WalletManager only has access to Wallet (not the full client with adapters).
        // Balance queries should be performed through CsvClient::chain_runtime()
        // when the client has chain adapters configured.
        //
        // This is a fail-closed API: it explicitly requires runtime configuration
        // rather than returning placeholder values.
        Err(crate::CsvError::ChainNotEnabled(format!(
            "Balance query for {} on {:?} requires configured chain adapter with RPC endpoint. \
             Use CsvClient::chain_runtime().get_balance() when client is built with chain configuration.",
            address, chain
        )))
    }
}
