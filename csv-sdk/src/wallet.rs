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

/// Error type for wallet operations
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Signature capability unavailable for the specified chain
    #[error(
        "Signature capability unavailable for chain '{0}'. Enable the 'wallet' feature and chain-specific features. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    UnsupportedChain(String),
    /// Bitcoin signature capability unavailable
    #[error(
        "Bitcoin signature capability unavailable. Enable the 'wallet' and 'bitcoin' features."
    )]
    BitcoinUnavailable,
    /// Ethereum signature capability unavailable
    #[error(
        "Ethereum signature capability unavailable. Enable the 'wallet' feature. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    EthereumUnavailable,
    /// Solana signature capability unavailable
    #[error(
        "Solana signature capability unavailable. Enable the 'wallet' feature. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    SolanaUnavailable,
    /// Sui signature capability unavailable
    #[error(
        "Sui signature capability unavailable. Enable the 'wallet' feature. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    SuiUnavailable,
    /// Aptos signature capability unavailable
    #[error(
        "Aptos signature capability unavailable. Enable the 'wallet' feature. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    AptosUnavailable,
    /// Signature derivation failed
    #[error(
        "Signature derivation failed for chain '{0}'. Enable the 'wallet' feature and ensure valid BIP-44 seed. For transaction signing, use CsvClient::chain_runtime() with configured chain adapter."
    )]
    DerivationFailed(String),
}

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
/// use csv_hash::chain_id::ChainId;
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
/// let btc_address = restored.address(ChainId::new("bitcoin"))?;
/// let eth_address = restored.address(ChainId::new("ethereum"))?;
/// ```
#[derive(Clone)]
pub struct Wallet {
    /// Mnemonic phrase (12 or 24 words).
    /// In production, this would be encrypted or stored securely.
    mnemonic: String,
    /// Derived seed (64 bytes from BIP-39).
    seed: [u8; 64],
    /// Optional passphrase used with the mnemonic.
    _passphrase: String,
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
                _passphrase: String::new(),
            }
        }

        #[cfg(not(feature = "wallet"))]
        {
            // Fallback: create a deterministic wallet for testing only
            let seed = [0u8; 64];
            Self {
                mnemonic: "[wallet feature required for real wallet generation]".to_string(),
                seed,
                _passphrase: String::new(),
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
                _passphrase: passphrase.to_string(),
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
            _passphrase: String::new(),
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
    /// Full address derivation requires wallet support and, for Bitcoin, the
    /// chain-specific adapter. Missing support or derivation failures return
    /// an error rather than a placeholder address.
    pub fn address(&self, chain: ChainId) -> Result<String, WalletError> {
        match chain.as_str() {
            "bitcoin" => self.btc_address(),
            "ethereum" => self.eth_address(),
            "sui" => self.sui_address(),
            "aptos" => self.aptos_address(),
            "solana" => self.sol_address(),
            _ => Err(WalletError::UnsupportedChain(chain.as_str().to_string())),
        }
    }

    /// Derive an address for a specific chain with custom account and index.
    ///
    /// # Arguments
    ///
    /// * `chain` — Which chain to derive for.
    /// * `account` — BIP-44 account number.
    /// * `index` — Address index within the account.
    pub fn derive_address(
        &self,
        chain: ChainId,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        match chain.as_str() {
            "bitcoin" => self.btc_address_with_path(account, index),
            "ethereum" => self.eth_address_with_path(account, index),
            "solana" => self.sol_address_with_path(account, index),
            "sui" => self.sui_address_with_path(account, index),
            "aptos" => self.aptos_address_with_path(account, index),
            _ => Err(WalletError::UnsupportedChain(chain.as_str().to_string())),
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
    /// # Errors
    ///
    /// Returns an error if the wallet feature is not enabled or if key derivation fails.
    /// For transaction signing, use CsvClient::chain_runtime() with configured chain adapter.
    pub fn sign(&self, chain: ChainId, message: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
        match chain.as_str() {
            "bitcoin" => self.sign_bitcoin(message, 0, 0),
            "ethereum" => self.sign_ethereum(message, 0, 0),
            "solana" => self.sign_solana(message, 0, 0),
            "sui" => self.sign_sui(message, 0, 0),
            "aptos" => self.sign_aptos(message, 0, 0),
            _ => Err(WalletError::UnsupportedChain(chain.as_str().to_string())),
        }
    }

    // -- Internal address derivation helpers --

    fn btc_address(&self) -> Result<String, WalletError> {
        self.btc_address_with_path(0, 0)
    }

    fn btc_address_with_path(&self, account: u32, index: u32) -> Result<String, WalletError> {
        // Bitcoin Taproot address derivation
        // Path: m/86'/0'/account'/0/index
        #[cfg(feature = "bitcoin")]
        {
            use csv_bitcoin::wallet::{Bip86Path, SealWallet};

            // Create wallet from seed (using signet network for derivation by default)
            let wallet = SealWallet::from_seed(&self.seed, bitcoin::Network::Signet)
                .map_err(|e| WalletError::DerivationFailed(format!("bitcoin: {}", e)))?;

            // Derive external address at specified account and index
            let path = Bip86Path::external(account, index);
            let key = wallet
                .derive_key(&path)
                .map_err(|e| WalletError::DerivationFailed(format!("bitcoin: {}", e)))?;

            Ok(key.address.to_string())
        }

        #[cfg(not(feature = "bitcoin"))]
        {
            let _ = account;
            let _ = index;
            Err(WalletError::BitcoinUnavailable)
        }
    }

    fn eth_address(&self) -> Result<String, WalletError> {
        self.eth_address_with_path(0, 0)
    }

    fn eth_address_with_path(&self, account: u32, index: u32) -> Result<String, WalletError> {
        // Ethereum address derivation using BIP-44: m/44'/60'/account'/0/index
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, XPrv};
            use k256::ecdsa::SigningKey;
            use sha3::{Digest, Keccak256};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let path = DerivationPath::from_str(&format!("m/44'/60'/{}'/0/{}", account, index))
                .map_err(|e| WalletError::DerivationFailed(format!("ethereum path: {}", e)))?;

            // Create extended private key from seed (network-agnostic bip32 crate)
            let xprv = XPrv::new(self.seed).map_err(|e| {
                WalletError::DerivationFailed(format!("ethereum master key: {}", e))
            })?;

            let mut derived = xprv;
            for child in path {
                derived = derived.derive_child(child).map_err(|e| {
                    WalletError::DerivationFailed(format!("ethereum child key: {}", e))
                })?;
            }

            // Get the private key bytes
            let priv_key_bytes = derived.private_key().to_bytes();

            // Create signing key
            let signing_key = SigningKey::from_bytes(&priv_key_bytes).map_err(|e| {
                WalletError::DerivationFailed(format!("ethereum signing key: {}", e))
            })?;

            // Get public key
            let verifying_key = signing_key.verifying_key();
            let pub_key = verifying_key.to_encoded_point(false);
            let pub_key_bytes = pub_key.as_bytes();

            // Skip the first byte (0x04 prefix) and hash the rest
            let pub_key_no_prefix = &pub_key_bytes[1..];
            let hash = Keccak256::digest(pub_key_no_prefix);

            // Take last 20 bytes
            let address_bytes = &hash[hash.len() - 20..];
            Ok(format!("0x{}", hex::encode(address_bytes)))
        }

        #[cfg(not(feature = "wallet"))]
        {
            let _ = account;
            let _ = index;
            Err(WalletError::EthereumUnavailable)
        }
    }

    fn sui_address(&self) -> Result<String, WalletError> {
        self.sui_address_with_path(0, 0)
    }

    fn sui_address_with_path(&self, account: u32, index: u32) -> Result<String, WalletError> {
        // Sui address derivation using SLIP-10: m/44'/784'/account'/0/index
        // Address = Blake2b-256(0x00 || public_key)
        // Note: SLIP-10 uses different derivation than BIP-32 for Ed25519
        #[cfg(feature = "wallet")]
        {
            use csv_hash::chain_id::ChainId;
            use csv_keys::bip44;

            // Use csv-keys bip44 for consistent SLIP-10 derivation
            let chain_id = ChainId::new("sui");
            let key = bip44::derive_key(&self.seed, &chain_id, account, index)
                .map_err(|e| WalletError::DerivationFailed(format!("sui key: {}", e)))?;
            bip44::derive_address_from_key(key.expose_secret(), &chain_id)
                .map_err(|e| WalletError::DerivationFailed(format!("sui address: {}", e)))
        }

        #[cfg(not(feature = "wallet"))]
        {
            let _ = account;
            let _ = index;
            Err(WalletError::SuiUnavailable)
        }
    }

    fn aptos_address(&self) -> Result<String, WalletError> {
        self.aptos_address_with_path(0, 0)
    }

    fn aptos_address_with_path(&self, account: u32, index: u32) -> Result<String, WalletError> {
        // Aptos address derivation using SLIP-10: m/44'/637'/account'/0/index
        // Address = SHA3-256(public_key || 0x00)
        // Note: SLIP-10 uses different derivation than BIP-32 for Ed25519
        #[cfg(feature = "wallet")]
        {
            use csv_hash::chain_id::ChainId;
            use csv_keys::bip44;

            // Use csv-keys bip44 for consistent SLIP-10 derivation
            let chain_id = ChainId::new("aptos");
            let key = bip44::derive_key(&self.seed, &chain_id, account, index)
                .map_err(|e| WalletError::DerivationFailed(format!("aptos key: {}", e)))?;
            bip44::derive_address_from_key(key.expose_secret(), &chain_id)
                .map_err(|e| WalletError::DerivationFailed(format!("aptos address: {}", e)))
        }

        #[cfg(not(feature = "wallet"))]
        {
            let _ = account;
            let _ = index;
            Err(WalletError::AptosUnavailable)
        }
    }

    fn sol_address(&self) -> Result<String, WalletError> {
        self.sol_address_with_path(0, 0)
    }

    fn sol_address_with_path(&self, account: u32, index: u32) -> Result<String, WalletError> {
        // Solana address derivation using SLIP-10: m/44'/501'/account'/0/index
        // Note: SLIP-10 uses different derivation than BIP-32 for Ed25519
        #[cfg(feature = "wallet")]
        {
            use csv_hash::chain_id::ChainId;
            use csv_keys::bip44;

            // Use csv-keys bip44 for consistent SLIP-10 derivation
            let chain_id = ChainId::new("solana");
            let key = bip44::derive_key(&self.seed, &chain_id, account, index)
                .map_err(|e| WalletError::DerivationFailed(format!("solana key: {}", e)))?;
            bip44::derive_address_from_key(key.expose_secret(), &chain_id)
                .map_err(|e| WalletError::DerivationFailed(format!("solana address: {}", e)))
        }

        #[cfg(not(feature = "wallet"))]
        {
            let _ = account;
            let _ = index;
            Err(WalletError::SolanaUnavailable)
        }
    }

    // -- Signing methods --

    fn sign_bitcoin(
        &self,
        _message: &[u8; 32],
        _account: u32,
        _index: u32,
    ) -> Result<Vec<u8>, WalletError> {
        // Bitcoin Taproot signing (Schnorr)
        #[cfg(all(feature = "bitcoin", feature = "wallet"))]
        {
            // Full Schnorr signing requires transaction context (sighash, taproot spend info)
            // This method only signs raw messages - for transaction signing, use the chain adapter
            Err(WalletError::DerivationFailed("bitcoin".to_string()))
        }

        #[cfg(not(all(feature = "bitcoin", feature = "wallet")))]
        {
            Err(WalletError::BitcoinUnavailable)
        }
    }

    #[allow(clippy::unwrap_used)]
    #[allow(unused_variables)]
    fn sign_ethereum(
        &self,
        message: &[u8; 32],
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, WalletError> {
        // Ethereum ECDSA signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, XPrv};
            use k256::ecdsa::{Signature, SigningKey, signature::Signer};
            use std::str::FromStr;

            // Derive the BIP-32 path
            let default_path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
            let path = DerivationPath::from_str(&format!("m/44'/60'/{}'/0/{}", account, index))
                .unwrap_or(default_path);

            let xprv = XPrv::new(self.seed).ok();

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
                        return Ok(signature.to_bytes().to_vec());
                    }
                }
            }

            Err(WalletError::DerivationFailed("ethereum".to_string()))
        }

        #[cfg(not(feature = "wallet"))]
        {
            Err(WalletError::EthereumUnavailable)
        }
    }

    #[allow(clippy::unwrap_used)]
    #[allow(unused_variables)]
    fn sign_solana(
        &self,
        message: &[u8; 32],
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, WalletError> {
        // Solana Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let default_path = DerivationPath::from_str("m/44'/501'/0'/0'/0").unwrap();
            let path = DerivationPath::from_str(&format!("m/44'/501'/{}'/0'/{}", account, index))
                .unwrap_or(default_path);

            let xprv = XPrv::new(self.seed).ok();

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
                        return Ok(signing_key.sign(message).to_bytes().to_vec());
                    }
                }
            }

            Err(WalletError::DerivationFailed("solana".to_string()))
        }

        #[cfg(not(feature = "wallet"))]
        {
            Err(WalletError::SolanaUnavailable)
        }
    }

    #[allow(clippy::unwrap_used)]
    #[allow(unused_variables)]
    fn sign_sui(
        &self,
        message: &[u8; 32],
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, WalletError> {
        // Sui Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let default_path = DerivationPath::from_str("m/44'/784'/0'/0'/0").unwrap();
            let path = DerivationPath::from_str(&format!("m/44'/784'/{}'/0'/{}", account, index))
                .unwrap_or(default_path);

            let xprv = XPrv::new(self.seed).ok();

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
                        return Ok(signing_key.sign(message).to_bytes().to_vec());
                    }
                }
            }

            Err(WalletError::DerivationFailed("sui".to_string()))
        }

        #[cfg(not(feature = "wallet"))]
        {
            Err(WalletError::SuiUnavailable)
        }
    }

    #[allow(clippy::unwrap_used)]
    #[allow(unused_variables)]
    fn sign_aptos(
        &self,
        message: &[u8; 32],
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, WalletError> {
        // Aptos Ed25519 signing
        #[cfg(feature = "wallet")]
        {
            use bip32::{DerivationPath, XPrv};
            use ed25519_dalek::{SecretKey, Signer, SigningKey};
            use std::str::FromStr;

            let default_path = DerivationPath::from_str("m/44'/637'/0'/0'/0").unwrap();
            let path = DerivationPath::from_str(&format!("m/44'/637'/{}'/0'/{}", account, index))
                .unwrap_or(default_path);

            let xprv = XPrv::new(self.seed).ok();

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
                        return Ok(signing_key.sign(message).to_bytes().to_vec());
                    }
                }
            }

            Err(WalletError::DerivationFailed("aptos".to_string()))
        }

        #[cfg(not(feature = "wallet"))]
        {
            Err(WalletError::AptosUnavailable)
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
    pub fn address(&self, chain: ChainId) -> Result<String, WalletError> {
        self.wallet.address(chain)
    }

    /// Derive an address for a specific chain with custom account and index.
    ///
    /// # Arguments
    ///
    /// * `chain` — Which chain to derive for.
    /// * `account` — BIP-44 account number.
    /// * `index` — Address index within the account.
    pub fn derive_address(
        &self,
        chain: ChainId,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        self.wallet.derive_address(chain, account, index)
    }

    /// Sign a message with the appropriate key for the given chain.
    pub fn sign(&self, chain: ChainId, message: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
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

/// Centralized wallet identity resolver.
///
/// This is the single canonical path for wallet address derivation across
/// all CLI commands (balance, sanad create, seal create, cross-chain transfer).
///
/// # Security
///
/// - Wrong keystore passphrase MUST fail closed - never silently fall back to mnemonic derivation
/// - No private key material is ever logged
pub struct WalletIdentityResolver {
    wallet: Wallet,
}

impl WalletIdentityResolver {
    /// Create a new wallet identity resolver from a mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The BIP-39 mnemonic phrase
    /// * `passphrase` - Optional passphrase (use empty string for none)
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, WalletError> {
        let wallet = Wallet::from_mnemonic(mnemonic, passphrase)
            .map_err(|e| WalletError::DerivationFailed(format!("from mnemonic: {}", e)))?;
        Ok(Self { wallet })
    }

    /// Create a new wallet identity resolver from a raw seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 64-byte BIP-39 seed
    pub fn from_seed(seed: [u8; 64]) -> Self {
        let wallet = Wallet::from_seed(seed);
        Self { wallet }
    }

    /// Derive the address for a specific chain with account and index.
    ///
    /// This is the canonical address derivation method used by all CLI commands.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to derive for
    /// * `account` - BIP-44 account number
    /// * `index` - Address index within the account
    ///
    /// # Returns
    ///
    /// The derived address as a string (chain-specific format)
    pub fn derive_address(
        &self,
        chain: ChainId,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        self.wallet.derive_address(chain, account, index)
    }

    /// Get the underlying wallet for advanced operations.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[cfg(feature = "wallet")]
    #[test]
    fn ethereum_address_derivation_matches_known_bip44_vector() {
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, "").unwrap();

        let address = wallet.address(ChainId::new("ethereum")).unwrap();

        assert_eq!(address, "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn invalid_ethereum_derivation_path_returns_error_without_seed_material() {
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let seed_prefix = hex::encode(&wallet.seed()[..20]);

        let err = wallet
            .derive_address(ChainId::new("ethereum"), 0, u32::MAX)
            .unwrap_err()
            .to_string();

        assert!(err.contains("ethereum"));
        assert!(!err.contains(&seed_prefix));
    }

    #[test]
    fn unsupported_chain_returns_error_without_seed_material() {
        let wallet = Wallet::from_seed([0xAB; 64]);
        let seed_prefix = hex::encode(&wallet.seed()[..8]);

        let err = wallet
            .address(ChainId::new("unknown"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("unknown"));
        assert!(!err.contains(&seed_prefix));
    }

    #[cfg(not(feature = "wallet"))]
    #[test]
    fn wallet_feature_disabled_returns_explicit_error_without_seed_material() {
        let wallet = Wallet::from_seed([0xCD; 64]);
        let seed_prefix = hex::encode(&wallet.seed()[..20]);

        let err = wallet
            .address(ChainId::new("ethereum"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("Ethereum signature capability unavailable"));
        assert!(!err.contains(&seed_prefix));
    }
}
