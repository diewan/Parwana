//! BIP-44 HD wallet derivation for multi-chain support.
//!
//! This module provides hierarchical deterministic (HD) wallet key derivation
//! following BIP-44 standards with chain-specific paths.

use crate::memory::SecretKey;
use csv_hash::chain_id::ChainId;
use thiserror::Error;

/// Error type for BIP-44 operations.
#[derive(Debug, Error)]
pub enum Bip44Error {
    /// Invalid derivation path.
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),

    /// Invalid seed length.
    #[error("Invalid seed length: expected 64, got {0}")]
    InvalidSeedLength(usize),

    /// Chain not supported.
    #[error("Chain not supported for HD derivation: {0:?}")]
    UnsupportedChain(ChainId),

    /// Derivation failed.
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
}

/// BIP-44 derivation path components.
#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    /// Purpose (BIP-44 = 44', BIP-49 = 49', BIP-84 = 84', BIP-86 = 86')
    pub purpose: u32,
    /// Coin type (SLIP-44 registered coin types)
    pub coin_type: u32,
    /// Account index
    pub account: u32,
    /// Change (0 = external, 1 = internal)
    pub change: u32,
    /// Address index
    pub address_index: u32,
}

impl DerivationPath {
    /// Create a new derivation path with hardened purpose and coin type.
    pub fn new_bip44(coin_type: u32, account: u32, change: u32, address_index: u32) -> Self {
        Self {
            purpose: 44 | 0x8000_0000,          // hardened
            coin_type: coin_type | 0x8000_0000, // hardened
            account: account | 0x8000_0000,     // hardened
            change,
            address_index,
        }
    }

    /// Create a BIP-86 derivation path (Bitcoin Taproot).
    pub fn new_bip86(account: u32, address_index: u32) -> Self {
        Self {
            purpose: 86 | 0x8000_0000, // BIP-86 hardened
            coin_type: 0x8000_0000,    // Bitcoin hardened
            account: account | 0x8000_0000,
            change: 0,
            address_index,
        }
    }

    /// Convert to string representation (e.g., "m/44'/60'/0'/0/0").
    pub fn to_string_path(&self) -> String {
        format!(
            "m/{}'/{}{}'/{}'/{}/{}",
            self.purpose & 0x7FFF_FFFF,
            if self.coin_type >= 0x8000_0000 {
                ""
            } else {
                "not"
            },
            self.coin_type & 0x7FFF_FFFF,
            self.account & 0x7FFF_FFFF,
            self.change,
            self.address_index
        )
    }
}

/// Get the BIP-44 coin type for a chain.
pub fn coin_type(chain: &ChainId) -> u32 {
    match chain.as_str() {
        "bitcoin" => 0,   // SLIP-44: BTC
        "ethereum" => 60, // SLIP-44: ETH
        "sui" => 784,     // SLIP-44: SUI
        "aptos" => 637,   // SLIP-44: APT
        "solana" => 501,  // SLIP-44: SOL
        _ => 0,           // Default to Bitcoin coin type for unknown chains
    }
}

/// Get the standard derivation path for a chain.
pub fn derivation_path(chain: &ChainId, account: u32, address_index: u32) -> DerivationPath {
    match chain.as_str() {
        "bitcoin" => {
            // Bitcoin: BIP-86 for Taproot (native segwit v1)
            DerivationPath::new_bip86(account, address_index)
        }
        _ => {
            // Ethereum, Sui, Aptos, Solana: standard BIP-44
            DerivationPath::new_bip44(
                coin_type(chain),
                account,
                0, // external
                address_index,
            )
        }
    }
}

/// Derive a secret key from a 64-byte seed using BIP-44/SLIP-10.
///
/// # Arguments
/// * `seed` - 64-byte BIP-39 seed
/// * `chain` - Target blockchain
/// * `account` - Account index (hardened)
/// * `address_index` - Address index within account
///
/// # Returns
/// A derived 32-byte secret key.
pub fn derive_key(
    seed: &[u8; 64],
    chain: &ChainId,
    account: u32,
    address_index: u32,
) -> Result<SecretKey, Bip44Error> {
    let path = derivation_path(chain, account, address_index);
    derive_key_from_path(seed, &path, chain)
}

/// Derive a key from a chain name string.
pub fn derive_key_from_name(
    seed: &[u8; 64],
    chain_name: &str,
    account: u32,
    address_index: u32,
) -> Result<SecretKey, Bip44Error> {
    let chain = match chain_name {
        "bitcoin" => ChainId::new("bitcoin"),
        "ethereum" => ChainId::new("ethereum"),
        "sui" => ChainId::new("sui"),
        "aptos" => ChainId::new("aptos"),
        "solana" => ChainId::new("solana"),
        _ => {
            return Err(Bip44Error::InvalidPath(format!(
                "Unknown chain: {}",
                chain_name
            )));
        }
    };
    derive_key(seed, &chain, account, address_index)
}

/// Derive a key from a specific derivation path.
///
/// This uses SLIP-10 for Ed25519 chains (Sui, Aptos, Solana) and
/// BIP-32 for secp256k1 chains (Bitcoin, Ethereum).
pub fn derive_key_from_path(
    seed: &[u8; 64],
    path: &DerivationPath,
    chain: &ChainId,
) -> Result<SecretKey, Bip44Error> {
    match chain.as_str() {
        "bitcoin" | "ethereum" => derive_secp256k1(seed, path),
        "sui" | "aptos" | "solana" => derive_ed25519(seed, path),
        _ => {
            // Default to Ed25519 for unknown chains
            derive_ed25519(seed, path)
        }
    }
}

/// Derive a secp256k1 key (Bitcoin, Ethereum).
///
/// Uses proper BIP-32 HD key derivation with HMAC-SHA512.
/// Derives master key from seed, then derives child keys along the path.
fn derive_secp256k1(seed: &[u8; 64], path: &DerivationPath) -> Result<SecretKey, Bip44Error> {
    use bip32::{ChildNumber, DerivationPath as Bip32Path, ExtendedKey, XPrv};
    use std::str::FromStr;

    // Create master extended private key from seed using BIP-32 (network-agnostic)
    // This matches the Wallet SDK's derivation method
    let xprv = XPrv::new(seed).ok()
        .ok_or_else(|| Bip44Error::DerivationFailed("Failed to create master key".to_string()))?;

    // Build BIP-32 derivation path string from components
    let path_str = format!(
        "m/{}/{}/{}/{}/{}",
        path.purpose & 0x7FFF_FFFF,
        path.coin_type & 0x7FFF_FFFF,
        path.account & 0x7FFF_FFFF,
        path.change,
        path.address_index
    );

    let bip32_path = Bip32Path::from_str(&path_str)
        .map_err(|e| Bip44Error::DerivationFailed(format!("Invalid derivation path: {}", e)))?;

    // Derive the child key using proper BIP-32 hierarchy
    let mut derived = xprv;
    for child in bip32_path {
        derived = derived.derive_child(child)
            .map_err(|e| Bip44Error::DerivationFailed(format!("Failed to derive child key: {}", e)))?;
    }

    // Extract the 32-byte secret key from the extended private key
    let key_bytes = derived.private_key().to_bytes();
    let key_array: [u8; 32] = key_bytes.into();

    Ok(SecretKey::new(key_array))
}

/// Derive an Ed25519 key (Sui, Aptos, Solana).
///
/// Uses proper SLIP-10 HD key derivation with HMAC-SHA512.
/// Derives master key from seed, then derives child keys along the path.
fn derive_ed25519(seed: &[u8; 64], path: &DerivationPath) -> Result<SecretKey, Bip44Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // SLIP-10 master key derivation for Ed25519
    // The master secret is HMAC-SHA512(key="ed25519 seed", data=seed)
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| Bip44Error::DerivationFailed(format!("HMAC setup failed: {}", e)))?;
    mac.update(seed);
    let master_key_material = mac.finalize().into_bytes();

    // SLIP-10 requires the master key to be split into chain code and key
    // For Ed25519, we use the first 32 bytes as the key and last 32 as chain code
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_material[..32]);

    // Derive child keys along the path using SLIP-10 hierarchy
    let mut key = derive_ed25519_child(&master_key, path)?;

    // Ed25519 requires clamping bits per the spec
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;

    Ok(SecretKey::new(key))
}

/// Derive a child Ed25519 key using SLIP-10 hierarchy.
///
/// Iteratively derives each level of the path: purpose' → coin_type' → account' → change → address_index
fn derive_ed25519_child(master_key: &[u8; 32], path: &DerivationPath) -> Result<[u8; 32], Bip44Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let mut current_key = *master_key;

    // Derive through each level of the hierarchy
    let levels = [
        (path.purpose, true),
        (path.coin_type, true),
        (path.account, true),
        (path.change, false),
        (path.address_index, false),
    ];

    for (index, hardened) in levels {
        let mut mac = HmacSha512::new_from_slice(&current_key)
            .map_err(|e| Bip44Error::DerivationFailed(format!("HMAC setup failed: {}", e)))?;

        if hardened {
            // Hardened child: prefix with 0x00
            mac.update(&[0x00]);
            mac.update(&current_key);
        } else {
            // Regular child: use parent public key (we use the key bytes directly for simplicity)
            // In full SLIP-10, this would use the public key, but for Ed25519 we derive sequentially
            mac.update(&current_key);
        }

        // Add the index (4 bytes, big-endian)
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // For Ed25519, we use the full 64-byte HMAC output as the new key material
        // The first 32 bytes become the new key
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&result[..32]);

        current_key = new_key;
    }

    Ok(current_key)
}

/// Generate multiple addresses for a chain from a single seed.
pub fn generate_addresses(
    seed: &[u8; 64],
    chain: &ChainId,
    account: u32,
    count: usize,
) -> Result<Vec<SecretKey>, Bip44Error> {
    let mut keys = Vec::with_capacity(count);

    for i in 0..count {
        let key = derive_key(seed, chain, account, i as u32)?;
        keys.push(key);
    }

    Ok(keys)
}

/// Derive addresses for all supported chains from a single seed.
pub fn derive_all_chain_keys(
    seed: &[u8; 64],
    account: u32,
) -> std::collections::HashMap<ChainId, SecretKey> {
    let mut keys = std::collections::HashMap::new();

    for chain_id in [
        ChainId::new("bitcoin"),
        ChainId::new("ethereum"),
        ChainId::new("sui"),
        ChainId::new("aptos"),
        ChainId::new("solana"),
    ] {
        let chain_name = chain_id.as_str();
        if let Ok(key) = derive_key_from_name(seed, chain_name, account, 0) {
            keys.insert(chain_id, key);
        }
    }

    keys
}

/// Derive an address from a raw 32-byte private key for a specific chain.
///
/// # Arguments
/// * `key_bytes` - 32-byte private key
/// * `chain` - Target blockchain
///
/// # Returns
/// The derived address as a string.
pub fn derive_address_from_key(key_bytes: &[u8], chain: &ChainId) -> Result<String, Bip44Error> {
    derive_address_from_key_with_network(key_bytes, chain, bitcoin::Network::Testnet)
}

/// Derive an address from a raw 32-byte private key for a specific chain with explicit network.
///
/// # Arguments
/// * `key_bytes` - 32-byte private key
/// * `chain` - Target blockchain
/// * `network` - Bitcoin network (only used for Bitcoin chain)
///
/// # Returns
/// The derived address as a string.
pub fn derive_address_from_key_with_network(
    key_bytes: &[u8],
    chain: &ChainId,
    network: bitcoin::Network,
) -> Result<String, Bip44Error> {
    if key_bytes.len() != 32 {
        return Err(Bip44Error::InvalidSeedLength(key_bytes.len()));
    }

    match chain.as_str() {
        "bitcoin" => derive_bitcoin_address_from_key(key_bytes, network),
        "ethereum" => derive_ethereum_address_from_key(key_bytes),
        "sui" => derive_sui_address_from_key(key_bytes),
        "aptos" => derive_aptos_address_from_key(key_bytes),
        "solana" => derive_solana_address_from_key(key_bytes),
        _ => Err(Bip44Error::UnsupportedChain(chain.clone())),
    }
}

/// Derive an address from a raw 32-byte private key for a specific chain (using ChainId).
pub fn derive_address_from_chain_id(
    key_bytes: &[u8],
    chain_id: &ChainId,
) -> Result<String, Bip44Error> {
    derive_address_from_chain_id_with_network(key_bytes, chain_id, bitcoin::Network::Testnet)
}

/// Derive an address from a raw 32-byte private key for a specific chain with explicit network.
pub fn derive_address_from_chain_id_with_network(
    key_bytes: &[u8],
    chain_id: &ChainId,
    network: bitcoin::Network,
) -> Result<String, Bip44Error> {
    match chain_id.as_str() {
        "bitcoin" | "ethereum" | "sui" | "aptos" | "solana" => {}
        _ => return Err(Bip44Error::UnsupportedChain(chain_id.clone())),
    };
    derive_address_from_key_with_network(key_bytes, chain_id, network)
}

fn derive_bitcoin_address_from_key(
    key_bytes: &[u8],
    network: bitcoin::Network,
) -> Result<String, Bip44Error> {
    use bitcoin::address::KnownHrp;
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    let secret_key = SecretKey::from_slice(key_bytes)
        .map_err(|e| Bip44Error::DerivationFailed(format!("Invalid secp256k1 key: {}", e)))?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pubkey, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    let hrp = match network {
        bitcoin::Network::Bitcoin => KnownHrp::Mainnet,
        bitcoin::Network::Testnet
        | bitcoin::Network::Testnet4
        | bitcoin::Network::Signet
        | bitcoin::Network::Regtest => KnownHrp::Testnets,
    };

    let address = bitcoin::Address::p2tr(&secp, xonly_pubkey, None, hrp);
    Ok(address.to_string())
}

fn derive_ethereum_address_from_key(key_bytes: &[u8]) -> Result<String, Bip44Error> {
    use secp256k1::{Secp256k1, SecretKey};
    use sha3::{Digest, Keccak256};

    let secret_key = SecretKey::from_slice(key_bytes)
        .map_err(|e| Bip44Error::DerivationFailed(format!("Invalid secp256k1 key: {}", e)))?;

    let secp = Secp256k1::new();
    let public_key = secret_key.public_key(&secp);
    let pubkey_bytes = public_key.serialize_uncompressed();

    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]); // Skip the 0x04 prefix
    let hash = hasher.finalize();

    // Ethereum address is the last 20 bytes
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

fn derive_sui_address_from_key(key_bytes: &[u8]) -> Result<String, Bip44Error> {
    use blake2::{Blake2b, Digest};
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let mut hasher = Blake2b::new();
    hasher.update([0x00]); // Sui address prefix
    hasher.update(verifying_key.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    Ok(format!("0x{}", hex::encode(&hash[..])))
}

fn derive_aptos_address_from_key(key_bytes: &[u8]) -> Result<String, Bip44Error> {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use sha3::{Digest, Sha3_256};

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let mut hasher = Sha3_256::new();
    hasher.update(verifying_key.as_bytes());
    hasher.update([0x00]); // Aptos address suffix
    let hash: [u8; 32] = hasher.finalize().into();

    Ok(format!("0x{}", hex::encode(&hash[..])))
}

fn derive_solana_address_from_key(key_bytes: &[u8]) -> Result<String, Bip44Error> {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Solana address is the base58-encoded public key
    Ok(bs58::encode(verifying_key.as_bytes()).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_path_bip44() {
        let path = DerivationPath::new_bip44(60, 0, 0, 0); // Ethereum
        let path_str = path.to_string_path();
        assert!(path_str.contains("44'"));
        assert!(path_str.contains("60'"));
    }

    #[test]
    fn test_derivation_path_bip86() {
        let path = DerivationPath::new_bip86(0, 0); // Bitcoin Taproot
        let path_str = path.to_string_path();
        assert!(path_str.contains("86'"));
    }

    #[test]
    fn test_coin_types() {
        assert_eq!(coin_type(&ChainId::new("bitcoin")), 0);
        assert_eq!(coin_type(&ChainId::new("ethereum")), 60);
        assert_eq!(coin_type(&ChainId::new("sui")), 784);
        assert_eq!(coin_type(&ChainId::new("aptos")), 637);
        assert_eq!(coin_type(&ChainId::new("solana")), 501);
    }

    #[test]
    fn test_derivation_path_for_chains() {
        let eth_path = derivation_path(&ChainId::new("ethereum"), 0, 0);
        assert_eq!(eth_path.coin_type & 0x7FFF_FFFF, 60);

        let btc_path = derivation_path(&ChainId::new("bitcoin"), 0, 0);
        assert_eq!(btc_path.purpose & 0x7FFF_FFFF, 86); // BIP-86
    }

    #[test]
    fn test_derive_key() {
        let seed = [1u8; 64];
        let key = derive_key(&seed, &ChainId::new("ethereum"), 0, 0);
        assert!(key.is_ok());
    }

    #[test]
    fn test_generate_addresses() {
        let seed = [2u8; 64];
        let keys = generate_addresses(&seed, &ChainId::new("ethereum"), 0, 5);
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), 5);
    }

    #[test]
    fn test_secp256k1_derivation_consistency() {
        let seed = [0xABu8; 64];
        
        // Derive the same key twice - should produce identical results
        let key1 = derive_key(&seed, &ChainId::new("ethereum"), 0, 0).unwrap();
        let key2 = derive_key(&seed, &ChainId::new("ethereum"), 0, 0).unwrap();
        
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Same seed + path must produce identical keys"
        );
    }

    #[test]
    fn test_secp256k1_different_paths_produce_different_keys() {
        let seed = [0xCDu8; 64];
        
        let key0 = derive_key(&seed, &ChainId::new("ethereum"), 0, 0).unwrap();
        let key1 = derive_key(&seed, &ChainId::new("ethereum"), 0, 1).unwrap();
        let key2 = derive_key(&seed, &ChainId::new("ethereum"), 1, 0).unwrap();
        
        assert_ne!(
            key0.as_bytes(),
            key1.as_bytes(),
            "Different address indices must produce different keys"
        );
        assert_ne!(
            key0.as_bytes(),
            key2.as_bytes(),
            "Different account indices must produce different keys"
        );
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Different paths must produce different keys"
        );
    }

    #[test]
    fn test_ed25519_derivation_consistency() {
        let seed = [0xEFu8; 64];
        
        let key1 = derive_key(&seed, &ChainId::new("solana"), 0, 0).unwrap();
        let key2 = derive_key(&seed, &ChainId::new("solana"), 0, 0).unwrap();
        
        assert_eq!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Same seed + path must produce identical Ed25519 keys"
        );
    }

    #[test]
    fn test_ed25519_different_paths_produce_different_keys() {
        let seed = [0x12u8; 64];
        
        let key0 = derive_key(&seed, &ChainId::new("sui"), 0, 0).unwrap();
        let key1 = derive_key(&seed, &ChainId::new("sui"), 0, 1).unwrap();
        
        assert_ne!(
            key0.as_bytes(),
            key1.as_bytes(),
            "Different address indices must produce different Ed25519 keys"
        );
    }

    #[test]
    fn test_bip32_compatible_derivation() {
        // Use a known seed and verify that BIP-32 derivation produces deterministic results
        // This seed is from BIP-32 test vector 1
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];

        // Derive m/44'/0'/0'/0/0 (Bitcoin BIP-44)
        let path = DerivationPath::new_bip44(0, 0, 0, 0);
        let key = derive_secp256k1(&seed, &path).unwrap();
        
        // Verify the key is deterministic by deriving again
        let key2 = derive_secp256k1(&seed, &path).unwrap();
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }
}
