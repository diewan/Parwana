//! Solana wallet implementation for CSV

use async_trait::async_trait;
use csv_protocol::signature::SignatureScheme;
use csv_wallet::{Signer, SignerRef, Signature as WalletSignature, WalletError, Result as WalletResult};
use secrecy::{SecretVec, ExposeSecret};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer as SolanaSignerTrait},
    transaction::Transaction,
};
use std::fmt;

use crate::error::{SolanaError, SolanaResult};
use crate::types::SolanaCommitAnchor;

/// Solana Signer implementation using csv-wallet Signer trait
pub struct SolanaSigner {
    id: String,
    secret_key: SecretVec<u8>,
    public_key: Vec<u8>,
}

impl SolanaSigner {
    /// Create a new Solana signer from a private key
    ///
    /// # Arguments
    /// * `id` - Signer identifier
    /// * `secret_key` - 64-byte keypair (32 bytes secret + 32 bytes public)
    pub fn new(id: String, secret_key: Vec<u8>) -> SolanaResult<Self> {
        if secret_key.len() != 64 {
            return Err(SolanaError::Wallet(
                "Keypair must be 64 bytes".to_string(),
            ));
        }

        let secret_bytes: [u8; 32] = secret_key[..32]
            .try_into()
            .map_err(|_| SolanaError::Wallet("Invalid secret key data".to_string()))?;

        let keypair = Keypair::new_from_array(secret_bytes);
        let public_key = keypair.pubkey().to_bytes();

        Ok(Self {
            id,
            secret_key: SecretVec::new(secret_key),
            public_key: public_key.to_vec(),
        })
    }

    /// Get the Solana public key for this signer
    pub fn pubkey(&self) -> Pubkey {
        let bytes: [u8; 32] = self.public_key[..32]
            .try_into()
            .expect("Public key must be at least 32 bytes");
        Pubkey::from(bytes)
    }
}

#[async_trait]
impl Signer for SolanaSigner {
    async fn sign(&self, message: &[u8]) -> WalletResult<WalletSignature> {
        let secret_bytes: [u8; 32] = self.secret_key.expose_secret()[..32]
            .try_into()
            .map_err(|_| WalletError::InvalidFormat("Invalid secret key data".to_string()))?;

        let keypair = Keypair::new_from_array(secret_bytes);
        let signature = keypair.sign_message(message);
        let sig_bytes = signature.as_ref().to_vec();

        Ok(WalletSignature::new(sig_bytes, SignatureScheme::Ed25519))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }

    fn as_ref(&self) -> SignerRef {
        SignerRef {
            id: self.id.clone(),
            chain: "solana".to_string(),
            public_key: self.public_key.clone(),
        }
    }

    fn chain(&self) -> &str {
        "solana"
    }
}

impl fmt::Debug for SolanaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaSigner")
            .field("id", &self.id)
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

/// Solana program wallet
pub struct ProgramWallet {
    /// Keypair
    pub keypair: Keypair,
    /// Anchor reference
    pub anchor_ref: Option<SolanaCommitAnchor>,
}

impl ProgramWallet {
    /// Create new program wallet
    pub fn new() -> SolanaResult<Self> {
        let keypair = Keypair::new();
        Ok(Self {
            keypair,
            anchor_ref: None,
        })
    }

    /// Create from keypair
    pub fn from_keypair(keypair: Keypair) -> Self {
        Self {
            keypair,
            anchor_ref: None,
        }
    }

    /// Get public key
    pub fn pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    /// Get anchor reference
    pub fn anchor_ref(&self) -> Option<&SolanaCommitAnchor> {
        self.anchor_ref.as_ref()
    }

    /// Set anchor reference
    pub fn set_anchor_ref(&mut self, anchor_ref: SolanaCommitAnchor) {
        self.anchor_ref = Some(anchor_ref);
    }

    /// Sign transaction with the given recent blockhash.
    ///
    /// The caller MUST fetch a valid recent blockhash from the Solana RPC
    /// before calling this method. Using a stale or default blockhash will
    /// cause the transaction to be rejected by the network.
    pub fn sign_transaction(
        &self,
        transaction: &mut Transaction,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> SolanaResult<()> {
        transaction.partial_sign(&[&self.keypair], recent_blockhash);
        Ok(())
    }

    /// Sign message
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.keypair.sign_message(message)
    }

    /// Verify signature
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> bool {
        // Use the signature's verify method with pubkey bytes
        let pubkey_bytes = self.keypair.pubkey().to_bytes();
        signature.verify(&pubkey_bytes, message)
    }

    /// Verify data with signature bytes
    pub fn verify(&self, message: &[u8], sig_bytes: &[u8; 64]) -> bool {
        let signature = Signature::from(*sig_bytes);
        self.verify_signature(message, &signature)
    }

    /// Serialize keypair
    pub fn serialize_keypair(&self) -> SolanaResult<Vec<u8>> {
        Ok(self.keypair.to_bytes().to_vec())
    }

    /// Deserialize keypair
    pub fn deserialize_keypair(data: &[u8]) -> SolanaResult<Self> {
        if data.len() != 64 {
            return Err(SolanaError::Wallet(
                "Invalid keypair data length".to_string(),
            ));
        }

        // Take first 32 bytes as the secret key
        let secret_key: [u8; 32] = data[..32]
            .try_into()
            .map_err(|_| SolanaError::Wallet("Invalid secret key data".to_string()))?;

        let keypair = Keypair::new_from_array(secret_key);
        Ok(Self::from_keypair(keypair))
    }

    /// Create wallet from base58-encoded keypair (standard Solana key format)
    pub fn from_base58(keypair_str: &str) -> SolanaResult<Self> {
        // Decode base58 to get the keypair bytes
        let keypair_bytes = bs58::decode(keypair_str)
            .into_vec()
            .map_err(|e| SolanaError::Wallet(format!("Invalid base58 keypair: {}", e)))?;

        // Ensure we have the correct length (64 bytes for full keypair)
        if keypair_bytes.len() != 64 {
            return Err(SolanaError::Wallet(format!(
                "Invalid keypair length: expected 64 bytes, got {}",
                keypair_bytes.len()
            )));
        }

        // Deserialize the keypair
        Self::deserialize_keypair(&keypair_bytes)
    }
}

/// Solana wallet error type
#[derive(Debug, thiserror::Error)]
pub enum SolanaWalletError {
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

impl From<SolanaWalletError> for SolanaError {
    fn from(err: SolanaWalletError) -> Self {
        SolanaError::Wallet(err.to_string())
    }
}
