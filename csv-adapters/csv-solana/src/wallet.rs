//! Solana wallet implementation for CSV

use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};

use crate::error::{SolanaError, SolanaResult};
use crate::types::SolanaCommitAnchor;

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

/// Wallet error type
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

impl From<WalletError> for SolanaError {
    fn from(err: WalletError) -> Self {
        SolanaError::Wallet(err.to_string())
    }
}
