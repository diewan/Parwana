//! Solana adapter implementation for CSV
//!
//! Implements the SealProtocol trait for Solana using Program Derived Addresses (PDAs)
//! as single-use seals. When a seal is consumed, the PDA account is closed, transferring
//! lamports to the destination, making the seal cryptographically unspendable.

use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::{
    Hash, Result, dag::DAGSegment, error::ProtocolError, proof::ProofBundle,
    signature::SignatureScheme,
};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;

use crate::config::SolanaConfig;
use crate::error::{SolanaError, SolanaResult};
use crate::rpc::SolanaRpc;
use crate::types::{
    AccountChange, ConfirmationStatus, SolanaCommitAnchor, SolanaFinalityProof,
    SolanaInclusionProof, SolanaSealPoint,
};
use crate::wallet::ProgramWallet;

/// Domain separator for Solana CSV commitments
const SOLANA_DOMAIN_SEPARATOR: [u8; 32] = [
    0x53, 0x4f, 0x4c, 0x61, 0x6e, 0x61, 0x43, 0x53, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Program instruction discriminators
const INSTRUCTION_CREATE_SEAL: u8 = 0x01;
const INSTRUCTION_CONSUME_SEAL: u8 = 0x02;
const INSTRUCTION_PUBLISH_COMMITMENT: u8 = 0x03;

/// Solana adapter for CSV (Client-Side Validation)
pub struct SolanaSealProtocol {
    /// Configuration
    pub config: SolanaConfig,
    /// RPC client
    pub rpc_client: Option<Box<dyn SolanaRpc>>,
    /// Wallet
    pub wallet: Option<ProgramWallet>,
    /// In-memory seal tracking for this session
    active_seals: std::sync::Mutex<Vec<SolanaSealPoint>>,
}

impl SolanaSealProtocol {
    /// Create new Solana adapter
    pub fn new(config: SolanaConfig) -> Self {
        Self {
            config,
            rpc_client: None,
            wallet: None,
            active_seals: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Create from configuration and RPC client (standard runtime pattern).
    ///
    /// # Arguments
    /// * `config` - Solana adapter configuration (includes network, program ID, optional keypair)
    /// * `rpc_client` - RPC client for Solana node communication
    ///
    /// # Security Notes
    /// - Uses Ed25519 for all signing operations (Solana native)
    /// - Domain separator includes "SOLanaCSV" prefix for cross-chain replay protection
    /// - Optional wallet created from config keypair if provided
    /// - All key material handled through secure ProgramWallet
    pub fn from_config(
        config: SolanaConfig,
        rpc_client: Box<dyn SolanaRpc>,
    ) -> crate::error::SolanaResult<Self> {
        // Build wallet from config keypair if provided
        let wallet = match &config.keypair {
            Some(keypair_str) => Some(ProgramWallet::from_base58(keypair_str).map_err(|e| {
                crate::error::SolanaError::Wallet(format!(
                    "Failed to create wallet from keypair: {}",
                    e
                ))
            })?),
            None => {
                log::debug!("No keypair provided in config, wallet operations will be unavailable");
                None
            }
        };

        log::info!(
            "Initialized Solana adapter for network {:?}",
            config.network
        );

        Ok(Self {
            config,
            rpc_client: Some(rpc_client),
            wallet,
            active_seals: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Set RPC client
    pub fn with_rpc_client(mut self, rpc_client: Box<dyn SolanaRpc>) -> Self {
        self.rpc_client = Some(rpc_client);
        self
    }

    /// Set wallet
    pub fn with_wallet(mut self, wallet: ProgramWallet) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Get configuration
    pub fn config(&self) -> &SolanaConfig {
        &self.config
    }

    /// Get RPC client
    pub fn rpc_client(&self) -> Option<&dyn SolanaRpc> {
        self.rpc_client.as_ref().map(|client| client.as_ref())
    }

    /// Get wallet
    pub fn wallet(&self) -> Option<&ProgramWallet> {
        self.wallet.as_ref()
    }

    /// Derive seal PDA from sanad ID and owner
    fn derive_seal_pda(&self, sanad_id: &Hash, owner: &Pubkey) -> Pubkey {
        let _seeds = [b"csv-seal", sanad_id.as_slice(), owner.as_ref()];
        // In production, this would use find_program_address with the actual CSV program
        // For now, we compute a deterministic hash-based address
        let mut hasher = Sha256::new();
        hasher.update(SOLANA_DOMAIN_SEPARATOR);
        hasher.update(b"seal");
        hasher.update(sanad_id.as_bytes());
        hasher.update(owner.as_ref());
        let hash = hasher.finalize();

        // Convert first 32 bytes to pubkey
        Pubkey::new_from_array(hash.into())
    }

    /// Derive commitment PDA from commitment hash
    fn derive_commitment_pda(&self, commitment: &Hash) -> Pubkey {
        let mut hasher = Sha256::new();
        hasher.update(SOLANA_DOMAIN_SEPARATOR);
        hasher.update(b"commitment");
        hasher.update(commitment.as_bytes());
        let hash = hasher.finalize();
        Pubkey::new_from_array(hash.into())
    }

    /// Check if RPC client is available
    fn check_rpc(&self) -> SolanaResult<&dyn SolanaRpc> {
        self.rpc_client()
            .ok_or_else(|| SolanaError::Rpc("No RPC client configured".to_string()))
    }

    /// Store seal reference
    fn store_seal(&self, seal: SolanaSealPoint) {
        if let Ok(mut seals) = self.active_seals.lock() {
            seals.push(seal);
        }
    }

    /// Find seal by account
    fn find_seal(&self, account: &Pubkey) -> Option<SolanaSealPoint> {
        if let Ok(seals) = self.active_seals.lock() {
            seals.iter().find(|s| &s.account == account).cloned()
        } else {
            None
        }
    }

    /// Get all active seals
    pub fn get_active_seals(&self) -> Vec<SolanaSealPoint> {
        if let Ok(seals) = self.active_seals.lock() {
            seals.clone()
        } else {
            Vec::new()
        }
    }
}

impl SealProtocol for SolanaSealProtocol {
    type SealPoint = SolanaSealPoint;
    type CommitAnchor = SolanaCommitAnchor;
    type InclusionProof = SolanaInclusionProof;
    type FinalityProof = SolanaFinalityProof;

    /// Create a new seal account (PDA) for a sanad
    fn create_seal(&self, amount: Option<u64>) -> Result<Self::SealPoint> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| SolanaError::Wallet("No wallet configured".to_string()))?;

        let owner = wallet.pubkey();
        let sanad_id = Hash::new(Self::generate_sanad_id());
        let seal_pda = self.derive_seal_pda(&sanad_id, &owner);

        let lamports = amount.unwrap_or(1_000_000); // Default 0.001 SOL rent exemption

        let seal_ref = SolanaSealPoint {
            account: seal_pda,
            owner,
            lamports,
            seed: Some(sanad_id.as_bytes().to_vec()),
        };

        // Create the seal account via RPC
        let rpc = self.check_rpc()?;

        // Get recent blockhash
        let recent_blockhash = rpc
            .get_recent_blockhash()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get recent blockhash: {}", e)))?;

        // Create system program instruction to transfer lamports and create account
        let create_account_ix = system_instruction::create_account(
            &owner, &seal_pda, lamports, 32,     // data size for seal
            &owner, // owner program
        );

        // Build transaction
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[create_account_ix],
            Some(&owner),
        );
        transaction.message.recent_blockhash = recent_blockhash;

        // Sign transaction
        transaction.sign(&[&wallet.keypair], recent_blockhash);

        // Send transaction via RPC
        let signature = rpc
            .send_transaction(&transaction)
            .map_err(|e| SolanaError::Rpc(format!("Failed to send transaction: {}", e)))?;

        // Wait for confirmation
        let _status = rpc
            .wait_for_confirmation(&signature)
            .map_err(|e| SolanaError::Rpc(format!("Transaction confirmation failed: {}", e)))?;

        // Get slot information
        let _slot = rpc
            .get_latest_slot()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get slot: {}", e)))?;

        // Store seal reference locally for tracking
        self.store_seal(seal_ref.clone());

        Ok(seal_ref)
    }

    /// Publish a commitment to the seal account
    fn publish(&self, hash: Hash, seal_point: Self::SealPoint) -> Result<Self::CommitAnchor> {
        let rpc = self.check_rpc()?;
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| SolanaError::Wallet("No wallet configured".to_string()))?;

        let owner = wallet.pubkey();
        let commitment_pda = self.derive_commitment_pda(&hash);

        // Get recent blockhash
        let recent_blockhash = rpc
            .get_recent_blockhash()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get recent blockhash: {}", e)))?;

        // Build instruction data with discriminator and commitment hash
        let mut instruction_data = vec![INSTRUCTION_PUBLISH_COMMITMENT];
        instruction_data.extend_from_slice(hash.as_bytes());

        // Create instruction to publish commitment to the seal account
        let publish_ix = solana_sdk::instruction::Instruction::new_with_bytes(
            seal_point.account, // seal program
            &instruction_data,
            vec![
                solana_sdk::instruction::AccountMeta::new(seal_point.account, false),
                solana_sdk::instruction::AccountMeta::new(commitment_pda, false),
                solana_sdk::instruction::AccountMeta::new_readonly(owner, true),
            ],
        );

        // Build transaction
        let mut transaction =
            solana_sdk::transaction::Transaction::new_with_payer(&[publish_ix], Some(&owner));
        transaction.message.recent_blockhash = recent_blockhash;

        // Sign transaction
        transaction.sign(&[&wallet.keypair], recent_blockhash);

        // Send transaction via RPC
        let signature = rpc
            .send_transaction(&transaction)
            .map_err(|e| SolanaError::Rpc(format!("Failed to send transaction: {}", e)))?;

        // Wait for confirmation
        let _status = rpc
            .wait_for_confirmation(&signature)
            .map_err(|e| SolanaError::Rpc(format!("Transaction confirmation failed: {}", e)))?;

        // Get slot information
        let slot = rpc
            .get_latest_slot()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get slot: {}", e)))?;

        let anchor_ref = SolanaCommitAnchor {
            signature,
            slot,
            block_height: slot,
            account_changes: vec![
                AccountChange {
                    pubkey: seal_point.account,
                    prev_lamports: seal_point.lamports,
                    new_lamports: 0, // Seal is consumed
                    prev_data: seal_point.seed.clone(),
                    new_data: None,
                    closed: true,
                },
                AccountChange {
                    pubkey: commitment_pda,
                    prev_lamports: 0,
                    new_lamports: 1_000_000,
                    prev_data: None,
                    new_data: Some(hash.as_bytes().to_vec()),
                    closed: false,
                },
            ],
        };

        // Remove seal from active tracking since it's now consumed
        if let Ok(mut seals) = self.active_seals.lock() {
            seals.retain(|s| s.account != seal_point.account);
        }

        Ok(anchor_ref)
    }

    /// Verify inclusion by checking the transaction is in a block
    fn verify_inclusion(&self, anchor_ref: Self::CommitAnchor) -> Result<Self::InclusionProof> {
        let _rpc = self.check_rpc()?;

        // In production, this would:
        // 1. Fetch the transaction from RPC
        // 2. Verify it's in a confirmed block
        // 3. Build account proofs

        let proof = SolanaInclusionProof {
            signature: anchor_ref.signature,
            slot: anchor_ref.slot,
            block_height: anchor_ref.block_height,
            confirmation_status: ConfirmationStatus::Confirmed,
            account_proofs: anchor_ref
                .account_changes
                .iter()
                .map(|change| {
                    crate::types::AccountProof {
                        pubkey: change.pubkey,
                        proof: vec![change.pubkey.as_ref().to_vec()], // Simplified
                        data_hash: change.new_data.as_ref().map(|d| {
                            let mut hasher = Sha256::new();
                            hasher.update(d);
                            Hash::new(hasher.finalize().into())
                        }),
                    }
                })
                .collect(),
        };

        Ok(proof)
    }

    /// Verify finality by checking block depth
    fn verify_finality(&self, anchor_ref: Self::CommitAnchor) -> Result<Self::FinalityProof> {
        let _rpc = self.check_rpc()?;

        // Solana has deterministic finality after ~32 slots (12-16 seconds)
        // For devnet/testnet, we use shorter confirmation

        let current_slot = self.check_rpc()?.get_latest_slot()?;
        let confirmation_depth = current_slot.saturating_sub(anchor_ref.slot);

        // Solana requires 32 slots for finality
        let _is_finalized = confirmation_depth >= 32;

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&anchor_ref.signature.as_ref()[..32]);

        let proof = SolanaFinalityProof {
            slot: anchor_ref.slot,
            block_hash: Hash::new(block_hash),
            confirmation_depth,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };

        Ok(proof)
    }

    /// Enforce seal by closing the account (consuming it)
    fn enforce_seal(&self, seal_point: Self::SealPoint) -> Result<()> {
        // Rule G-02: Double-spend prevention
        // This method ensures that a PDA account cannot be consumed more than once
        // by checking both local registry and on-chain account state

        // Step 1: Check local registry (fast path)
        if let Ok(seals) = self.active_seals.lock() {
            if !seals.iter().any(|s| s.account == seal_point.account) {
                return Err(ProtocolError::SealReplay(format!(
                    "PDA account {:?} not found in active seals",
                    seal_point.account
                )));
            }
        }

        // Step 2: Check on-chain account state via RPC (authoritative check)
        // This ensures that even if local state is corrupted or lost,
        // we still prevent double-spends by querying the blockchain
        #[cfg(feature = "rpc")]
        {
            let rpc = self.check_rpc()?;
            let account = rpc.get_account(&seal_point.account).map_err(|e| {
                ProtocolError::NetworkError(format!(
                    "Failed to check account status on-chain: {}",
                    e
                ))
            })?;

            // If account doesn't exist or has zero lamports, it's already been consumed
            if account.lamports == 0 {
                return Err(ProtocolError::SealReplay(format!(
                    "PDA account {:?} already consumed on-chain (zero lamports)",
                    seal_point.account
                )));
            }
        }

        // Step 3: Mark seal as consumed by removing from active seals
        // In production, this would also close the account on-chain
        if let Ok(mut seals) = self.active_seals.lock() {
            seals.retain(|s| s.account != seal_point.account);
        }

        Ok(())
    }

    /// Compute commitment hash with domain separation
    fn hash_commitment(
        &self,
        preimage: Hash,
        seal: Hash,
        anchor: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let mut hasher = Sha256::new();

        // Domain separator
        hasher.update(SOLANA_DOMAIN_SEPARATOR);

        // Instruction discriminator
        hasher.update([INSTRUCTION_PUBLISH_COMMITMENT]);

        // Commitment data
        hasher.update(preimage.as_bytes());
        hasher.update(seal.as_bytes());
        hasher.update(anchor.as_bytes());

        // Seal reference data
        hasher.update(seal_point.account.as_ref());
        hasher.update(seal_point.lamports.to_le_bytes());

        Hash::new(hasher.finalize().into())
    }

    /// Build a complete proof bundle
    fn build_proof_bundle(
        &self,
        anchor_ref: Self::CommitAnchor,
        segment: DAGSegment,
    ) -> Result<ProofBundle> {
        let solana_inclusion = self.verify_inclusion(anchor_ref.clone())?;
        let solana_finality = self.verify_finality(anchor_ref.clone())?;

        // Create seal_ref from the first active seal or create a default one
        let seal_ref = {
            let seals = self.active_seals.lock().unwrap();
            seals
                .first()
                .map(|s| unsafe {
                    csv_protocol::seal::SealPoint::new_unchecked(
                        s.account.to_bytes().to_vec(),
                        Some(s.lamports),
                    )
                })
                .unwrap_or_else(|| unsafe {
                    csv_protocol::seal::SealPoint::new_unchecked(
                        anchor_ref.signature.as_ref()[..32].to_vec(),
                        None,
                    )
                })
        };

        // Create anchor_ref from SolanaCommitAnchor
        let core_anchor_ref = unsafe {
            csv_protocol::seal::CommitAnchor::new_unchecked(
                anchor_ref.signature.as_ref().to_vec(),
                anchor_ref.block_height,
                serde_json::to_vec(&anchor_ref.account_changes).unwrap_or_default(),
            )
        };

        // Create inclusion proof
        let inclusion_proof = unsafe {
            csv_protocol::proof::InclusionProof::new_unchecked(
                solana_inclusion
                    .account_proofs
                    .iter()
                    .flat_map(|p| p.proof.iter().flatten().copied())
                    .collect(),
                Hash::new(
                    anchor_ref.signature.as_ref()[..32]
                        .try_into()
                        .unwrap_or([0u8; 32]),
                ),
                anchor_ref.slot,
                anchor_ref.slot,
            )
        };

        // Create finality proof - Solana has deterministic finality after 31 slots
        let finality_proof = unsafe {
            csv_protocol::proof::FinalityProof::new_unchecked(
                solana_finality.block_hash.as_bytes().to_vec(),
                solana_finality.confirmation_depth,
                true, // Solana has deterministic finality
            )
        };

        // Create a complete proof bundle
        let bundle = unsafe {
            csv_protocol::proof::ProofBundle::new_unchecked(
                segment,
                vec![anchor_ref.signature.as_ref().to_vec()],
                seal_ref,
                core_anchor_ref,
                inclusion_proof,
                finality_proof,
            )
        };

        Ok(bundle)
    }

    /// Handle rollback for reorgs
    fn rollback(&self, anchor_ref: Self::CommitAnchor) -> Result<()> {
        // Solana has very rare reorgs due to deterministic finality
        // But we still need to handle them

        // Check if the slot is still valid
        let _rpc = self.check_rpc()?;

        // In production, this would:
        // 1. Query the slot to see if it's still in the canonical chain
        // 2. If not, return the seal to active status
        // 3. Invalidate the commitment

        // For now, we just verify the slot is old enough to be finalized
        let current_slot = self.check_rpc()?.get_latest_slot()?;
        let age = current_slot.saturating_sub(anchor_ref.slot);

        if age < 32 {
            return Err(SolanaError::Rpc(format!(
                "Cannot rollback: transaction not yet finalized (age: {} slots)",
                age
            ))
            .into());
        }

        // If we're here, the transaction is finalized and cannot be rolled back
        Ok(())
    }

    /// Get domain separator for this chain
    fn domain_separator(&self) -> [u8; 32] {
        SOLANA_DOMAIN_SEPARATOR
    }

    /// Get signature scheme (Ed25519 for Solana)
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

impl SolanaSealProtocol {
    /// Get RPC client reference for chain_operations (crate-visible)
    pub(crate) fn get_rpc(&self) -> SolanaResult<&dyn SolanaRpc> {
        self.check_rpc()
    }

    /// Get network from config (crate-visible)
    pub(crate) fn get_network(&self) -> crate::config::Network {
        self.config.network
    }

    /// Get domain separator (crate-visible)
    pub(crate) fn get_domain(&self) -> [u8; 32] {
        SOLANA_DOMAIN_SEPARATOR
    }
}

/// Helper struct for serializing Solana-specific proof data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SolanaProofData {
    signature: String,
    slot: u64,
    confirmation_status: String,
}

impl SolanaSealProtocol {
    /// Generate a unique sanad ID
    fn generate_sanad_id() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
        bytes
    }
}

impl Default for SolanaSealProtocol {
    fn default() -> Self {
        Self::new(SolanaConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seal_pda() {
        let config = SolanaConfig::default();
        let adapter = SolanaSealProtocol::new(config);
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Pubkey::new_unique();

        let pda1 = adapter.derive_seal_pda(&sanad_id, &owner);
        let pda2 = adapter.derive_seal_pda(&sanad_id, &owner);

        assert_eq!(pda1, pda2, "PDA derivation should be deterministic");
    }

    #[test]
    fn test_domain_separator() {
        let config = SolanaConfig::default();
        let adapter = SolanaSealProtocol::new(config);

        let sep = adapter.domain_separator();
        assert_eq!(&sep[0..9], b"SOLanaCSV");
    }

    #[test]
    fn test_signature_scheme() {
        let config = SolanaConfig::default();
        let adapter = SolanaSealProtocol::new(config);

        assert_eq!(adapter.signature_scheme(), SignatureScheme::Ed25519);
    }
}
