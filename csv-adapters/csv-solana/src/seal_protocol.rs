//! Solana adapter implementation for CSV
//!
//! Implements the SealProtocol trait for Solana using Program Derived Addresses (PDAs)
//! as single-use seals. When a seal is consumed, the PDA account is closed, transferring
//! lamports to the destination, making the seal cryptographically unspendable.

use async_trait::async_trait;
use csv_hash::Hash;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::{error::ProtocolError, seal_protocol::SealProtocol, signature::SignatureScheme};
use csv_wire::HashWire;
use sha2::{Digest, Sha256};
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use std::str::FromStr;

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

/// Program instruction discriminator.
///
/// The `create_seal` / `consume_seal` raw discriminators were removed: those
/// paths go through the Anchor discriminators in `anchor_client`
/// (LINT-DEADCODE-HYGIENE-001).
const INSTRUCTION_PUBLISH_COMMITMENT: u8 = 0x03;

/// Encode the deployed Anchor `create_seal` ABI. Keeping this pure makes the
/// canonical-ID/commitment distinction directly testable without an RPC.
fn create_seal_instruction_data(sanad_id: Hash, commitment: Hash) -> Vec<u8> {
    let mut instruction_data = Vec::with_capacity(8 + 32 + 32 + 32);
    instruction_data.extend_from_slice(&crate::anchor_client::discriminators::create_seal());
    instruction_data.extend_from_slice(sanad_id.as_bytes());
    instruction_data.extend_from_slice(commitment.as_bytes());
    instruction_data.extend_from_slice(&[0u8; 32]);
    instruction_data
}

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
            Some(keypair) => {
                // Convert SecretKey to bytes and create Keypair
                let secret_bytes = keypair.expose_secret();
                let keypair = Keypair::new_from_array(*secret_bytes);
                Some(ProgramWallet::from_keypair(keypair))
            }
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

    fn csv_program_id(&self) -> SolanaResult<Pubkey> {
        Pubkey::from_str(&self.config.csv_program_id).map_err(|e| {
            SolanaError::InvalidProgramId(format!("{} ({})", self.config.csv_program_id, e))
        })
    }

    /// Derive the Anchor `SanadAccount` PDA from the on-chain seeds.
    fn derive_seal_pda(&self, sanad_id: &Hash, owner: &Pubkey) -> SolanaResult<Pubkey> {
        let program_id = self.csv_program_id()?;
        log::info!(
            "SOLANA ADAPTER: Deriving PDA with program_id: {}",
            program_id
        );
        log::info!("SOLANA ADAPTER: Owner pubkey: {}", owner);
        log::info!(
            "SOLANA ADAPTER: Sanad ID: 0x{}",
            hex::encode(sanad_id.as_bytes())
        );
        let (pda, bump) = Pubkey::find_program_address(
            &[b"sanad", owner.as_ref(), sanad_id.as_bytes()],
            &program_id,
        );
        log::info!("SOLANA ADAPTER: Derived PDA: {} (bump: {})", pda, bump);
        Ok(pda)
    }

    /// Derive commitment PDA from commitment hash
    ///
    /// PDA derivation seam; the attested-mint path derives its PDAs in `anchor_client`.
    #[allow(dead_code)]
    fn derive_commitment_pda(&self, commitment: &Hash) -> SolanaResult<Pubkey> {
        let program_id = self.csv_program_id()?;
        let (pda, _bump) =
            Pubkey::find_program_address(&[b"commitment", commitment.as_bytes()], &program_id);
        Ok(pda)
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
    ///
    /// Local active-seal lookup; the runtime consults on-chain state instead.
    #[allow(dead_code)]
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

#[async_trait]
impl SealProtocol for SolanaSealProtocol {
    type SealPoint = SolanaSealPoint;
    type CommitAnchor = SolanaCommitAnchor;
    type InclusionProof = SolanaInclusionProof;
    type FinalityProof = SolanaFinalityProof;

    /// Create a new seal account (PDA) for a sanad
    ///
    /// Returns the exact PDA that `publish()` will create on-chain.
    async fn create_seal(
        &self,
        amount: Option<u64>,
        sanad_id: Hash,
        _commitment: Hash,
    ) -> Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| SolanaError::Wallet("No wallet configured".to_string()))?;

        let owner = wallet.pubkey();
        let lamports = amount.unwrap_or(1_000_000); // Default 0.001 SOL rent exemption

        // The transaction is submitted by `publish`, but the account identity is
        // already fixed by the canonical Sanad ID and wallet owner. Returning a
        // timestamp-derived placeholder here made the local seal reference differ
        // from the account actually created on-chain.
        let account = self.derive_seal_pda(&sanad_id, &owner)?;

        Ok(SolanaSealPoint {
            account,
            owner,
            lamports,
            seed: Some(sanad_id.as_bytes().to_vec()),
        })
    }

    /// Publish a commitment to the seal account
    ///
    /// For Solana, this performs the real on-chain create_seal transaction while
    /// preserving the distinct canonical Sanad ID and content commitment.
    async fn publish(
        &self,
        commitment: Hash,
        seal_point: Self::SealPoint,
        sanad_id: Hash,
    ) -> Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| SolanaError::Wallet("No wallet configured".to_string()))?;
        let owner = wallet.pubkey();

        let lamports = seal_point.lamports;

        // Derive the PDA from the canonical Sanad ID and owner.
        let seal_pda = self.derive_seal_pda(&sanad_id, &owner)?;

        log::info!(
            "SOLANA: Publishing commitment to seal account\n\
             SOLANA: Seal account: {}\n\
             SOLANA: Commitment hash: 0x{}\n\
             SOLANA: Wallet owner: {}",
            seal_pda,
            hex::encode(commitment.as_bytes()),
            owner,
        );

        let rpc = self.check_rpc()?;
        let recent_blockhash = rpc
            .get_recent_blockhash()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get recent blockhash: {}", e)))?;

        // Build create_seal with the distinct canonical ID and commitment.
        let instruction_data = create_seal_instruction_data(sanad_id, commitment);

        let program_id = self.csv_program_id()?;
        let instruction = Instruction {
            program_id,
            accounts: vec![
                solana_sdk::instruction::AccountMeta::new(seal_pda, false),
                solana_sdk::instruction::AccountMeta::new(owner, true),
                solana_sdk::instruction::AccountMeta::new_readonly(
                    solana_system_interface::program::ID,
                    false,
                ),
            ],
            data: instruction_data,
        };

        let message = solana_sdk::message::Message::new(&[instruction], Some(&owner));
        let mut transaction = solana_sdk::transaction::Transaction::new_unsigned(message);
        transaction.sign(&[&wallet.keypair], recent_blockhash);

        let signature = rpc.send_transaction(&transaction).map_err(|e| {
            SolanaError::Rpc(format!("Failed to send create_seal transaction: {}", e))
        })?;
        rpc.wait_for_confirmation(&signature)
            .map_err(|e| SolanaError::Rpc(format!("Transaction confirmation failed: {}", e)))?;

        let slot = rpc
            .get_latest_slot()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get slot: {}", e)))?;

        // Store seal in active_seals with seed = commitment bytes
        let real_seal = SolanaSealPoint {
            account: seal_pda,
            owner,
            lamports,
            seed: Some(sanad_id.as_bytes().to_vec()),
        };
        self.store_seal(real_seal.clone());

        log::info!("SOLANA: Seal created successfully");

        Ok(SolanaCommitAnchor {
            signature,
            slot,
            block_height: slot,
            account_changes: vec![AccountChange {
                pubkey: seal_pda,
                prev_lamports: 0,
                new_lamports: lamports,
                prev_data: None,
                new_data: Some(commitment.as_bytes().to_vec()),
                closed: false,
            }],
        })
    }

    /// Verify inclusion by checking the transaction is in a block
    async fn verify_inclusion(
        &self,
        anchor_ref: Self::CommitAnchor,
    ) -> Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
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
                            HashWire::from(Hash::new(hasher.finalize().into()))
                        }),
                    }
                })
                .collect(),
        };

        Ok(proof)
    }

    /// Verify finality by checking block depth
    async fn verify_finality(
        &self,
        anchor_ref: Self::CommitAnchor,
    ) -> Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        let rpc = self.check_rpc()?;

        // Solana has deterministic finality after ~32 slots (12-16 seconds)
        // For devnet/testnet, we use shorter confirmation

        let current_slot = rpc.get_latest_slot()?;
        let confirmation_depth = current_slot.saturating_sub(anchor_ref.slot);

        // Solana requires 32 slots for finality
        let is_finalized = confirmation_depth >= 32;

        if !is_finalized {
            return Err(SolanaError::Rpc(format!(
                "Transaction not yet finalized (confirmation depth: {} slots, required: 32)",
                confirmation_depth
            ))
            .into());
        }

        // Get the actual block hash from the slot using RPC
        let block_hash = rpc
            .get_block_hash(anchor_ref.slot)
            .map_err(|e| SolanaError::Rpc(format!("Failed to get block hash: {}", e)))?;

        let proof = SolanaFinalityProof {
            slot: anchor_ref.slot,
            block_hash: HashWire::from(Hash::new(block_hash.to_bytes())),
            confirmation_depth,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };

        Ok(proof)
    }

    /// Enforce seal by closing the account (consuming it)
    async fn enforce_seal(
        &self,
        seal_point: Self::SealPoint,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that a PDA account cannot be consumed more than once
        // by checking both local registry and on-chain account state

        // Step 1: Check local registry (fast path)
        if let Ok(seals) = self.active_seals.lock()
            && !seals.iter().any(|s| s.account == seal_point.account)
        {
            return Err(Box::new(ProtocolError::SealReplay(format!(
                "PDA account {:?} not found in active seals",
                seal_point.account
            ))));
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
                return Err(Box::new(ProtocolError::SealReplay(format!(
                    "PDA account {:?} already consumed on-chain (zero lamports)",
                    seal_point.account
                ))));
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
    async fn build_proof_bundle(
        &self,
        anchor_ref: Self::CommitAnchor,
        segment: csv_protocol::seal_protocol::DagSegment,
    ) -> Result<ProofBundle, Box<dyn std::error::Error + 'static>> {
        let solana_inclusion = self.verify_inclusion(anchor_ref.clone()).await?;
        let solana_finality = self.verify_finality(anchor_ref.clone()).await?;

        // Create seal_ref from the first active seal or create a default one
        let seal_ref = {
            let seals = self.active_seals.lock().expect("Seal mutex not poisoned");
            seals
                .first()
                .map(|s| unsafe {
                    csv_protocol::seal::SealPoint::new_unchecked(
                        s.account.to_bytes().to_vec(),
                        Some(s.lamports),
                        None,
                    )
                })
                .unwrap_or_else(|| unsafe {
                    csv_protocol::seal::SealPoint::new_unchecked(
                        anchor_ref.signature.as_ref()[..32].to_vec(),
                        None,
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
            csv_protocol::proof_taxonomy::InclusionProof::new_unchecked(
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
        let block_hash: Hash = solana_finality
            .block_hash
            .clone()
            .try_into()
            .unwrap_or_else(|_| Hash::zero());
        let finality_proof = unsafe {
            csv_protocol::proof_taxonomy::FinalityProof::new_unchecked(
                block_hash.as_bytes().to_vec(),
                solana_finality.confirmation_depth,
                true, // Solana has deterministic finality
            )
        };

        // Convert DagSegment to DAGSegment for state transition DAG
        // Compute node_id from anchor hashes to ensure uniqueness
        let mut node_id_data = Vec::new();
        node_id_data.extend_from_slice(segment.anchor_from.as_bytes());
        node_id_data.extend_from_slice(segment.anchor_to.as_bytes());
        let node_id = csv_hash::Hash::new(csv_hash::csv_tagged_hash("dag-node-id", &node_id_data));

        // Create a single DAGNode from the transition data
        let dag_node = csv_hash::dag::DAGNode::new(
            node_id,
            segment.transition_data.clone(),
            vec![segment.proof.clone()], // Use proof as signature
            vec![],                      // No witnesses for single transition
            vec![segment.anchor_from],   // Parent is the source anchor
        );

        // Compute root_commitment from the node
        let root_commitment = dag_node.hash();
        let dag_segment = csv_hash::dag::DAGSegment::new(vec![dag_node], root_commitment);
        let bundle = csv_protocol::proof_taxonomy::ProofBundle::with_signature_scheme(
            csv_protocol::SignatureScheme::Ed25519,
            dag_segment,
            vec![anchor_ref.signature.as_ref().to_vec()],
            seal_ref,
            core_anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| {
            Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
        })?;

        Ok(bundle)
    }

    /// Handle rollback for reorgs
    async fn rollback(
        &self,
        anchor_ref: Self::CommitAnchor,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
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
///
/// Retained as the Solana proof wire shape; the runtime proof path uses `ProofBundle`.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SolanaProofData {
    signature: String,
    slot: u64,
    confirmation_status: String,
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
    fn create_seal_abi_keeps_canonical_id_distinct_from_commitment() {
        let sanad_id = Hash::new([0x11; 32]);
        let commitment = Hash::new([0x22; 32]);
        let encoded = create_seal_instruction_data(sanad_id, commitment);

        assert_eq!(
            &encoded[..8],
            &crate::anchor_client::discriminators::create_seal()
        );
        assert_eq!(&encoded[8..40], sanad_id.as_bytes());
        assert_eq!(&encoded[40..72], commitment.as_bytes());
        assert_ne!(&encoded[8..40], &encoded[40..72]);
        assert_eq!(&encoded[72..104], &[0u8; 32]);
    }

    #[test]
    fn test_derive_seal_pda() {
        let config = SolanaConfig::default();
        let adapter = SolanaSealProtocol::new(config);
        let sanad_id = Hash::new([1u8; 32]);
        let owner = Pubkey::new_unique();

        let pda1 = adapter.derive_seal_pda(&sanad_id, &owner).unwrap();
        let pda2 = adapter.derive_seal_pda(&sanad_id, &owner).unwrap();

        assert_eq!(pda1, pda2, "PDA derivation should be deterministic");
        assert!(!pda1.is_on_curve(), "PDA must be off-curve");
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
