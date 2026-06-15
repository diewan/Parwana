//! Runtime adapter wrapper for Solana chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Solana-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer,
};
use csv_protocol::finality::capabilities::{
    ChainCapabilities, StateModel, FinalityModel, ProofModel, 
    ReplayProtectionModel, ReorgRisk, ChainRole
};
use csv_protocol::signature::SignatureScheme;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

use crate::ops::SolanaBackend;

/// Runtime adapter wrapper for Solana
pub struct SolanaRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<SolanaBackend>,
}

impl SolanaRuntimeAdapter {
    /// Create a new Solana runtime adapter
    pub fn new(backend: Arc<SolanaBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities {
            state_model: StateModel::Account,
            finality_model: FinalityModel::OptimisticWithSlotExpiry { slots: 32 },
            finality_depth: 32,
            deterministic_finality: false,
            proof_model: ProofModel::SlotConfirmation,
            replay_protection: ReplayProtectionModel::PdaClosed,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        };
        let signature_scheme = SignatureScheme::Ed25519;

        Self {
            chain_id,
            capabilities,
            signature_scheme,
            backend,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for SolanaRuntimeAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        self.capabilities.clone()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    async fn lock_sanad(
        &self,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        let result = self.backend
            .lock_sanad(&sanad_id, destination_chain, "0x0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        Ok(LockResult {
            tx_hash: result.transaction_hash,
            block_height: result.block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // For Solana, minting means calling the mint function on the smart contract
        // with the lock proof from the source chain
        //
        // This implementation:
        // 1. Deserializes the proof bundle
        // 2. Builds the mint transaction instruction
        // 3. Signs the transaction with the wallet
        // 4. Broadcasts the transaction via RPC
        // 5. Returns the mint_tx_hash as result

        use csv_protocol::proof_taxonomy::ProofBundle;
        use solana_sdk::instruction::Instruction;
        use solana_sdk::transaction::Transaction;
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;

        // Deserialize the proof bundle
        let proof_bundle = ProofBundle::from_canonical_bytes(proof_bundle).map_err(|e| format!("Failed to deserialize proof bundle: {}", e))
            .map_err(|e| AdapterError::Generic(format!("Failed to deserialize proof bundle: {}", e)))?;

        // Get the program ID from backend seal_protocol config
        let program_id = Pubkey::from_str(&self.backend.seal_protocol().config.csv_program_id)
            .map_err(|e| AdapterError::Generic(format!("Invalid program ID: {}", e)))?;

        // Get the wallet for signing from backend seal_protocol
        let wallet = self.backend.seal_protocol().wallet.as_ref()
            .ok_or_else(|| AdapterError::Generic("Wallet not configured for mint operation".to_string()))?;

        // Build the mint instruction
        // The mint instruction should include:
        // - The sanad_id from the transfer
        // - The commitment from the proof bundle
        // - The source chain seal reference
        let sanad_id_bytes = transfer.sanad_id.as_bytes();
        let commitment_bytes = proof_bundle.transition_dag.root_commitment.as_bytes();

        // Create the instruction data
        // This is a simplified version - the actual instruction format depends on the Solana program
        let mut instruction_data = Vec::new();
        instruction_data.push(0x04); // Mint instruction discriminator
        instruction_data.extend_from_slice(sanad_id_bytes);
        instruction_data.extend_from_slice(commitment_bytes);

        // Derive the PDA for the sanad account
        let sanad_pda = Pubkey::create_with_seed(
            &wallet.pubkey(),
            &hex::encode(sanad_id_bytes),
            &program_id,
        ).map_err(|e| AdapterError::Generic(format!("Failed to derive PDA: {}", e)))?;

        // Build the instruction
        let instruction = Instruction {
            program_id,
            accounts: vec![
                solana_sdk::instruction::AccountMeta::new(sanad_pda, false),
                solana_sdk::instruction::AccountMeta::new(wallet.pubkey(), true),
                solana_sdk::instruction::AccountMeta::new_readonly(solana_sdk::pubkey::Pubkey::from([0u8; 32]), false),
            ],
            data: instruction_data,
        };

        // Get recent blockhash from backend RPC
        let recent_blockhash = self.backend.rpc().get_recent_blockhash()
            .map_err(|e| AdapterError::Generic(format!("Failed to get recent blockhash: {}", e)))?;

        // Build and sign the transaction
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&wallet.pubkey()),
            &[&wallet.keypair],
            recent_blockhash,
        );

        // Send the transaction
        let signature = self.backend.rpc().send_transaction(&transaction)
            .map_err(|e| AdapterError::Generic(format!("Failed to send transaction: {}", e)))?;

        // Get the block height - use slot as proxy since get_block_height not available in SolanaRpc
        let block_height = self.backend.rpc().get_latest_slot()
            .map_err(|e| AdapterError::Generic(format!("Failed to get slot: {}", e)))?;

        Ok(MintResult {
            tx_hash: signature.to_string(),
            block_height,
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainProofProvider;
        use csv_protocol::proof_taxonomy::InclusionProof as CoreInclusionProof;
        use csv_protocol::proof_taxonomy::FinalityProof;

        // Build inclusion proof using the backend's ChainProofProvider implementation
        let commitment = transfer.sanad_id;
        let block_height = lock_result.block_height;
        let anchor_id = &transfer.lock_tx_hash;

        let inclusion_proof = self.backend
            .build_inclusion_proof(&commitment, block_height, anchor_id)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Build finality proof
        let finality_proof = self.backend
            .build_finality_proof(&hex::encode(anchor_id))
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build finality proof: {}", e)))?;

        // Construct ProofBundle from inclusion and finality proofs
        let seal_ref = csv_hash::seal::SealPoint::new(anchor_id.clone(), Some(block_height), None)
            .map_err(|e| AdapterError::Generic(format!("Invalid seal point: {}", e)))?;

        let anchor_ref = csv_hash::seal::CommitAnchor::new(anchor_id.clone(), block_height, commitment.as_bytes().to_vec())
            .map_err(|e| AdapterError::Generic(format!("Invalid commit anchor: {}", e)))?;

        ProofBundle::with_signature_scheme(
            self.signature_scheme,
            csv_hash::dag::DAGSegment::new(),
            vec![],
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to create proof bundle: {}", e)))
    }

    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainProofProvider;

        // Validate the proof bundle using the backend's ChainProofProvider implementation
        let inclusion_proof = &proof_bundle.inclusion_proof;
        let finality_proof = &proof_bundle.finality_proof;
        let commitment = &transfer.sanad_id;

        let is_valid = self.backend
            .verify_proof_bundle(inclusion_proof, finality_proof, commitment)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to verify proof bundle: {}", e)))?;

        if !is_valid {
            return Err(AdapterError::Generic("Proof bundle validation failed".to_string()));
        }

        Ok(())
    }

    async fn check_seal_registry(&self, seal_id: &[u8]) -> Result<SealRegistryStatus, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainQuery;

        // Check if the seal account exists on-chain using the backend's ChainQuery implementation
        // Convert seal_id to a string address for querying
        let address_str = hex::encode(seal_id);

        // Try to get account info to check if seal exists
        match self.backend.get_account_info(&address_str).await {
            Ok(Some(_)) => Ok(SealRegistryStatus::Registered),
            Ok(None) => Ok(SealRegistryStatus::NotRegistered),
            Err(e) => Err(AdapterError::Generic(format!("Failed to check seal registry: {}", e))),
        }
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainQuery;

        // Get balance using the backend's ChainQuery implementation
        let balance_info = self.backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to get balance: {}", e)))?;

        Ok(balance_info.total.to_string())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
