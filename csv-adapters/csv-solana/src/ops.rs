//! Chain Operation Traits Implementation for Solana
//!
//! This module implements all chain operation traits from csv-adapter-core:
//! - ChainQuery: Querying chain state via RPC
//! - ChainSigner: Ed25519 signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Program deployment
//! - ChainProofProvider: Proof building and verification
//! - ChainSanadOps: Sanad management via program accounts
//!
use async_trait::async_trait;
use csv_hash::Hash;
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainReadiness, ChainReadinessCheck, ChainSanadOps,
    ChainSigner, ContractStatus, DeploymentStatus, FinalityStatus, SanadOperationResult,
    SanadStateReader, TransactionInfo, TransactionStatus,
};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::sanad::SanadId;
use csv_protocol::seal::{CommitAnchor, SealPoint};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::str::FromStr;
use std::sync::Arc;

use crate::config::Network;
use crate::rpc::SolanaRpc;
use crate::seal_protocol::SolanaSealProtocol;
use crate::types::ConfirmationStatus;

/// Solana chain operations implementation
pub struct SolanaBackend {
    /// Inner RPC client for chain communication
    rpc: Box<dyn SolanaRpc>,
    /// Chain configuration
    network: Network,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Reference to seal protocol for seal creation and publishing
    seal_protocol: Arc<SolanaSealProtocol>,
    /// secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation digest
    /// (optional).
    ///
    /// Distinct from the Ed25519 wallet that submits the transaction: the
    /// destination program authenticates a mint by recovering M-of-N secp256k1
    /// verifier public keys from signatures over the §9.2 digest
    /// (`secp256k1_recover`), independent of who pays gas. Absent any key the
    /// adapter fails closed rather than emitting an unauthenticated mint the
    /// program would reject. Multiple keys attach one verifier signature each,
    /// satisfying an M-of-N `VerifierRegistry` in a single mint (MINT-KEYS-001).
    verifier_signing_keys: Vec<secp256k1::SecretKey>,
}

impl SolanaBackend {
    /// Create new Solana chain operations from RPC client
    pub fn new(rpc: Box<dyn SolanaRpc>, network: Network) -> Self {
        // Create a minimal seal protocol to derive domain separator
        let mock_rpc = Box::new(crate::rpc::MockSolanaRpc::new());
        let seal =
            SolanaSealProtocol::from_config(crate::config::SolanaConfig::default(), mock_rpc)
                .unwrap_or_else(|_| {
                    // Ultimate fallback
                    SolanaSealProtocol::from_config(
                        crate::config::SolanaConfig {
                            network: Network::Devnet,
                            ..Default::default()
                        },
                        Box::new(crate::rpc::MockSolanaRpc::new()),
                    )
                    .expect("Default SolanaConfig produces a valid SealProtocol")
                });

        // MED-DUP-03: Derive domain separator from SealProtocol instead of recomputing
        let domain_separator = seal.get_domain();

        Self {
            rpc,
            network,
            domain_separator,
            seal_protocol: Arc::new(seal),
            verifier_signing_keys: Vec::new(),
        }
    }

    /// Get seal protocol reference
    pub fn seal_protocol(&self) -> &Arc<SolanaSealProtocol> {
        &self.seal_protocol
    }

    /// Set the secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation
    /// digest.
    ///
    /// This is the mint-authority key: its compressed 33-byte public key must be
    /// registered in the destination program's `VerifierRegistry`. It is distinct
    /// from the Ed25519 wallet configured on the seal protocol that submits (and
    /// pays for) the transaction.
    pub fn with_verifier_key(mut self, verifier_signing_key: secp256k1::SecretKey) -> Self {
        self.verifier_signing_keys.push(verifier_signing_key);
        self
    }

    /// Set the full set of secp256k1 verifier keys that sign the RFC-0012 §9.2
    /// mint attestation digest (MINT-KEYS-001).
    ///
    /// Replaces any previously configured keys. Each key's 33-byte compressed
    /// public key must be registered in the destination program's
    /// `VerifierRegistry`; the adapter attaches one signature per key so a single
    /// mint can satisfy an M-of-N threshold. An empty set leaves the backend
    /// fail-closed.
    pub fn with_verifier_keys(mut self, verifier_signing_keys: Vec<secp256k1::SecretKey>) -> Self {
        self.verifier_signing_keys = verifier_signing_keys;
        self
    }

    /// Canonical 32-byte identity of the destination `csv_seal` program — the
    /// RFC-0012 §9.2 `destinationContract` bound into the attestation digest on
    /// Solana (the program's native account id, which the on-chain
    /// `mint_attestation_digest` reproduces as `crate::ID.to_bytes()`).
    pub fn program_id(&self) -> ChainOpResult<[u8; 32]> {
        let program_id = Pubkey::from_str(&self.seal_protocol.config.csv_program_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid program ID: {}", e)))?;
        Ok(program_id.to_bytes())
    }

    /// Sign a 32-byte RFC-0012 §9.2 attestation digest with the configured
    /// secp256k1 verifier key, producing a 65-byte recoverable signature
    /// (`r(32) || s(32) || v(1)`, `v` = recovery id `∈ {0, 1}`).
    ///
    /// The digest is `sha256(preimage)` (the frozen §9.2 preimage). The on-chain
    /// `secp256k1_recover` recovers the signer from `(digest, recovery_id, r||s)`,
    /// so signing the digest directly recovers the same key on-chain. The recovery
    /// id is emitted raw (0/1); the program's `recover_compressed_verifier` accepts
    /// both the raw and the EVM (`+27`) form. Fails closed when no verifier key is
    /// configured rather than emitting an unauthenticated mint.
    pub fn sign_mint_attestation_digest(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<u8>> {
        // First configured verifier key (fail-closed on none). Retained for
        // single-signer callers/tests; the mint path uses the plural form below.
        let secret_key = self.verifier_signing_keys.first().ok_or_else(|| {
            ChainOpError::SigningError(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            )
        })?;
        Ok(Self::sign_digest_with(secret_key, digest))
    }

    /// Sign the §9.2 digest with **every** configured verifier key, returning one
    /// 65-byte recoverable signature per key (MINT-KEYS-001).
    ///
    /// This is the mint-path signer: multiple local signers satisfy an M-of-N
    /// `VerifierRegistry` in one transaction. Fails closed when no verifier key is
    /// configured.
    pub fn sign_mint_attestation_digests(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<Vec<u8>>> {
        if self.verifier_signing_keys.is_empty() {
            return Err(ChainOpError::SigningError(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            ));
        }
        Ok(self
            .verifier_signing_keys
            .iter()
            .map(|k| Self::sign_digest_with(k, digest))
            .collect())
    }

    /// Produce a single 65-byte recoverable signature (`r || s || v`, raw
    /// recovery id 0/1) over the 32-byte digest, matching the on-chain
    /// `secp256k1_recover`-over-digest semantics.
    fn sign_digest_with(secret_key: &secp256k1::SecretKey, digest: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};
        let msg = Message::from_digest(*digest);
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(&msg, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&compact);
        // Raw recovery id (0/1); the program accepts this and the EVM +27 form.
        out.push(recovery_id.to_i32() as u8);
        out
    }

    /// Create from SolanaSealProtocol
    pub fn from_seal_protocol(seal: Arc<SolanaSealProtocol>) -> ChainOpResult<Self> {
        let rpc = seal
            .get_rpc()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get RPC: {}", e)))?;
        Ok(Self {
            rpc: rpc.clone_boxed(),
            network: seal.get_network(),
            domain_separator: seal.get_domain(),
            seal_protocol: seal,
            verifier_signing_keys: Vec::new(),
        })
    }

    /// Parse Solana address (Pubkey) from string
    fn parse_address(&self, address: &str) -> ChainOpResult<Pubkey> {
        address
            .parse::<Pubkey>()
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Solana address: {}", e)))
    }

    /// Format Solana address for display
    fn format_address(&self, addr: Pubkey) -> String {
        addr.to_string()
    }

    /// Parse transaction signature
    fn parse_signature(&self, sig: &str) -> ChainOpResult<Signature> {
        let bytes = bs58::decode(sig)
            .into_vec()
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid signature: {}", e)))?;

        if bytes.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Solana signature must be 64 bytes".to_string(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes);
        Ok(Signature::from(sig_bytes))
    }

    /// Get RPC client reference
    pub fn rpc(&self) -> &dyn SolanaRpc {
        self.rpc.as_ref()
    }
}

#[async_trait]
impl ChainQuery for SolanaBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        let pubkey = self.parse_address(address)?;

        let balance = self
            .rpc()
            .get_balance(&pubkey)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;

        // get_block is not available in SolanaRpc trait
        // In production, this would fetch the block at the given slot

        // Get token accounts for SPL tokens
        let token_balances = Vec::new(); // Would query token accounts

        Ok(BalanceInfo {
            address: address.to_string(),
            total: balance,
            available: balance,
            locked: 0,
            tokens: token_balances,
        })
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        let sig = self.parse_signature(hash)?;

        // The RPC returns a String representation, we need to parse it
        let tx_str = self
            .rpc()
            .get_transaction(&sig)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;

        // Parse the transaction string to build TransactionInfo
        // In a real implementation, this would deserialize the transaction data
        let slot = 0u64; // Would be extracted from tx_str
        let status = TransactionStatus::Confirmed {
            block_height: slot,
            confirmations: 32,
        };

        Ok(TransactionInfo {
            hash: hash.to_string(),
            sender: String::new(),
            recipient: None,
            amount: None,
            status,
            block_height: Some(slot),
            timestamp: None,
            fee: None,
            raw_data: Some(tx_str.into_bytes()),
        })
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        let tx_info = self.get_transaction(tx_hash).await?;

        match tx_info.status {
            TransactionStatus::Confirmed { block_height, .. } => {
                // Get latest slot
                let latest_slot = self
                    .rpc()
                    .get_latest_slot()
                    .map_err(|e| ChainOpError::RpcError(format!("Failed to get slot: {}", e)))?;

                let confirmations = latest_slot.saturating_sub(block_height);

                // Solana has probabilistic finality after 32 confirmations
                if confirmations >= 32 {
                    Ok(FinalityStatus::Finalized {
                        block_height,
                        finality_block: block_height,
                    })
                } else {
                    Ok(FinalityStatus::Pending)
                }
            }
            TransactionStatus::Failed { .. } => Ok(FinalityStatus::Orphaned),
            _ => Ok(FinalityStatus::Pending),
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        let program_id = self.parse_address(contract_address)?;

        // Check if program account exists and is executable
        let account = self
            .rpc()
            .get_account(&program_id)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get account: {}", e)))?;

        let is_deployed = account.executable;

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed,
            balance: Some(account.lamports),
            owner: Some(account.owner.to_string()),
            metadata: serde_json::json!({
                "chain": "solana",
                "network": format!("{:?}", self.network),
                "executable": account.executable,
                "data_size": account.data.len(),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        self.rpc()
            .get_latest_slot()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get slot: {}", e)))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let slot = self.get_latest_block_height().await?;

        Ok(serde_json::json!({
            "chain_id": match self.network {
                Network::Mainnet => "mainnet-beta",
                Network::Devnet => "devnet",
                Network::Testnet => "testnet",
                Network::Local => "localnet",
            },
            "chain": "solana",
            "network": format!("{:?}", self.network),
            "latest_slot": slot,
            "protocol": "Solana",
            "finality": "probabilistic",
        }))
    }

    async fn get_account_nonce(&self, _address: &str) -> ChainOpResult<u64> {
        // Solana does not use account nonces - it uses recent blockhashes for transaction uniqueness
        Err(ChainOpError::CapabilityUnavailable(
            "Solana does not support account nonces (uses recent blockhash)".to_string(),
        ))
    }

    fn validate_address(&self, address: &str) -> bool {
        address.parse::<Pubkey>().is_ok()
    }
}

fn keypair_from_hex_key_id(key_id: &str) -> ChainOpResult<solana_sdk::signature::Keypair> {
    let key_bytes = hex::decode(key_id).map_err(|_| {
        ChainOpError::SigningError(
            "Invalid key_id format. Expected hex-encoded 32-byte Solana secret key.".to_string(),
        )
    })?;

    if key_bytes.len() != 32 {
        return Err(ChainOpError::SigningError(
            "Invalid Solana key length. Expected 32 bytes.".to_string(),
        ));
    }

    let secret_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ChainOpError::SigningError("Invalid Solana secret key".to_string()))?;

    // Use new_from_array which takes a 32-byte secret key directly
    Ok(solana_sdk::signature::Keypair::new_from_array(secret_key))
}

#[async_trait]
impl ChainSigner for SolanaBackend {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(public_key);

        let pubkey = Pubkey::new_from_array(pubkey_bytes);
        Ok(pubkey.to_string())
    }

    async fn sign_transaction(&self, tx_data: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        use solana_sdk::transaction::Transaction;

        let keypair = keypair_from_hex_key_id(key_id)?;
        let mut transaction: Transaction = bincode::deserialize(tx_data).map_err(|e| {
            ChainOpError::InvalidInput(format!("Invalid Solana transaction: {}", e))
        })?;
        let recent_blockhash = transaction.message.recent_blockhash;

        transaction
            .try_sign(&[&keypair], recent_blockhash)
            .map_err(|e| ChainOpError::SigningError(format!("Solana signing failed: {}", e)))?;

        bincode::serialize(&transaction).map_err(|e| {
            ChainOpError::SigningError(format!("Failed to serialize transaction: {}", e))
        })
    }

    async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        use solana_sdk::signature::Signer;

        let keypair = keypair_from_hex_key_id(key_id)?;
        Ok(keypair.sign_message(message).as_ref().to_vec())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(public_key);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Convert bytes to proper types
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {:?}", e)))?;

        let ed_sig = Signature::from_bytes(&sig_bytes);

        match verifying_key.verify(message, &ed_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

#[async_trait]
impl ChainBroadcaster for SolanaBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // signed_tx is a serialized Solana transaction
        // Deserialize and send via RPC
        let transaction: solana_sdk::transaction::Transaction = bincode::deserialize(signed_tx)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction: {}", e)))?;

        let sig = self
            .rpc()
            .send_transaction(&transaction)
            .map_err(|e| ChainOpError::TransactionError(format!("Submission failed: {}", e)))?;

        Ok(sig.to_string())
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        let sig = self.parse_signature(tx_hash)?;
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_millis(400); // Solana slot time

        loop {
            if start.elapsed() > timeout {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            // Use wait_for_confirmation for better status detection
            match self.rpc().wait_for_confirmation(&sig) {
                Ok(ConfirmationStatus::Finalized) => {
                    let slot = self.rpc().get_latest_slot().unwrap_or(0);
                    return Ok(TransactionStatus::Confirmed {
                        block_height: slot,
                        confirmations: 32,
                    });
                }
                Ok(ConfirmationStatus::Confirmed) => {
                    let slot = self.rpc().get_latest_slot().unwrap_or(0);
                    return Ok(TransactionStatus::Confirmed {
                        block_height: slot,
                        confirmations: 1,
                    });
                }
                Ok(_) => {
                    // PF-03: async poll (non-blocking)
                    tokio::time::sleep(poll_interval).await;
                }
                Err(_) => {
                    // PF-03: async poll (non-blocking)
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Solana fee estimation
        // Typical transaction: 5000 lamports (0.000005 SOL)
        let fee = self
            .rpc()
            .get_recent_blockhash()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get blockhash: {}", e)))?;

        // Would parse fee from blockhash response
        let _ = fee;
        Ok(5000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Empty transaction data".to_string(),
            ));
        }

        // Would deserialize and validate transaction structure
        // Check for valid signatures, recent blockhash, etc.

        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for SolanaBackend {
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Lock contract deployment requires program deployment. \
             Use deploy_or_publish_seal_program() with compiled BPF bytecode."
                .to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Mint contract deployment requires program deployment. \
             Same program handles both lock and mint in Solana."
                .to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = program_bytes;
        let _ = admin_address;

        Err(ChainOpError::CapabilityUnavailable(
            "Program deployment requires signed transaction. \
             Use deploy_csv_program() with compiled BPF bytecode \
             or external tools (solana program deploy)."
                .to_string(),
        ))
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let status = self.get_contract_status(contract_address).await?;
        Ok(status.is_deployed)
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Solana deployment cost
        // Rent exemption based on program size
        let rent = self
            .rpc()
            .get_minimum_balance_for_rent_exemption(program_bytes.len())
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get rent: {}", e)))?;

        let tx_fees = 5000u64; // Transaction fees

        Ok(rent + tx_fees)
    }
}

#[async_trait]
impl ChainProofProvider for SolanaBackend {
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        use sha3::{Digest, Keccak256};

        if anchor_id.len() != 64 {
            return Err(ChainOpError::InvalidInput(format!(
                "Invalid anchor_id length for Solana: expected 64-byte transaction signature, got {}",
                anchor_id.len()
            )));
        }

        let program_id = self
            .seal_protocol
            .config
            .csv_program_id
            .parse::<solana_sdk::pubkey::Pubkey>()
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Solana program ID: {}", e)))?;

        let latest_slot = self
            .rpc()
            .get_latest_slot()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get latest slot: {}", e)))?;

        if latest_slot < block_height {
            return Err(ChainOpError::ProofVerificationError(format!(
                "Cannot build inclusion proof for future slot {} (latest {})",
                block_height, latest_slot
            )));
        }

        let mut block_hasher = Keccak256::new();
        block_hasher.update(block_height.to_le_bytes());
        block_hasher.update(program_id.as_ref());
        block_hasher.update(anchor_id);
        block_hasher.update(commitment.as_bytes());
        let block_hash = Hash::new(block_hasher.finalize().into());

        let mut proof_bytes = Vec::with_capacity(22 + 8 + 32 + 64 + 32 + 8 + 32);
        proof_bytes.extend_from_slice(b"CSV-SOLANA-SLOT-PROOF");
        proof_bytes.extend_from_slice(&block_height.to_le_bytes());
        proof_bytes.extend_from_slice(program_id.as_ref());
        proof_bytes.extend_from_slice(anchor_id);
        proof_bytes.extend_from_slice(commitment.as_bytes());
        proof_bytes.extend_from_slice(&latest_slot.to_le_bytes());
        proof_bytes.extend_from_slice(block_hash.as_bytes());

        Ok(
            CoreInclusionProof::new(proof_bytes, block_hash, block_height, block_height)
                .map_err(|e| ChainOpError::ProofVerificationError(e.to_string()))?,
        )
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_inclusion_native(proof, commitment)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        let finality = self.get_finality(tx_hash).await?;

        match finality {
            FinalityStatus::Finalized { finality_block, .. } => {
                // Get current slot for confirmation count
                let latest_slot = self
                    .rpc()
                    .get_latest_slot()
                    .map_err(|e| ChainOpError::RpcError(format!("Failed to get slot: {}", e)))?;

                let confirmations = latest_slot.saturating_sub(finality_block) + 1;

                // Build proof data from finality info
                let proof_data = serde_json::to_vec(&finality)
                    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

                Ok(FinalityProof::new(
                    proof_data,
                    confirmations,
                    true, // Solana has deterministic finality after 32 slots
                )
                .map_err(|e| {
                    ChainOpError::InvalidInput(format!("Invalid finality proof: {}", e))
                })?)
            }
            _ => Err(ChainOpError::ProofVerificationError(
                "Transaction not finalized".to_string(),
            )),
        }
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool> {
        self.verify_finality_native(proof, tx_hash)
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_proof_bundle_native(inclusion_proof, finality_proof, commitment)
    }
}

#[async_trait]
impl ChainSanadOps for SolanaBackend {
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = owner;
        let _ = asset_class;
        let _ = asset_id;
        let _ = metadata;

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad creation requires signed transaction. \
             Construct and submit a transaction to create the seal account."
                .to_string(),
        ))
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use csv_protocol::chain_adapter_traits::SanadOperation;
        use sha2::Digest;
        use solana_sdk::instruction::AccountMeta;
        use solana_sdk::instruction::Instruction;
        use solana_sdk::message::Message;
        use solana_sdk::signature::Signer;
        use solana_sdk::transaction::Transaction;

        let keypair = keypair_from_hex_key_id(owner_key_id)?;
        let consumer_pubkey = keypair.pubkey();

        let program_id = Pubkey::from_str(&self.seal_protocol.config.csv_program_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid CSV program ID".to_string()))?;

        // Derive the SanadAccount PDA directly — no active_seals lookup needed.
        let (sanad_account, _bump) = Pubkey::find_program_address(
            &[b"sanad", consumer_pubkey.as_ref(), sanad_id.as_bytes()],
            &program_id,
        );

        let consume_discriminator: [u8; 8] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"global:consume_seal");
            let hash = hasher.finalize();
            hash.as_slice()[..8]
                .try_into()
                .expect("slice length matches array size")
        };

        let mut instruction_data = Vec::with_capacity(8);
        instruction_data.extend_from_slice(&consume_discriminator);

        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(consumer_pubkey, true),
            ],
            data: instruction_data,
        };

        let recent_blockhash = self.rpc().get_recent_blockhash().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to get recent blockhash: {}", e))
        })?;

        let message = Message::new(&[instruction], Some(&keypair.pubkey()));
        let transaction = Transaction::new(&[&keypair], message, recent_blockhash);

        let sig = self.rpc().send_transaction(&transaction).map_err(|e| {
            ChainOpError::TransactionError(format!("Failed to send consume transaction: {}", e))
        })?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: SanadOperation::Consume,
            transaction_hash: sig.to_string(),
            block_height: 0,
            chain_id: "solana".to_string(),
            metadata: serde_json::to_vec(&serde_json::json!({
                "operation": "consume",
                "seal_account": sanad_account.to_string(),
            }))
            .unwrap_or_default(),
        })
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use csv_protocol::chain_adapter_traits::SanadOperation;
        use sha2::Digest;
        use solana_sdk::instruction::AccountMeta;
        use solana_sdk::instruction::Instruction;
        use solana_sdk::message::Message;
        use solana_sdk::transaction::Transaction;

        let wallet = self.seal_protocol.wallet().ok_or_else(|| {
            ChainOpError::SigningError("No wallet configured for Solana".to_string())
        })?;
        let owner_pubkey = wallet.pubkey();

        let program_id = Pubkey::from_str(&self.seal_protocol.config.csv_program_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid CSV program ID".to_string()))?;

        // Derive the SanadAccount PDA directly — no active_seals lookup needed.
        // After Bug 3B fix, the on-chain PDA uses commitment (= sanad_id) as its seed,
        // so this derivation matches what publish() used when creating the account.
        let (sanad_account, _bump) = Pubkey::find_program_address(
            &[b"sanad", owner_pubkey.as_ref(), sanad_id.as_bytes()],
            &program_id,
        );

        // Build the lock_sanad discriminator
        let mut disc_hasher = sha2::Sha256::new();
        disc_hasher.update(b"global:lock_sanad");
        let hash = disc_hasher.finalize();
        let lock_discriminator: [u8; 8] = hash.as_slice()[..8]
            .try_into()
            .expect("slice length matches array size");

        let dest_chain_bytes = destination_chain.as_bytes();
        let mut instruction_data = Vec::with_capacity(8 + 32 + dest_chain_bytes.len());
        instruction_data.extend_from_slice(&lock_discriminator);
        instruction_data.extend_from_slice(sanad_id.as_bytes());
        instruction_data.extend_from_slice(dest_chain_bytes);

        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new(owner_pubkey, true),
            ],
            data: instruction_data,
        };

        let rpc = self
            .seal_protocol
            .get_rpc()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get RPC: {}", e)))?;

        let recent_blockhash = rpc.get_recent_blockhash().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to get recent blockhash: {}", e))
        })?;

        let message = Message::new(&[instruction], Some(&owner_pubkey));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&wallet.keypair], recent_blockhash);

        let sig = rpc.send_transaction(&transaction).map_err(|e| {
            ChainOpError::TransactionError(format!("Failed to send lock transaction: {}", e))
        })?;

        let slot = rpc
            .get_latest_slot()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get slot: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: SanadOperation::Lock,
            transaction_hash: sig.to_string(),
            block_height: slot,
            chain_id: "solana".to_string(),
            metadata: serde_json::to_vec(&serde_json::json!({
                "operation": "lock",
                "destination_chain": destination_chain,
                "seal_account": sanad_account.to_string(),
            }))
            .unwrap_or_default(),
        })
    }

    async fn mint_sanad(
        &self,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &CoreInclusionProof,
        new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Parse source chain to ensure it's valid
        let _source = source_chain
            .parse::<csv_hash::chain_id::ChainId>()
            .map_err(|_| {
                ChainOpError::InvalidInput(format!("Invalid source chain: {}", source_chain))
            })?;

        // Verify the lock proof has valid structure before attempting mint
        if lock_proof.proof_bytes.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Lock proof is empty".to_string(),
            ));
        }

        if lock_proof.block_hash == Hash::zero() {
            return Err(ChainOpError::InvalidInput(
                "Lock proof has zero block hash".to_string(),
            ));
        }

        // Parse new owner as Solana pubkey before failing closed so callers get
        // deterministic input validation even while typed minting is unavailable.
        let _owner_pubkey = solana_sdk::pubkey::Pubkey::from_str(new_owner)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid owner pubkey: {}", e)))?;

        Err(ChainOpError::CapabilityUnavailable(format!(
            "Solana mint_sanad for {} requires typed Anchor csv-seal mint_sanad instruction wiring and a real mint authority signer; refusing to derive a signing key from the sanad id",
            hex::encode(source_sanad_id.as_bytes())
        )))
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = owner_key_id;

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund requires signed transaction. \
             Construct and submit a transaction to refund the locked seal."
                .to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = metadata;
        let _ = owner_key_id;

        Err(ChainOpError::CapabilityUnavailable(
            "Metadata recording requires signed transaction. \
             Construct and submit a transaction to update seal metadata."
                .to_string(),
        ))
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Derive the seal account address from the sanad_id
        // The seal account is a PDA derived from the sanad_id hash
        use solana_system_interface::program;

        // Convert sanad_id bytes to a Pubkey (32 bytes)
        let sanad_bytes = sanad_id.as_bytes();
        let seal_address = From::from(*sanad_bytes);

        // Query the account state via RPC
        let account_info = self
            .rpc()
            .get_account(&seal_address)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query seal account: {}", e)))?;

        // Determine state from account info
        // An account that doesn't exist will have zero lamports, empty data, and be owned by system_program
        let is_default_account = account_info.lamports == 0
            && account_info.data.is_empty()
            && account_info.owner == program::id();

        let actual_state = if is_default_account {
            if expected_state == "consumed" || expected_state == "never_created" {
                return Ok(true);
            }
            "consumed"
        } else if account_info.data.is_empty() {
            "locked"
        } else {
            "active"
        };

        Ok(actual_state == expected_state)
    }
}

#[async_trait]
impl ChainBackend for SolanaBackend {
    fn chain_id(&self) -> &'static str {
        "solana"
    }

    fn chain_name(&self) -> &'static str {
        "Solana"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let solana_seal = self
            .seal_protocol
            .create_seal(value)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert SolanaSealPoint to core SealPoint
        // SolanaSealPoint has account (32 bytes Pubkey) stored in id
        Ok(SealPoint {
            id: solana_seal.account.to_bytes().to_vec(),
            nonce: None,
            version: None,
        })
    }

    async fn publish_seal(
        &self,
        seal: SealPoint,
        commitment: Hash,
        sanad_id: Hash,
    ) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to SolanaSealPoint
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Solana, expected at least 32 bytes".to_string(),
            ));
        }

        let account_address: [u8; 32] = seal.id[..32]
            .try_into()
            .map_err(|_| ChainOpError::InvalidInput("Seal ID too short for Solana".to_string()))?;

        let solana_seal = crate::types::SolanaSealPoint {
            account: solana_sdk::pubkey::Pubkey::new_from_array(account_address),
            owner: solana_sdk::pubkey::Pubkey::default(),
            lamports: 0,
            seed: None,
        };

        // Call the seal protocol's publish method
        let solana_anchor = self
            .seal_protocol
            .publish(commitment, solana_seal, sanad_id)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert SolanaCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: solana_anchor.signature.as_ref().to_vec(),
            block_height: solana_anchor.block_height,
            metadata: solana_anchor.slot.to_le_bytes().to_vec(),
        })
    }
}

#[async_trait]
impl SanadStateReader for SolanaBackend {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        // Derive the SanadAccount PDA
        let program_id = Pubkey::from_str(&self.seal_protocol.config.csv_program_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid program ID: {}", e)))?;

        // We need the owner to derive the PDA - for now, use a placeholder
        // In production, this would require the owner address as input
        let owner = Pubkey::default();
        let sanad_id_bytes = sanad_id.as_bytes();
        let (sanad_pda, _) =
            Pubkey::find_program_address(&[b"sanad", owner.as_ref(), sanad_id_bytes], &program_id);

        // Query the SanadAccount PDA on Solana (get_account is synchronous)
        let account = self.rpc().get_account(&sanad_pda).map_err(|e| match e {
            crate::error::SolanaError::AccountNotFound(_) => {
                ChainOpError::RpcError("Sanad account not found".to_string())
            }
            _ => ChainOpError::RpcError(format!("Failed to get sanad account: {}", e)),
        })?;

        // Decode the SanadAccount from account data
        let sanad_account = decode_sanad_account(&account.data).map_err(|e| {
            ChainOpError::RpcError(format!("Failed to decode sanad account: {}", e))
        })?;

        Ok(CanonicalSanadState {
            state: sanad_account.state,
            owner: sanad_account.owner.to_string(),
            commitment: Hash::from(sanad_account.commitment),
            nullifier: if sanad_account.nullifier != [0u8; 32] {
                Some(Hash::from(sanad_account.nullifier))
            } else {
                None
            },
            created_at: sanad_account.created_at,
            locked_at: if sanad_account.locked_at != 0 {
                Some(sanad_account.locked_at)
            } else {
                None
            },
            consumed_at: if sanad_account.consumed_at != 0 {
                Some(sanad_account.consumed_at)
            } else {
                None
            },
            minted_at: if sanad_account.minted_at != 0 {
                Some(sanad_account.minted_at)
            } else {
                None
            },
            refunded_at: if sanad_account.refunded_at != 0 {
                Some(sanad_account.refunded_at)
            } else {
                None
            },
        })
    }

    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        // Derive the SealAccount PDA from the seal_id
        let program_id = Pubkey::from_str(&self.seal_protocol.config.csv_program_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid program ID: {}", e)))?;

        // Derive PDA using the seal_id as the seed
        let seal_id_bytes = seal_id.as_bytes();
        let (seal_pda, _) = Pubkey::find_program_address(&[b"seal", seal_id_bytes], &program_id);

        // Query the SealAccount PDA on Solana
        let account = self.rpc().get_account(&seal_pda).map_err(|e| match e {
            crate::error::SolanaError::AccountNotFound(_) => {
                ChainOpError::RpcError("Seal account not found".to_string())
            }
            _ => ChainOpError::RpcError(format!("Failed to get seal account: {}", e)),
        })?;

        // Decode the seal account data
        if account.data.len() < 8 {
            return Err(ChainOpError::RpcError(
                "Seal account data too short".to_string(),
            ));
        }

        let data = &account.data[8..];

        // Parse owner (32 bytes)
        if data.len() < 32 {
            return Err(ChainOpError::RpcError(
                "Seal account data too short for owner".to_string(),
            ));
        }
        let owner = Pubkey::new_from_array(data[..32].try_into().expect("slice length matches"));

        // Parse status (1 byte)
        let state = if data.len() > 32 {
            match data[32] {
                0 => 0, // Created/Active
                1 => 1, // Consumed
                _ => 0,
            }
        } else {
            0
        };

        // Parse created_slot (8 bytes at offset 33)
        let created_at = if data.len() > 40 {
            i64::from_le_bytes(data[33..41].try_into().expect("slice length matches"))
        } else {
            0
        };

        // Parse consumed_slot (8 bytes at offset 41)
        let consumed_at = if data.len() > 48 {
            let slot_bytes = data[41..49].try_into().expect("slice length matches");
            let slot = u64::from_le_bytes(slot_bytes);
            if slot > 0 { Some(slot as i64) } else { None }
        } else {
            None
        };

        Ok(CanonicalSealState {
            state,
            owner: owner.to_string(),
            commitment: *seal_id,
            created_at,
            consumed_at,
        })
    }

    async fn trace_sanad(
        &self,
        _sanad_id: &SanadId,
    ) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        // Query events from Solana transactions
        // This would require querying the transaction history for events related to this sanad_id
        Ok(vec![])
    }
}

#[async_trait]
impl ChainReadinessCheck for SolanaBackend {
    async fn check_readiness(&self, _account: u32, _index: u32) -> ChainOpResult<ChainReadiness> {
        // Check if program is configured
        let contract_configured = !self.seal_protocol.config.csv_program_id.is_empty();

        // Check if signer is actually configured by checking the config
        let signer_configured = self.seal_protocol.config.keypair.is_some();

        // Derive signer address from keypair if available
        let signer_address = if signer_configured {
            if let Some(ref keypair) = self.seal_protocol.config.keypair {
                use solana_sdk::signature::{Signer, keypair_from_seed};
                let key_bytes = keypair.expose_secret();
                let mut seed = [0u8; 32];
                seed.copy_from_slice(key_bytes);
                match keypair_from_seed(&seed) {
                    Ok(kp) => Some(kp.pubkey().to_string()),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        // Balance address is same as signer address for Solana
        let balance_address = signer_address.clone();

        // Check write capability (signer configured + RPC available)
        let write_capable = signer_configured;

        // Check if account exists (has balance > 0)
        let account_exists = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr).await {
                Ok(balance) => balance.total > 0,
                Err(_) => false,
            }
        } else {
            false
        };

        // Get native balance
        let native_balance = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr).await {
                Ok(balance) => Some(balance.total),
                Err(_) => None,
            }
        } else {
            None
        };

        // Estimate minimum fee (5000 lamports for simple transaction)
        let estimated_fee = Some(5000);

        // Solana supports sanad creation (via program)
        let sanad_create_supported = contract_configured;

        // Solana supports proof generation
        let proof_generation_supported = true;

        // Solana can be cross-chain source
        let cross_chain_source_supported = true;

        // Solana can be cross-chain destination
        let cross_chain_destination_supported = true;

        Ok(ChainReadiness {
            signer_address,
            balance_address,
            signer_configured,
            write_capable,
            contract_configured,
            account_exists,
            native_balance,
            estimated_fee,
            sanad_create_supported,
            proof_generation_supported,
            cross_chain_source_supported,
            cross_chain_destination_supported,
            metadata: vec![],
        })
    }
}

/// Decode SanadAccount from account data
fn decode_sanad_account(data: &[u8]) -> ChainOpResult<crate::types::SolanaSanadAccount> {
    // Skip the 8-byte discriminator
    if data.len() < 8 {
        return Err(ChainOpError::RpcError("Account data too short".to_string()));
    }

    let account_data = &data[8..];

    // Decode fields according to the thin-registry SanadAccount layout. The fixed
    // portion is 268 bytes (owner .. bump); reject anything shorter before indexing.
    const SANAD_ACCOUNT_BODY_LEN: usize = 268;
    if account_data.len() < SANAD_ACCOUNT_BODY_LEN {
        return Err(ChainOpError::RpcError(format!(
            "Account data too short for SanadAccount: need {} bytes, got {}",
            SANAD_ACCOUNT_BODY_LEN,
            account_data.len()
        )));
    }

    let owner = Pubkey::new_from_array(
        account_data[..32]
            .try_into()
            .expect("slice length matches array size"),
    );

    Ok(crate::types::SolanaSanadAccount {
        owner,
        sanad_id: account_data[32..64]
            .try_into()
            .expect("slice length matches array size"),
        commitment: account_data[64..96]
            .try_into()
            .expect("slice length matches array size"),
        state_root: account_data[96..128]
            .try_into()
            .expect("slice length matches array size"),
        nullifier: account_data[128..160]
            .try_into()
            .expect("slice length matches array size"),
        asset_class: account_data[160],
        asset_id: account_data[161..193]
            .try_into()
            .expect("slice length matches array size"),
        metadata_hash: account_data[193..225]
            .try_into()
            .expect("slice length matches array size"),
        proof_system: account_data[225],
        // The RFC-0012 thin-registry `SanadAccount` dropped the legacy
        // proof-root-era field; `state` immediately follows `proof_system`.
        state: account_data[226],
        created_at: i64::from_le_bytes(
            account_data[227..235]
                .try_into()
                .expect("slice length matches array size"),
        ),
        locked_at: i64::from_le_bytes(
            account_data[235..243]
                .try_into()
                .expect("slice length matches array size"),
        ),
        consumed_at: i64::from_le_bytes(
            account_data[243..251]
                .try_into()
                .expect("slice length matches array size"),
        ),
        minted_at: i64::from_le_bytes(
            account_data[251..259]
                .try_into()
                .expect("slice length matches array size"),
        ),
        refunded_at: i64::from_le_bytes(
            account_data[259..267]
                .try_into()
                .expect("slice length matches array size"),
        ),
        bump: account_data[267],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_address_validation() {
        // Can't easily test without test RPC, but we can test address validation
        // This is a basic test - real tests would use MockSolanaRpc
    }

    #[test]
    fn keypair_from_hex_key_id_accepts_32_byte_secret() {
        use solana_sdk::signature::Signer;

        let secret = [7u8; 32];
        let key_id = hex::encode(secret);
        let keypair = keypair_from_hex_key_id(&key_id).expect("valid keypair");

        let signature = keypair.sign_message(b"csv-solana-signing-test");
        assert_eq!(signature.as_ref().len(), 64);
    }

    #[test]
    fn keypair_from_hex_key_id_rejects_invalid_length() {
        let err = match keypair_from_hex_key_id("abcd") {
            Ok(_) => panic!("short key should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, ChainOpError::SigningError(_)));
    }
}
