//! Runtime adapter wrapper for Solana chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Solana-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintAttestationInputs, MintResult,
    RuntimeMintRequest, SealRegistryStatus, TxFinality,
};
use csv_protocol::chain_adapter_traits::ChainBackend;
use csv_protocol::finality::capabilities::{
    ChainCapabilities, ChainRole, FinalityModel, ProofModel, ReorgRisk, ReplayProtectionModel,
    StateModel,
};
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use std::sync::Arc;

use crate::ops::SolanaBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExistingMintRecord {
    sanad_id: [u8; 32],
    commitment: [u8; 32],
    source_chain: [u8; 32],
    destination_owner_hash: [u8; 32],
    lock_event_id: [u8; 32],
    nullifier: [u8; 32],
}

impl ExistingMintRecord {
    const SIZE: usize = 8 + (6 * 32) + 8 + 1;
    const HASH_FIELD_START: usize = 8;
    const HASH_FIELD_END: usize = Self::HASH_FIELD_START + (6 * 32);

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE || data[..8] != anchor_account_discriminator("MintRecord") {
            return None;
        }

        let fields = &data[Self::HASH_FIELD_START..Self::HASH_FIELD_END];
        Some(Self {
            sanad_id: fields[0..32].try_into().ok()?,
            commitment: fields[32..64].try_into().ok()?,
            source_chain: fields[64..96].try_into().ok()?,
            destination_owner_hash: fields[96..128].try_into().ok()?,
            lock_event_id: fields[128..160].try_into().ok()?,
            nullifier: fields[160..192].try_into().ok()?,
        })
    }

    fn matches_attestation(&self, attestation: &MintAttestationInputs) -> bool {
        self.sanad_id == attestation.sanad_id
            && self.commitment == attestation.commitment
            && self.source_chain == attestation.source_chain
            && self.destination_owner_hash == destination_owner_hash(&attestation.destination_owner)
            && self.lock_event_id == attestation.lock_event_id
            && self.nullifier == attestation.nullifier
    }
}

fn anchor_account_discriminator(account_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(format!("account:{account_name}").as_bytes());
    let hash = hasher.finalize();
    hash[..8]
        .try_into()
        .expect("SHA256 digest is at least 8 bytes")
}

fn destination_owner_hash(owner: &[u8]) -> [u8; 32] {
    solana_program::keccak::hashv(&[owner]).to_bytes()
}

fn existing_mint_tx_ref(mint_record: &Pubkey) -> String {
    hex::encode(mint_record.to_bytes())
}

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

    fn idempotent_existing_mint(
        &self,
        mint_record: &Pubkey,
        attestation: &MintAttestationInputs,
    ) -> Result<Option<MintResult>, AdapterError> {
        let account = match self.backend.rpc().get_account(mint_record) {
            Ok(account) => account,
            Err(_) => return Ok(None),
        };

        let record = ExistingMintRecord::decode(&account.data).ok_or_else(|| {
            AdapterError::Generic(format!(
                "Mint record PDA {} exists but does not decode as a CSV MintRecord",
                mint_record
            ))
        })?;

        if !record.matches_attestation(attestation) {
            return Err(AdapterError::Generic(format!(
                "Mint record PDA {} already exists for different mint inputs",
                mint_record
            )));
        }

        let block_height = self
            .backend
            .rpc()
            .get_latest_slot()
            .map_err(|e| AdapterError::Generic(format!("Failed to get slot: {}", e)))?;

        Ok(Some(MintResult {
            tx_hash: existing_mint_tx_ref(mint_record),
            block_height,
            materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                self.chain_id.clone(),
            ),
        }))
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

    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        let result = self
            .backend
            .lock_sanad(
                &sanad_id,
                destination_chain,
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        // The runtime records lock tx hashes as hex; a base58 Solana signature
        // would be corrupted by the coordinator's hex round-trip.
        let tx_hash = result
            .transaction_hash
            .parse::<solana_sdk::signature::Signature>()
            .map(|sig| hex::encode(sig.as_ref() as &[u8]))
            .unwrap_or(result.transaction_hash);

        Ok(LockResult {
            tx_hash,
            block_height: result.block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // `proof_bundle` is the runtime's canonical-CBOR `RuntimeMintRequest`
        // (RFC-0012 §3/§9): the §9.2 attestation inputs the runtime bound after its
        // off-chain canonical verifier already adjudicated the source proof
        // (`validate_source_proof` on the *source* adapter, journaled by the
        // coordinator before this call). This adapter is the thin-registry
        // submitter: it binds `destination_contract = program id` and
        // `destination_chain_id = keccak256("csv.chain.solana")` exactly as the
        // on-chain `mint_attestation_digest` derives them, computes the frozen §9.2
        // digest, signs it with the secp256k1 verifier key, and submits the
        // redesigned `mint_sanad` instruction. There is no proof root and no Merkle
        // proof anywhere on this path; Solana's weak native single-use is backstopped
        // by the three replay-tombstone PDAs the instruction creates.
        use solana_sdk::transaction::Transaction;

        let request: RuntimeMintRequest =
            csv_codec::from_canonical_cbor(proof_bundle).map_err(|e| {
                AdapterError::Generic(format!("Failed to decode runtime mint request: {}", e))
            })?;

        // Bind the request to this transfer: a payload whose attestation is for a
        // different Sanad must never be signed or submitted here.
        if request.attestation.sanad_id != *transfer.sanad_id.as_bytes() {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Mint request Sanad {} does not match transfer Sanad {}",
                hex::encode(request.attestation.sanad_id),
                hex::encode(transfer.sanad_id.as_bytes())
            )));
        }

        // Bind `destination_contract` to this program id and force
        // `destination_chain_id` to the frozen Solana chain tag, exactly as the
        // program recomputes them, so the signed digest matches the value
        // `mint_attestation_digest` reproduces on-chain.
        let program_id_bytes = self
            .backend
            .program_id()
            .map_err(|e| AdapterError::Generic(format!("No mint program configured: {}", e)))?;
        let program_id = Pubkey::from(program_id_bytes);
        let mut attestation = request.attestation.clone();
        attestation.destination_contract = program_id_bytes;
        attestation.destination_chain_id = solana_contract_chain_id();

        // The recipient must be present. The program hashes `keccak256(destination_owner)`
        // into the digest and rejects an empty owner; the runtime leaves it empty
        // until owner-binding supplies a recipient, so fail closed here before signing.
        if attestation.destination_owner.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "Mint request has no destination owner: cannot materialize a sanad without a \
                 recipient"
                    .to_string(),
            ));
        }

        let (mint_record, _) =
            crate::anchor_client::pdas::mint_record(&program_id, &attestation.sanad_id);
        if let Some(result) = self.idempotent_existing_mint(&mint_record, &attestation)? {
            return Ok(result);
        }

        // Compute the frozen §9.2 digest and attest it with the configured verifier
        // key. Fails closed (no signer -> no signature) rather than emitting an
        // unauthenticated mint the program would reject.
        let digest = attestation.attestation_digest();
        let signatures = self
            .backend
            .sign_mint_attestation_digests(&digest)
            .map_err(|e| {
                AdapterError::Generic(format!("Failed to sign §9.2 mint attestation: {}", e))
            })?;
        let mut verifier_signatures = request.verifier_signatures.clone();
        verifier_signatures.extend(signatures);

        let args = crate::mint::build_solana_mint_args(&attestation, &verifier_signatures);

        // The wallet is the fee payer / transaction signer only — it holds NO mint
        // authority (authority is the verifier signatures carried in the args).
        let wallet = self
            .backend
            .seal_protocol()
            .wallet
            .as_ref()
            .ok_or_else(|| {
                AdapterError::Generic("Wallet not configured for mint operation".to_string())
            })?;

        let instruction = crate::mint::build_mint_instruction(&program_id, &wallet.pubkey(), &args);

        // Get recent blockhash from backend RPC
        let recent_blockhash =
            self.backend.rpc().get_recent_blockhash().map_err(|e| {
                AdapterError::Generic(format!("Failed to get recent blockhash: {}", e))
            })?;

        // Build and sign the transaction
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&wallet.pubkey()),
            &[&wallet.keypair],
            recent_blockhash,
        );

        // Send the transaction (fails closed if the program rejects an
        // unauthenticated or duplicate mint at simulation/preflight).
        let signature = match self.backend.rpc().send_transaction(&transaction) {
            Ok(signature) => signature,
            Err(e) => {
                if format!("{}", e).contains("already in use")
                    && let Some(result) =
                        self.idempotent_existing_mint(&mint_record, &attestation)?
                {
                    return Ok(result);
                }
                return Err(AdapterError::Generic(format!(
                    "Failed to send transaction: {}",
                    e
                )));
            }
        };

        // `send_transaction` only reports that the RPC node accepted the
        // transaction for broadcast.  The runtime persists the mint-record PDA
        // as the destination reference and immediately asks `confirm_tx` to
        // read that account.  Do not expose the PDA until the transaction has
        // actually landed, otherwise a normal RPC propagation delay is reported
        // as a misleading `AccountNotFound` mint failure.
        self.backend
            .rpc()
            .wait_for_confirmation(&signature)
            .map_err(|e| {
                AdapterError::RpcError(format!(
                    "Failed to confirm Solana mint transaction {}: {}",
                    signature, e
                ))
            })?;

        // Get the block height - use slot as proxy since get_block_height not available in SolanaRpc
        let block_height = self
            .backend
            .rpc()
            .get_latest_slot()
            .map_err(|e| AdapterError::Generic(format!("Failed to get slot: {}", e)))?;

        Ok(MintResult {
            tx_hash: existing_mint_tx_ref(&mint_record),
            block_height,
            materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                self.chain_id.clone(),
            ),
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        use crate::types::ConfirmationStatus;
        use csv_hash::seal::{CommitAnchor, SealPoint};
        use csv_protocol::proof_taxonomy::InclusionProof;
        use std::str::FromStr;

        // Parse the lock signature (hex of the 64-byte signature, or base58).
        let signature = parse_tx_signature(&lock_result.tx_hash)?;

        // Fetch the on-chain LockAccount PDA ["lock", sanad_id]: the canonical
        // lock record this proof vouches for.
        let program_id = solana_sdk::pubkey::Pubkey::from_str(
            &self.backend.seal_protocol().config().csv_program_id,
        )
        .map_err(|_| AdapterError::Generic("Invalid CSV program ID".to_string()))?;
        let sanad_bytes = transfer.sanad_id.as_bytes();
        let (lock_account, _) =
            solana_sdk::pubkey::Pubkey::find_program_address(&[b"lock", sanad_bytes], &program_id);
        let lock_data = self
            .backend
            .rpc()
            .get_account(&lock_account)
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!(
                    "Lock record PDA {} not found on-chain: {}",
                    lock_account, e
                ))
            })?
            .data;

        // The LockAccount layout is [8-byte discriminator][LockRecord], and
        // LockRecord starts with the 32-byte sanad_id — verify the record
        // binds this exact sanad before vouching for it.
        if lock_data.len() < 40 || &lock_data[8..40] != sanad_bytes {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "On-chain lock record {} does not bind sanad 0x{}",
                lock_account,
                hex::encode(sanad_bytes)
            )));
        }

        // Look up the landed slot with history before using the short-lived
        // confirmation poll. A resumed transfer commonly falls outside
        // Solana's recent signature-status cache, while get_transaction_slot
        // searches history and also rejects failed transactions.
        let lock_slot = match self
            .backend
            .rpc()
            .get_transaction_slot(&signature)
            .map_err(|e| AdapterError::Generic(format!("Failed to get lock tx slot: {}", e)))?
        {
            Some(slot) => slot,
            None => {
                let status = self
                    .backend
                    .rpc()
                    .wait_for_confirmation(&signature)
                    .map_err(|e| {
                        AdapterError::ProofVerificationFailed(format!(
                            "Lock tx {} not confirmed: {}",
                            signature, e
                        ))
                    })?;
                if matches!(status, ConfirmationStatus::Processed) {
                    return Err(AdapterError::ProofVerificationFailed(format!(
                        "Lock tx {} is processed but not yet confirmed",
                        signature
                    )));
                }
                self.backend
                    .rpc()
                    .get_transaction_slot(&signature)
                    .map_err(|e| {
                        AdapterError::Generic(format!("Failed to get lock tx slot: {}", e))
                    })?
                    .ok_or_else(|| {
                        AdapterError::ProofVerificationFailed(format!(
                            "Lock tx {} was confirmed but has no landed slot",
                            signature
                        ))
                    })?
            }
        };

        // Real finality evidence: confirmation depth of the lock slot below
        // the current tip.
        let latest_slot = self
            .backend
            .rpc()
            .get_latest_slot()
            .map_err(|e| AdapterError::Generic(format!("Failed to get latest slot: {}", e)))?;
        // Deterministic encoding of the actual on-chain evidence: lock
        // signature, lock slot, and the raw lock record account data.
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(signature.as_ref());
        proof_bytes.extend_from_slice(&lock_slot.to_le_bytes());
        proof_bytes.extend_from_slice(&lock_data);

        let sig_bytes: &[u8] = signature.as_ref();
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&sig_bytes[..32]);

        let inclusion_proof = InclusionProof::new(
            proof_bytes.clone(),
            csv_hash::Hash::new(block_hash),
            lock_slot,
            0,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid inclusion proof: {}", e)))?;

        // Keep the finality evidence in the same structured format consumed by
        // the native verifier.  A bare slot was accepted by an earlier builder
        // but is malformed (the verifier requires slot, tip, confirmation
        // count, finality flag, and block hash).
        let finality_proof = crate::proofs::build_finality_proof(
            lock_slot,
            csv_hash::Hash::new(block_hash),
            latest_slot,
        );

        // Anchor bound to the Sanad ID; the verifier's binding rule requires
        // anchor metadata == inclusion proof bytes.
        let commit_anchor = CommitAnchor::new(
            transfer.sanad_id.as_bytes().to_vec(),
            lock_slot,
            proof_bytes,
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        // The seal reference is the sanad account PDA this lock consumed.
        let wallet = self
            .backend
            .seal_protocol()
            .wallet()
            .ok_or_else(|| AdapterError::Generic("No Solana wallet configured".to_string()))?;
        let owner_pubkey = wallet.pubkey();
        let (sanad_account, _) = solana_sdk::pubkey::Pubkey::find_program_address(
            &[b"sanad", owner_pubkey.as_ref(), sanad_bytes],
            &program_id,
        );
        let seal_point = SealPoint::new(sanad_account.to_bytes().to_vec(), Some(0), None)
            .map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;

        // Real authorizing signature over the DAG root commitment by the same
        // Ed25519 wallet key that signed the lock transaction. Format:
        // [pk_len: u32 LE][public_key][signature].
        let root_commitment = *transfer.sanad_id.as_bytes();
        let auth_sig = wallet.keypair.sign_message(&root_commitment);
        let pubkey_bytes = owner_pubkey.to_bytes();
        let mut encoded_signature = Vec::with_capacity(4 + 32 + 64);
        encoded_signature.extend_from_slice(&(pubkey_bytes.len() as u32).to_le_bytes());
        encoded_signature.extend_from_slice(&pubkey_bytes);
        encoded_signature.extend_from_slice(auth_sig.as_ref());

        let dag_node = csv_hash::dag::DAGNode::new(
            csv_hash::Hash::new(root_commitment),
            lock_data,
            vec![encoded_signature.clone()],
            vec![sig_bytes.to_vec()],
            vec![],
        );
        let transition_dag =
            csv_hash::dag::DAGSegment::new(vec![dag_node], csv_hash::Hash::new(root_commitment));

        ProofBundle::with_signature_scheme(
            csv_protocol::signature::SignatureScheme::Ed25519,
            transition_dag,
            vec![encoded_signature],
            seal_point,
            commit_anchor,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to build proof bundle: {}", e)))
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

        let is_valid = self
            .backend
            .verify_proof_bundle(inclusion_proof, finality_proof, commitment)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to verify proof bundle: {}", e)))?;

        if !is_valid {
            return Err(AdapterError::Generic(
                "Proof bundle validation failed".to_string(),
            ));
        }

        Ok(())
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;

        // Solana uses PDA accounts as seals - check if the seal account exists on-chain
        // Parse the seal_id as a Pubkey (32 bytes)
        if seal_id.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid seal_id length: expected 32, got {}",
                seal_id.len()
            )));
        }

        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(seal_id);
        let seal_pubkey = Pubkey::new_from_array(pubkey_bytes);

        // Query the account via RPC
        let account =
            self.backend.rpc().get_account(&seal_pubkey).map_err(|e| {
                AdapterError::Generic(format!("Failed to query seal account: {}", e))
            })?;

        // Check if account exists and has lamports (unspent)
        if account.lamports == 0 {
            return Ok(SealRegistryStatus::Consumed);
        }

        // Check if the account is owned by the CSV program
        let program_id = Pubkey::from_str(&self.backend.seal_protocol().config.csv_program_id)
            .map_err(|e| AdapterError::Generic(format!("Invalid program ID: {}", e)))?;

        if account.owner != program_id {
            return Err(AdapterError::Generic(
                "Seal account not owned by CSV program".to_string(),
            ));
        }

        Ok(SealRegistryStatus::Available)
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainQuery;

        // Get balance using the backend's ChainQuery implementation
        let balance_info = self
            .backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to get balance: {}", e)))?;

        Ok(balance_info.total.to_string())
    }

    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        use crate::types::ConfirmationStatus;

        if tx_hash.len() == 64
            && tx_hash.chars().all(|c| c.is_ascii_hexdigit())
            && let Ok(bytes) = hex::decode(tx_hash)
            && let Ok(pubkey_bytes) = <[u8; 32]>::try_from(bytes.as_slice())
        {
            let mint_record = Pubkey::new_from_array(pubkey_bytes);
            let account = self.backend.rpc().get_account(&mint_record).map_err(|e| {
                AdapterError::RpcError(format!(
                    "Failed to confirm Solana mint record {}: {}",
                    mint_record, e
                ))
            })?;
            ExistingMintRecord::decode(&account.data).ok_or_else(|| {
                AdapterError::Generic(format!(
                    "Solana mint record {} does not decode as a CSV MintRecord",
                    mint_record
                ))
            })?;
            let block_height = self.backend.rpc().get_latest_slot().map_err(|e| {
                AdapterError::RpcError(format!("Failed to get Solana latest slot: {}", e))
            })?;
            return Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    self.chain_id.clone(),
                ),
            });
        }

        // The runtime records lock tx references as hex of the 64-byte
        // signature (128 hex chars); accept that alongside base58.
        let signature = parse_tx_signature(tx_hash)?;

        // Historical status lookup is the durable resume path. It searches
        // beyond the recent-status cache and checks transaction failure.
        if let Some(block_height) = self
            .backend
            .rpc()
            .get_transaction_slot(&signature)
            .map_err(|e| {
                AdapterError::RpcError(format!(
                    "Failed to get slot for Solana transaction {}: {}",
                    tx_hash, e
                ))
            })?
        {
            return Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    self.chain_id.clone(),
                ),
            });
        }

        let status = self
            .backend
            .rpc()
            .wait_for_confirmation(&signature)
            .map_err(|e| {
                AdapterError::RpcError(format!(
                    "Failed to confirm Solana transaction {}: {}",
                    tx_hash, e
                ))
            })?;

        match status {
            ConfirmationStatus::Confirmed | ConfirmationStatus::Finalized => {
                // Report the slot the transaction landed in, not the current
                // tip: resume paths reuse this as the lock slot when
                // rebuilding proofs.
                let block_height = self
                    .backend
                    .rpc()
                    .get_transaction_slot(&signature)
                    .map_err(|e| {
                        AdapterError::RpcError(format!(
                            "Failed to get slot for Solana transaction {}: {}",
                            tx_hash, e
                        ))
                    })?
                    .ok_or_else(|| {
                        AdapterError::Generic(format!(
                            "Solana transaction {} confirmed but has no signature status",
                            tx_hash
                        ))
                    })?;
                Ok(MintResult {
                    tx_hash: tx_hash.to_string(),
                    block_height,
                    materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                        self.chain_id.clone(),
                    ),
                })
            }
            ConfirmationStatus::Processed => Err(AdapterError::Generic(format!(
                "Solana transaction {} is processed but not yet confirmed",
                tx_hash
            ))),
        }
    }

    async fn tx_finality(&self, tx_hash: &str) -> Result<TxFinality, AdapterError> {
        // Real confirmation depth for the runtime finality gate. The trait
        // default delegates to `confirm_tx` and reports `u64::MAX`
        // confirmations, which made the per-chain finality depth a no-op for
        // Solana: a lock was treated as final at `Confirmed` commitment.
        let signature = parse_tx_signature(tx_hash)?;

        let landed_slot = self
            .backend
            .rpc()
            .get_transaction_slot(&signature)
            .map_err(|e| {
                AdapterError::RpcError(format!(
                    "Failed to get slot for Solana transaction {}: {}",
                    tx_hash, e
                ))
            })?;
        // Not yet visible to the cluster: zero confirmations, let the runtime
        // gate report Pending rather than erroring right after broadcast.
        let Some(landed_slot) = landed_slot else {
            return Ok(TxFinality {
                block_height: 0,
                confirmations: 0,
            });
        };

        let latest_slot = self.backend.rpc().get_latest_slot().map_err(|e| {
            AdapterError::RpcError(format!("Failed to get Solana latest slot: {}", e))
        })?;

        Ok(TxFinality {
            block_height: landed_slot,
            confirmations: latest_slot.saturating_sub(landed_slot),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Parse a Solana transaction reference: the runtime records tx references as
/// hex of the 64-byte signature (128 hex chars); base58 is accepted alongside
/// for direct callers.
fn parse_tx_signature(tx_hash: &str) -> Result<solana_sdk::signature::Signature, AdapterError> {
    use solana_sdk::signature::Signature;

    if tx_hash.len() == 128 && tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid tx signature hex: {}", e)))?;
        let sig: [u8; 64] = bytes
            .try_into()
            .map_err(|_| AdapterError::Generic("Invalid tx signature length".to_string()))?;
        Ok(Signature::from(sig))
    } else {
        tx_hash.parse::<Signature>().map_err(|e| {
            AdapterError::Generic(format!("Invalid Solana transaction signature: {}", e))
        })
    }
}

/// Contract-layer Solana chain identity: `keccak256("csv.chain.solana")`.
///
/// The `csv_seal` program hardcodes this tag (`keccak256(CHAIN_NAME_SOLANA)`) as
/// `destinationChainId` in the §9.2 preimage regardless of cluster, so the adapter
/// forces the same value rather than trusting the runtime-supplied destination
/// chain name.
fn solana_contract_chain_id() -> [u8; 32] {
    use csv_protocol::cross_chain::CrossChainHashAlgorithm;
    *CrossChainHashAlgorithm::Keccak256
        .hash_bytes(b"csv.chain.solana")
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Network, SolanaConfig};
    use crate::ops::SolanaBackend;
    use crate::rpc::MockSolanaRpc;
    use crate::seal_protocol::SolanaSealProtocol;
    use csv_adapter_core::MintAttestationInputs;
    use csv_hash::Hash;
    use std::str::FromStr;

    /// Deterministic non-default program id so the digest binding is exercised.
    const PROGRAM_ID: &str = "CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj";

    fn test_backend(verifier: Option<secp256k1::SecretKey>) -> Arc<SolanaBackend> {
        test_backend_with_rpc(verifier, MockSolanaRpc::new())
    }

    fn test_backend_with_rpc(
        verifier: Option<secp256k1::SecretKey>,
        rpc: MockSolanaRpc,
    ) -> Arc<SolanaBackend> {
        let config = SolanaConfig {
            network: Network::Devnet,
            csv_program_id: PROGRAM_ID.to_string(),
            keypair: Some(csv_keys::memory::SecretKey::new([7u8; 32])),
            ..Default::default()
        };
        let seal = SolanaSealProtocol::from_config(config, Box::new(rpc)).expect("seal protocol");
        let mut backend =
            SolanaBackend::from_seal_protocol(Arc::new(seal)).expect("backend from seal protocol");
        if let Some(v) = verifier {
            backend = backend.with_verifier_key(v);
        }
        Arc::new(backend)
    }

    fn test_transfer(sanad_id: Hash) -> CrossChainTransfer {
        CrossChainTransfer {
            id: "solana-transfer-1".to_string(),
            source_chain: "ethereum".to_string(),
            destination_chain: "solana".to_string(),
            lock_tx_hash: vec![0xAAu8; 32],
            lock_output_index: 0,
            sanad_id,
            transition_id: vec![1u8; 32],
        }
    }

    fn mint_attestation(sanad_id: Hash) -> MintAttestationInputs {
        MintAttestationInputs {
            destination_chain_id: [0u8; 32],
            destination_contract: [0u8; 32],
            sanad_id: *sanad_id.as_bytes(),
            commitment: [8u8; 32],
            source_chain: [9u8; 32],
            destination_owner: vec![0x11u8; 32],
            lock_event_id: [0xAu8; 32],
            nullifier: [0xBu8; 32],
            attestation_expiry: 0,
        }
    }

    fn runtime_mint_request_cbor(sanad_id: Hash) -> Vec<u8> {
        let request = RuntimeMintRequest {
            attestation: mint_attestation(sanad_id),
            verifier_signatures: vec![],
            proof_bundle: vec![],
        };
        csv_codec::to_canonical_cbor(&request).expect("encode runtime mint request")
    }

    fn mint_record_account(attestation: &MintAttestationInputs) -> solana_sdk::account::Account {
        let mut data = Vec::with_capacity(ExistingMintRecord::SIZE);
        data.extend_from_slice(&anchor_account_discriminator("MintRecord"));
        data.extend_from_slice(&attestation.sanad_id);
        data.extend_from_slice(&attestation.commitment);
        data.extend_from_slice(&attestation.source_chain);
        data.extend_from_slice(&destination_owner_hash(&attestation.destination_owner));
        data.extend_from_slice(&attestation.lock_event_id);
        data.extend_from_slice(&attestation.nullifier);
        data.extend_from_slice(&123_i64.to_le_bytes());
        data.push(255);

        solana_sdk::account::Account {
            lamports: 1_000_000,
            data,
            owner: Pubkey::from_str(PROGRAM_ID).expect("valid program id"),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[tokio::test]
    async fn mint_sanad_rejects_request_bound_to_other_sanad() {
        // A payload whose attestation is for a different Sanad must be rejected
        // before any signing or submission.
        let adapter = SolanaRuntimeAdapter::new(test_backend(None));
        let transfer = test_transfer(Hash::new([2u8; 32]));
        let payload = runtime_mint_request_cbor(Hash::new([9u8; 32]));

        let result = adapter.mint_sanad(&transfer, &payload).await;
        assert!(
            result.is_err(),
            "must reject a mint request bound to a different sanad"
        );
    }

    #[tokio::test]
    async fn mint_sanad_rejects_undecodable_payload() {
        let adapter = SolanaRuntimeAdapter::new(test_backend(None));
        let transfer = test_transfer(Hash::new([2u8; 32]));

        let result = adapter.mint_sanad(&transfer, b"not-a-mint-request").await;
        assert!(
            result.is_err(),
            "must reject a payload that is not a canonical RuntimeMintRequest"
        );
    }

    #[tokio::test]
    async fn confirm_tx_returns_landed_slot_not_tip() {
        let adapter = SolanaRuntimeAdapter::new(test_backend(None));
        let signature = solana_sdk::signature::Signature::new_unique().to_string();

        let result = adapter.confirm_tx(&signature).await.expect("confirm tx");

        assert_eq!(result.tx_hash, signature);
        // The mock reports landed slot 968 and tip 1000: the confirmed slot
        // must be the slot the tx landed in, not the current tip, or resumed
        // transfers rebuild proofs against a fabricated lock slot.
        assert_eq!(result.block_height, 968);
    }

    #[tokio::test]
    async fn tx_finality_reports_landed_slot_and_real_confirmations() {
        let adapter = SolanaRuntimeAdapter::new(test_backend(None));
        let signature = solana_sdk::signature::Signature::new_unique();

        // Both the base58 form and the runtime's 128-hex-char form must resolve.
        for tx_ref in [
            signature.to_string(),
            hex::encode(signature.as_ref() as &[u8]),
        ] {
            let finality = adapter.tx_finality(&tx_ref).await.expect("tx finality");
            assert_eq!(finality.block_height, 968);
            assert_eq!(finality.confirmations, 1000 - 968);
        }
    }

    #[tokio::test]
    async fn mint_sanad_existing_matching_record_is_idempotent_success() {
        let sanad = Hash::new([2u8; 32]);
        let mut attestation = mint_attestation(sanad);
        attestation.destination_contract = Pubkey::from_str(PROGRAM_ID)
            .expect("valid program id")
            .to_bytes();
        attestation.destination_chain_id = solana_contract_chain_id();
        let (mint_record, _) = crate::anchor_client::pdas::mint_record(
            &Pubkey::from_str(PROGRAM_ID).unwrap(),
            &attestation.sanad_id,
        );

        let mut rpc = MockSolanaRpc::new();
        rpc.add_account(mint_record, mint_record_account(&attestation));

        let adapter = SolanaRuntimeAdapter::new(test_backend_with_rpc(None, rpc));
        let transfer = test_transfer(sanad);
        let payload = runtime_mint_request_cbor(sanad);

        let result = adapter
            .mint_sanad(&transfer, &payload)
            .await
            .expect("matching existing mint record should be idempotent success");

        assert_eq!(result.tx_hash, existing_mint_tx_ref(&mint_record));
        assert_eq!(result.block_height, 1000);
    }

    #[tokio::test]
    async fn mint_sanad_returns_stable_hex_mint_record_ref_after_submission() {
        let secp = secp256k1::Secp256k1::new();
        let (secret, _pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let adapter = SolanaRuntimeAdapter::new(test_backend(Some(secret)));
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);
        let payload = runtime_mint_request_cbor(sanad);
        let (mint_record, _) = crate::anchor_client::pdas::mint_record(
            &Pubkey::from_str(PROGRAM_ID).unwrap(),
            sanad.as_bytes(),
        );

        let result = adapter
            .mint_sanad(&transfer, &payload)
            .await
            .expect("mint submission should return a runtime-compatible tx ref");

        assert_eq!(result.tx_hash, existing_mint_tx_ref(&mint_record));
        assert_eq!(result.tx_hash.len(), 64);
        assert!(result.tx_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn mint_sanad_fails_closed_without_verifier_key() {
        // No secp256k1 verifier key: the adapter cannot attest the §9.2 digest and
        // must fail closed rather than submit an unauthenticated mint.
        let adapter = SolanaRuntimeAdapter::new(test_backend(None));
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);
        let payload = runtime_mint_request_cbor(sanad);

        let result = adapter.mint_sanad(&transfer, &payload).await;
        let err = result.expect_err("must fail closed without a verifier signer");
        assert!(
            format!("{}", err).contains("verifier"),
            "error should point at the missing verifier signer: {}",
            err
        );
    }

    #[tokio::test]
    async fn mint_sanad_rejects_missing_destination_owner() {
        // The runtime leaves `destination_owner` empty until owner-binding wires a
        // recipient; the program hashes and requires it, so an empty owner must fail
        // closed before signing.
        let secp = secp256k1::Secp256k1::new();
        let (secret, _pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let adapter = SolanaRuntimeAdapter::new(test_backend(Some(secret)));
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);

        let mut attestation = mint_attestation(sanad);
        attestation.destination_owner = Vec::new(); // un-bound owner
        let request = RuntimeMintRequest {
            attestation,
            verifier_signatures: vec![],
            proof_bundle: vec![],
        };
        let payload = csv_codec::to_canonical_cbor(&request).unwrap();

        let result = adapter.mint_sanad(&transfer, &payload).await;
        let err = result.expect_err("must reject a mint with an unspecified destination owner");
        assert!(
            format!("{}", err).contains("destination owner"),
            "error should point at the missing destination owner: {}",
            err
        );
    }

    #[test]
    fn verifier_signature_recovers_to_configured_key_over_digest() {
        // The §9.2 signature the adapter attaches must recover — over the digest,
        // exactly as Solana's `secp256k1_recover` does — to the configured verifier
        // public key. This pins the signature format (raw recovery id, no EVM +27)
        // and the destination_contract / destination_chain_id binding.
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let (secret, expected_pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = test_backend(Some(secret));

        let mut attestation = mint_attestation(Hash::new([2u8; 32]));
        attestation.destination_contract = backend.program_id().unwrap();
        attestation.destination_chain_id = solana_contract_chain_id();
        let digest = attestation.attestation_digest();

        let sig = backend
            .sign_mint_attestation_digest(&digest)
            .expect("verifier key configured");
        assert_eq!(sig.len(), 65, "recoverable signature is r || s || v");
        assert!(sig[64] <= 1, "recovery id must be raw 0/1, not EVM +27");

        let recovery_id = RecoveryId::from_i32(sig[64] as i32).expect("valid recovery id");
        let recoverable =
            RecoverableSignature::from_compact(&sig[..64], recovery_id).expect("valid signature");
        let msg = Message::from_digest(digest);
        let recovered = secp
            .recover_ecdsa(&msg, &recoverable)
            .expect("recover verifier pubkey");
        assert_eq!(
            recovered, expected_pubkey,
            "signature must recover to the configured verifier key"
        );
    }
}
