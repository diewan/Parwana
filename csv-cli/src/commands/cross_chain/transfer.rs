//! Cross-chain transfer command implementation (Phase 5 Compliant)
//!
//! Uses only csv-sdk runtime APIs - no direct chain adapter dependencies.
//! Lease management is delegated to csv-runtime.
//!
//! Two finality-wait drivers over one resumable coordinator core, selected by
//! command-line switches (never interactively):
//!   * default (non-blocking): lock, journal, return "awaiting finality".
//!   * `--wait` (poll-and-block): lock, then poll `resume` until the lock reaches
//!     finality and the destination mint completes.
//!
//! The `resume` subcommand advances an already-locked transfer without re-locking.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine as _;

use csv_algebra::finality::FinalityEvidence;
use csv_algebra::proof::CanonicalProof;
use csv_algebra::state::AwaitingFinality;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::SealPoint;
use csv_protocol::verification_levels::VerificationLevel;
use csv_runtime::execution_journal::ExecutionJournal;
use csv_runtime::execution_journal::RocksDbExecutionJournal;
use csv_runtime::{SendExecutor, SendExecutorError, SendTransfer};
use csv_sdk::CsvClient;
use csv_sdk::transfers::{
    DestinationMaterialization, TransferManager, TransferOutcome, TransferReceipt as SdkReceipt,
};
use csv_wire::{
    CONSIGNMENT_VERSION, Consignment as WireConsignment, Invoice, SanadIdWire, SealDefinition,
};

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{
    ProvenanceStrengthSignal, SanadRecord, SanadStatus, SealRecord, SealStatus, TransferRecord,
    TransferStatus, UnifiedStateManager,
};

use super::to_protocol_chain;
use crate::wallet_identity::WalletIdentity;

/// Finality-wait behaviour selected by command-line switches.
pub struct WaitOpts {
    /// Poll-and-block until the transfer completes (vs. return on Pending).
    pub wait: bool,
    /// How often to re-check finality while `wait` is set.
    pub poll_interval: Duration,
    /// How long to keep polling before giving up while `wait` is set.
    pub timeout: Duration,
}

impl WaitOpts {
    pub fn new(wait: bool, poll_interval_secs: u64, timeout_secs: u64) -> Self {
        Self {
            wait,
            poll_interval: Duration::from_secs(poll_interval_secs.max(1)),
            timeout: Duration::from_secs(timeout_secs),
        }
    }
}

/// Authenticity path selected for `materialize` via `--proof`.
///
/// `attestor` is the interim RFC §9 verifier-signed attestation path (available
/// first). `zk` is the deferred RFC §9.5 ZkSeal path; it must return a clear
/// not-available error rather than quietly falling back to `attestor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProofMode {
    /// Interim authenticity: RFC §9 verifier-signed mint attestation.
    Attestor,
    /// Target authenticity: RFC §9.5 ZkSeal proof. Not available until the
    /// prover lands (see TXMODE-ZK-001).
    Zk,
}

/// Gate materialize on an available authenticity path.
///
/// `attestor` is available now; `zk` fails closed with an explicit not-available
/// error and MUST NOT fall back to `attestor` (the fallback would quietly
/// downgrade the authenticity guarantee the operator asked for).
fn ensure_proof_available(proof: ProofMode) -> Result<()> {
    match proof {
        ProofMode::Attestor => Ok(()),
        ProofMode::Zk => Err(anyhow::anyhow!(
            "`--proof zk` is not available yet: the ZkSeal prover (RFC §9.5) has not \
             landed (see TXMODE-ZK-001). Re-run with `--proof attestor` to use the \
             interim verifier-signed attestation path. materialize does not fall back \
             to attestor automatically."
        )),
    }
}

fn seal_strength_rank(chain: &str) -> Option<u8> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "solana" => Some(1),
        "ethereum" => Some(2),
        "aptos" => Some(3),
        "bitcoin" | "sui" => Some(4),
        _ => None,
    }
}

fn chain_display_name(chain: &str) -> &'static str {
    match chain.trim().to_ascii_lowercase().as_str() {
        "bitcoin" => "Bitcoin",
        "sui" => "Sui",
        "aptos" => "Aptos",
        "ethereum" => "Ethereum",
        "solana" => "Solana",
        _ => "unknown",
    }
}

pub(crate) fn provenance_strength_signal(
    source_chain: &Chain,
    destination_chain: &Chain,
) -> Option<ProvenanceStrengthSignal> {
    let source_rank = seal_strength_rank(source_chain.as_str())?;
    let destination_rank = seal_strength_rank(destination_chain.as_str())?;
    let provenance_gap = i16::from(destination_rank) - i16::from(source_rank);
    if provenance_gap <= 0 {
        return None;
    }

    let source = chain_display_name(source_chain.as_str());
    let destination = chain_display_name(destination_chain.as_str());
    Some(ProvenanceStrengthSignal {
        source_chain: source_chain.clone(),
        destination_chain: destination_chain.clone(),
        source_rank,
        destination_rank,
        provenance_gap,
        warning: format!(
            "{source} single-use seals are weaker than the receiving {destination} seal. \
             Destination strength does not upgrade origin security; wait for deeper {source} \
             finality before treating this sanad as settled."
        ),
    })
}

pub(crate) fn emit_provenance_strength_warning(signal: &ProvenanceStrengthSignal) {
    output::warning(&signal.warning);
    output::kv("Provenance Gap", &signal.provenance_gap.to_string());
}

fn chain_from_proof_source(value: &str) -> Option<Chain> {
    let normalized = value
        .trim()
        .trim_start_matches("csv.chain.")
        .trim_start_matches("chain:")
        .to_ascii_lowercase();
    if seal_strength_rank(&normalized).is_some() {
        Some(Chain::new(&normalized))
    } else {
        None
    }
}

fn consignment_source_chain(consignment: &WireConsignment) -> Option<Chain> {
    if let Some(chain) = chain_from_proof_source(&consignment.proof_bundle.finality_proof.source) {
        return Some(chain);
    }
    if let Some(chain) = chain_from_proof_source(&consignment.proof_bundle.inclusion_proof.source) {
        return Some(chain);
    }
    std::str::from_utf8(&consignment.proof_bundle.anchor_ref.metadata)
        .ok()
        .and_then(chain_from_proof_source)
}

struct ResumeContext {
    from: Chain,
    to: Chain,
    sanad_id: SanadId,
}

/// Build a runtime-backed CSV client for the given source/destination chains.
///
/// Shared by both `transfer` (fresh lock) and `resume` (advance existing lock),
/// so the adapter/wallet wiring can never drift between the two entry points.
pub(super) async fn build_client(
    from: &Chain,
    to: &Chain,
    finality_depth: Option<u64>,
    config: &Config,
    state: &UnifiedStateManager,
) -> Result<CsvClient> {
    let from_chain = to_protocol_chain(from.clone());
    let to_chain = to_protocol_chain(to.clone());

    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.data_dir = Some(config.data_dir.clone());

    // Source chain config (threads wallet UTXOs, seed, and sanad seals).
    if let Ok(from_chain_config) = config.chain(from) {
        let utxos = if from.as_str() == "bitcoin" {
            state
                .storage
                .wallet
                .utxos
                .iter()
                .map(|u| csv_sdk::config::UtxoConfig {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    account: u.account,
                    index: u.index,
                    script_pubkey: u.script_pubkey.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

        let chain_config = csv_sdk::config::ChainConfig {
            rpc: csv_sdk::config::RpcConfig {
                url: from_chain_config.rpc_url.clone(),
                indexer_url: from_chain_config.indexer_url.clone(),
                indexer_backend: from_chain_config.indexer_backend.clone(),
                api_key: None,
                timeout_ms: 30000,
                max_retries: 3,
            },
            finality_depth: finality_depth.unwrap_or(from_chain_config.finality_depth) as u32,
            enabled: true,
            xpub: None,
            seed: (from.as_str() == "bitcoin")
                .then(|| {
                    WalletIdentity::from_state(state).map(|identity| identity.bitcoin_seed_hex())
                })
                .transpose()?,
            contract_address: from_chain_config.contract_address.clone(),
            program_id: from_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos,
            sanad_seals: state
                .storage
                .wallet
                .sanad_seals
                .iter()
                .map(|s| csv_sdk::config::SanadSealConfig {
                    sanad_id: s.sanad_id.clone(),
                    anchor_txid: s.anchor_txid.clone(),
                    vout: s.vout,
                    commitment: state
                        .storage
                        .sanads
                        .iter()
                        .find(|r| r.id == s.sanad_id)
                        .map(|r| r.commitment.clone()),
                })
                .collect(),
        };
        sdk_config.chains.insert(from.to_string(), chain_config);
    }

    // Destination chain config.
    if let Ok(to_chain_config) = config.chain(to) {
        let chain_config = csv_sdk::config::ChainConfig {
            rpc: csv_sdk::config::RpcConfig {
                url: to_chain_config.rpc_url.clone(),
                indexer_url: to_chain_config.indexer_url.clone(),
                indexer_backend: to_chain_config.indexer_backend.clone(),
                api_key: None,
                timeout_ms: 30000,
                max_retries: 3,
            },
            finality_depth: to_chain_config.finality_depth as u32,
            enabled: true,
            xpub: None,
            seed: (to.as_str() == "bitcoin")
                .then(|| {
                    WalletIdentity::from_state(state).map(|identity| identity.bitcoin_seed_hex())
                })
                .transpose()?,
            contract_address: to_chain_config.contract_address.clone(),
            program_id: to_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        };
        sdk_config.chains.insert(to.to_string(), chain_config);
    }

    let identity = WalletIdentity::from_state(state)?;
    let private_keys = identity.signing_map(&[(from, 0, 0), (to, 0, 0)], state)?;

    let client = CsvClient::builder()
        .with_chain(from_chain)
        .with_chain(to_chain)
        .with_config(sdk_config)
        .with_private_keys(private_keys)
        .with_runtime_coordinator()
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    Ok(client)
}

/// Interactive off-chain transfer (`send`) — behavior lands in TXMODE-SEND-001.
///
/// Assigns the Sanad to the invoice's recipient-controlled seal, closes the
/// source seal, and emits a consignment for off-band delivery without invoking
/// a destination-chain submitter or attestor.
pub async fn cmd_send(
    from: Chain,
    sanad_id: String,
    invoice: String,
    output_path: Option<PathBuf>,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Interactive Off-Chain Transfer (send)");

    let sanad_id =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_hex = hex::encode(sanad_id.as_bytes());

    let sanad_record = state
        .get_sanad(&sanad_hex)
        .ok_or_else(|| anyhow::anyhow!("Sanad {} not found in local state", sanad_hex))?;
    if sanad_record.status != SanadStatus::Active {
        return Err(anyhow::anyhow!(
            "Sanad {} is not active (status: {})",
            sanad_hex,
            sanad_record.status
        ));
    }
    if sanad_record.chain != from {
        return Err(anyhow::anyhow!(
            "Sanad {} is anchored on {}, not {}",
            sanad_hex,
            sanad_record.chain,
            from
        ));
    }

    let invoice = decode_invoice_blob(&invoice)?;
    let destination_chain = crate::config::parse_chain(invoice.seal.chain())
        .map_err(|e| anyhow::anyhow!("Invalid invoice destination chain: {}", e))?;
    let destination_seal = invoice
        .bound_seal_point()
        .map_err(|e| anyhow::anyhow!("Invalid invoice seal: {}", e))?;
    let invoice_id = invoice
        .canonical_id()
        .map_err(|e| anyhow::anyhow!("Failed to derive invoice id: {}", e))?;

    let source_seal = resolve_source_seal(&from, &sanad_hex, state)?;
    let transfer_id = derive_send_transfer_id(&from, &sanad_id, &source_seal, &invoice_id)?;

    let proof_bundle = load_verified_send_proof(&from, &sanad_hex, &destination_seal, state)?;
    let executor = CliSendExecutor {
        invoice,
        proof_bundle,
    };
    let transfer = SendTransfer {
        transfer_id: transfer_id.clone(),
        source_chain: from.to_string(),
        sanad_id: sanad_id.clone(),
        source_seal,
        destination_seal,
    };

    let client = build_client(&from, &destination_chain, None, config, state).await?;
    let coordinator = client
        .coordinator()
        .ok_or_else(|| anyhow::anyhow!("Runtime coordinator is not available"))?;

    let receipt = match coordinator.execute_send(&transfer, &executor).await {
        Ok(receipt) => receipt,
        Err(csv_runtime::TransferCoordinatorError::RuntimeError(msg))
            if msg.contains("already has journal history") =>
        {
            coordinator.resume_send(&transfer, &executor).await?
        }
        Err(e) => return Err(e.into()),
    };

    let path =
        output_path.unwrap_or_else(|| PathBuf::from(format!("consignment-{transfer_id}.cbor")));
    write_consignment_once(&path, &receipt.consignment.0)?;
    record_send_completed(
        state,
        &receipt.transfer_id,
        &from,
        &destination_chain,
        &sanad_id,
        &path,
    );
    state.save()?;

    output::success("Interactive off-chain send completed");
    output::kv("Transfer ID", &receipt.transfer_id);
    output::kv("Source Chain", from.as_str());
    output::kv("Invoice ID", &hex::encode(invoice_id));
    output::kv("Consignment", &path.display().to_string());
    output::info("No destination-chain submitter, fee spend, or attestor was used.");
    Ok(())
}

struct CliSendExecutor {
    invoice: Invoice,
    proof_bundle: csv_protocol::proof_taxonomy::ProofBundle,
}

#[async_trait]
impl SendExecutor for CliSendExecutor {
    async fn assign_seal(
        &self,
        transfer: &SendTransfer,
    ) -> Result<csv_runtime::SealAssignment, SendExecutorError> {
        let expected = self
            .invoice
            .bound_seal_point()
            .map_err(SendExecutorError::Assign)?;
        if expected != transfer.destination_seal {
            return Err(SendExecutorError::Assign(
                "invoice seal does not match transfer destination seal".to_string(),
            ));
        }
        if self.proof_bundle.seal_ref != transfer.destination_seal {
            return Err(SendExecutorError::Assign(
                "transition proof is not assigned to the invoice seal".to_string(),
            ));
        }

        let mut bytes = b"csv.send.assignment.v1".to_vec();
        bytes.extend_from_slice(transfer.sanad_id.as_bytes());
        bytes.extend_from_slice(
            &transfer
                .source_seal
                .to_canonical_bytes()
                .map_err(|e| SendExecutorError::Assign(e.to_string()))?,
        );
        bytes.extend_from_slice(
            &transfer
                .destination_seal
                .to_canonical_bytes()
                .map_err(|e| SendExecutorError::Assign(e.to_string()))?,
        );
        Ok(csv_runtime::SealAssignment(bytes))
    }

    async fn close_source_seal(
        &self,
        transfer: &SendTransfer,
        assignment: &csv_runtime::SealAssignment,
    ) -> Result<csv_runtime::SealCloseWitness, SendExecutorError> {
        let mut preimage = b"csv.send.close-witness.v1".to_vec();
        preimage.extend_from_slice(transfer.sanad_id.as_bytes());
        preimage.extend_from_slice(
            &transfer
                .source_seal
                .to_canonical_bytes()
                .map_err(|e| SendExecutorError::Close(e.to_string()))?,
        );
        preimage.extend_from_slice(&assignment.0);
        Ok(csv_runtime::SealCloseWitness(
            csv_hash::csv_tagged_hash("csv.send.close-witness.v1", &preimage).to_vec(),
        ))
    }

    async fn emit_consignment(
        &self,
        transfer: &SendTransfer,
        _witness: &csv_runtime::SealCloseWitness,
    ) -> Result<csv_runtime::Consignment, SendExecutorError> {
        let consignment = csv_wire::Consignment::new(
            self.invoice.clone(),
            SanadIdWire::from(transfer.sanad_id.clone()),
            self.proof_bundle.clone(),
        );
        if !consignment
            .binds_invoice_seal()
            .map_err(SendExecutorError::Emit)?
        {
            return Err(SendExecutorError::Emit(
                "consignment does not bind the invoice seal".to_string(),
            ));
        }
        let bytes = consignment
            .canonical_cbor()
            .map_err(|e| SendExecutorError::Emit(e.to_string()))?;
        Ok(csv_runtime::Consignment(bytes))
    }
}

fn decode_invoice_blob(blob: &str) -> Result<Invoice> {
    let raw = if let Some(path) = blob.strip_prefix('@') {
        std::fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read invoice file: {}", e))?
    } else {
        hex::decode(blob.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid invoice hex blob: {}", e))?
    };
    csv_codec::from_canonical_cbor(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to decode canonical invoice: {}", e))
}

fn resolve_source_seal(
    from: &Chain,
    sanad_hex: &str,
    state: &UnifiedStateManager,
) -> Result<SealPoint> {
    if from.as_str() == "bitcoin" {
        if let Some(record) = state.storage.wallet.sanad_seals.iter().find(|s| {
            s.sanad_id
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(sanad_hex)
        }) {
            let mut txid = decode_hex_field("bitcoin sanad seal txid", &record.anchor_txid)?;
            txid.reverse();
            let seal = SealDefinition::bitcoin(txid, record.vout)
                .map_err(|e| anyhow::anyhow!("Invalid Bitcoin source seal: {}", e))?;
            return seal
                .to_seal_point(None)
                .map_err(|e| anyhow::anyhow!("Invalid Bitcoin source seal point: {}", e));
        }
    }

    let sanad = state
        .get_sanad(sanad_hex)
        .ok_or_else(|| anyhow::anyhow!("Sanad {} not found in local state", sanad_hex))?;
    decode_stored_seal_point(&sanad.seal_ref)
}

fn decode_stored_seal_point(value: &str) -> Result<SealPoint> {
    let trimmed = value.trim();
    let bytes = if let Ok(bytes) = hex::decode(trimmed.trim_start_matches("0x")) {
        bytes
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| anyhow::anyhow!("Stored seal_ref is neither hex nor base64: {}", e))?
    };

    SealPoint::from_canonical_bytes(&bytes)
        .or_else(|_| SealPoint::new(bytes, None, None))
        .map_err(|e| anyhow::anyhow!("Invalid stored source seal: {}", e))
}

fn load_verified_send_proof(
    from: &Chain,
    sanad_hex: &str,
    destination_seal: &SealPoint,
    state: &UnifiedStateManager,
) -> Result<csv_protocol::proof_taxonomy::ProofBundle> {
    let proof = state
        .storage
        .proofs
        .iter()
        .filter(|p| p.chain == *from)
        .filter(|p| {
            p.sanad_id
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(sanad_hex)
        })
        .filter(|p| p.verified)
        .filter(|p| {
            matches!(
                p.proof_type.as_str(),
                "transition" | "send_transition" | "consignment"
            )
        })
        .max_by_key(|p| p.verified_at.unwrap_or(p.created_at))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No verified send transition proof found for Sanad {} on {}. Refusing to emit \
                 a consignment without transition history; generate and verify a transition \
                 ProofBundle assigned to the invoice seal first.",
                sanad_hex,
                from
            )
        })?;
    let raw = proof
        .decoded_proof_data()
        .ok_or_else(|| anyhow::anyhow!("Verified proof record has no decodable proof data"))?;
    let bundle = csv_protocol::proof_taxonomy::ProofBundle::from_canonical_bytes(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to decode transition ProofBundle: {}", e))?;
    if bundle.seal_ref != *destination_seal {
        return Err(anyhow::anyhow!(
            "Verified transition proof is assigned to a different seal than the invoice"
        ));
    }
    if bundle.transition_dag.nodes.is_empty()
        || bundle.inclusion_proof.proof_bytes.is_empty()
        || bundle.finality_proof.finality_data.is_empty()
    {
        return Err(anyhow::anyhow!(
            "Verified transition proof is incomplete; refusing to emit consignment"
        ));
    }
    Ok(bundle)
}

fn derive_send_transfer_id(
    from: &Chain,
    sanad_id: &SanadId,
    source_seal: &SealPoint,
    invoice_id: &[u8],
) -> Result<String> {
    let mut preimage = b"csv.send.transfer-id.v1".to_vec();
    preimage.extend_from_slice(from.as_str().as_bytes());
    preimage.extend_from_slice(sanad_id.as_bytes());
    preimage.extend_from_slice(
        &source_seal
            .to_canonical_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to encode source seal: {}", e))?,
    );
    preimage.extend_from_slice(invoice_id);
    Ok(hex::encode(csv_hash::csv_tagged_hash(
        "csv.send.transfer-id.v1",
        &preimage,
    )))
}

fn write_consignment_once(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(existing) = path.exists().then(|| std::fs::read(path)).transpose()? {
        if existing == bytes {
            output::info(&format!(
                "Consignment file already exists with matching bytes: {}",
                path.display()
            ));
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "Refusing to overwrite existing consignment file with different bytes: {}",
            path.display()
        ));
    }
    std::fs::write(path, bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write consignment file: {}", e))
}

/// Recipient invoice issuance (`invoice`), the interactive-mode entry point.
///
/// Emits an [`Invoice`] binding a single-use [`SealDefinition`] the recipient
/// controls on the destination chain, the accepted Sanad schema/type, and a
/// fresh anti-replay nonce. This is the grief-proofing step: because the
/// recipient defines the seal, a sender can only ever assign the sanad to a seal
/// the recipient owns.
///
/// The `--seal` reference is chain-tagged (`<chain>:<field>:<field>`) so it is
/// self-describing without a separate `--chain` flag, and it is verified against
/// wallet-held key material **offline** — no destination transaction, gas, or
/// RPC. If the wallet cannot prove control of the seal, the command fails closed
/// rather than issuing an invoice for a seal the recipient does not own.
pub async fn cmd_invoice(
    schema: String,
    seal: String,
    _config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    output::header("Issue Transfer Invoice (invoice)");

    // 1. Resolve the chain-tagged seal reference to a pinned `SealDefinition`.
    let seal_def = parse_seal_ref(&seal)?;
    output::kv("Destination chain", seal_def.chain());

    // 2. Prove — offline, against wallet-held material — that the recipient
    //    controls this seal. Fail closed otherwise: issuing an invoice for a
    //    seal we do not own would let a sender assign the sanad somewhere the
    //    recipient cannot later spend it.
    verify_seal_controlled(&seal_def, state)?;
    output::success("Seal ownership verified against wallet-held material");

    // 3. Encode the accepted schema/type (opaque to the wire layer).
    let schema_id = encode_schema_id(&schema)?;

    // 4. Fresh anti-replay nonce chosen by the recipient. Folded into the bound
    //    `SealPoint` so a consignment for one invoice cannot satisfy another.
    let nonce: u64 = rand::random();

    // 5. Build and serialize the invoice through csv-wire using canonical CBOR
    //    (the only encoding permitted on this path — no JSON).
    let invoice = Invoice::new(seal_def, schema_id, nonce)
        .map_err(|e| anyhow::anyhow!("Failed to build invoice: {}", e))?;
    let blob = invoice
        .canonical_cbor()
        .map_err(|e| anyhow::anyhow!("Failed to encode invoice: {}", e))?;
    let invoice_id = invoice
        .canonical_id()
        .map_err(|e| anyhow::anyhow!("Failed to derive invoice id: {}", e))?;
    let bound = invoice
        .bound_seal_point()
        .map_err(|e| anyhow::anyhow!("Failed to derive bound seal point: {}", e))?;

    output::kv("Invoice ID", &hex::encode(&invoice_id));
    output::kv("Schema", &schema);
    output::kv("Nonce", &nonce.to_string());
    output::kv("Bound seal id", &hex::encode(&bound.id));
    output::success("Invoice issued — deliver the blob below to the sender:");
    output::kv("Invoice blob (hex)", &hex::encode(&blob));

    Ok(())
}

/// Decode an optionally `0x`-prefixed hex field of a seal reference.
fn decode_hex_field(what: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid hex for {}: {}", what, e))
}

/// Parse a chain-tagged seal reference into a pinned [`SealDefinition`].
///
/// The format is `<chain>:<field>:<field>` so `--seal` alone is self-describing.
/// Per chain (mirroring the pinned per-chain `SealPoint` encodings):
///   * `bitcoin:<txid_hex>:<vout>`             — UTXO OutPoint (txid in the usual
///     display/big-endian order; reversed here to the internal order the
///     definition pins).
///   * `sui:<object_id_hex>:<version>`         — owned object.
///   * `aptos:<resource_address_hex>:<key_hex>` — Move resource.
///   * `ethereum:<contract_hex>:<slot_hex>`    — contract storage slot.
fn parse_seal_ref(seal_ref: &str) -> Result<SealDefinition> {
    let fields: Vec<&str> = seal_ref.splitn(3, ':').collect();
    if fields.len() != 3 || fields.iter().any(|f| f.is_empty()) {
        return Err(anyhow::anyhow!(
            "Invalid --seal reference '{}'. Expected `<chain>:<field>:<field>`, e.g. \
             `bitcoin:<txid_hex>:<vout>`, `sui:<object_id_hex>:<version>`, \
             `aptos:<resource_address_hex>:<key_hex>`, or \
             `ethereum:<contract_hex>:<slot_hex>`.",
            seal_ref
        ));
    }
    let (chain, a, b) = (fields[0], fields[1], fields[2]);

    let def = match chain {
        "bitcoin" => {
            let mut txid = decode_hex_field("bitcoin txid", a)?;
            // The definition pins the internal byte order; callers supply the
            // display order, so reverse before constructing.
            txid.reverse();
            let vout: u32 = b
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid bitcoin vout '{}': {}", b, e))?;
            SealDefinition::bitcoin(txid, vout).map_err(|e| anyhow::anyhow!(e))?
        }
        "sui" => {
            let object_id = decode_hex_field("sui object_id", a)?;
            let version: u64 = b
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid sui object version '{}': {}", b, e))?;
            SealDefinition::sui(object_id, version).map_err(|e| anyhow::anyhow!(e))?
        }
        "aptos" => {
            let resource_address = decode_hex_field("aptos resource_address", a)?;
            let key = decode_hex_field("aptos key", b)?;
            SealDefinition::aptos(resource_address, key).map_err(|e| anyhow::anyhow!(e))?
        }
        "ethereum" => {
            let contract = decode_hex_field("ethereum contract", a)?;
            let slot = decode_hex_field("ethereum slot", b)?;
            SealDefinition::ethereum(contract, slot).map_err(|e| anyhow::anyhow!(e))?
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unsupported seal chain '{}'. Expected one of: bitcoin, sui, aptos, ethereum.",
                other
            ));
        }
    };
    Ok(def)
}

/// Encode the `--schema` argument into the invoice's opaque `schema_id`.
///
/// Accepts either a `0x`-prefixed hex schema hash (used verbatim) or a plain
/// type label (encoded as its UTF-8 bytes). The schema layer interprets it on
/// `accept`; the wire layer keeps it opaque.
fn encode_schema_id(schema: &str) -> Result<Vec<u8>> {
    let trimmed = schema.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("--schema must not be empty"));
    }
    if let Some(hexpart) = trimmed.strip_prefix("0x") {
        let bytes =
            hex::decode(hexpart).map_err(|e| anyhow::anyhow!("Invalid hex schema id: {}", e))?;
        if bytes.is_empty() {
            return Err(anyhow::anyhow!("--schema hex must not be empty"));
        }
        Ok(bytes)
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

/// Verify — offline, against wallet-held key material — that the recipient
/// controls `seal`. Fail closed if control cannot be established.
///
/// Only the chains whose control is derivable without a network round-trip are
/// verifiable here:
///   * **Bitcoin** — the nominated OutPoint must be in the wallet's UTXO set.
///   * **Aptos** — the resource address must be the wallet's own account.
///
/// Sui object ownership and Ethereum storage-slot control cannot be derived from
/// wallet key material offline (they need an on-chain query), so they fail closed
/// pending a follow-up adapter-backed ownership check.
fn verify_seal_controlled(seal: &SealDefinition, state: &UnifiedStateManager) -> Result<()> {
    match seal {
        SealDefinition::Bitcoin { txid, vout } => {
            // `txid` is internal byte order; the wallet stores display order.
            let mut display = txid.clone();
            display.reverse();
            let display_hex = hex::encode(&display);
            let owned = state.storage.wallet.utxos.iter().any(|u| {
                u.vout == *vout
                    && u.txid
                        .trim_start_matches("0x")
                        .eq_ignore_ascii_case(&display_hex)
            });
            if !owned {
                return Err(anyhow::anyhow!(
                    "Refusing to issue an invoice for a Bitcoin seal the wallet does not \
                     control: OutPoint {}:{} is not in the wallet UTXO set. Fund/scan the \
                     address or nominate a UTXO you own.",
                    display_hex,
                    vout
                ));
            }
            Ok(())
        }
        SealDefinition::Aptos {
            resource_address, ..
        } => {
            let identity = WalletIdentity::from_state(state)?;
            let addr = identity.address(&Chain::new("aptos"), 0, 0)?;
            let addr_bytes = hex::decode(addr.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("Failed to decode derived Aptos address: {}", e))?;
            if &addr_bytes != resource_address {
                return Err(anyhow::anyhow!(
                    "Refusing to issue an invoice for an Aptos seal the wallet does not \
                     control: resource address 0x{} is not the wallet's Aptos account 0x{}.",
                    hex::encode(resource_address),
                    hex::encode(&addr_bytes)
                ));
            }
            Ok(())
        }
        SealDefinition::Sui { .. } | SealDefinition::Ethereum { .. } => Err(anyhow::anyhow!(
            "Offline ownership verification is not available for {} seals: control of an \
             object/storage slot cannot be derived from wallet key material without an \
             on-chain query. This fail-closed path will be lifted by a follow-up adding an \
             adapter-backed ownership check; use a Bitcoin or Aptos destination seal for now.",
            seal.chain()
        )),
    }
}

/// Verified, replay-free consignment metadata ready to persist as local ownership.
#[derive(Debug)]
pub struct AcceptedConsignment {
    pub sanad_id: String,
    pub source_chain: Option<Chain>,
    pub dest_chain: csv_hash::ChainId,
    pub seal_ref: String,
    pub seal_id: String,
    pub owner: String,
    pub commitment: String,
    pub anchor_height: u64,
    pub verification_level: VerificationLevel,
    pub provenance_strength: Option<ProvenanceStrengthSignal>,
    pub consignment: WireConsignment,
}

/// Decode and fully validate a canonical interactive-mode consignment without
/// mutating local state.
pub fn validate_consignment_bytes(
    bytes: &[u8],
    state: &UnifiedStateManager,
    authorized_signers: &[Vec<u8>],
) -> Result<AcceptedConsignment> {
    let consignment: WireConsignment = csv_codec::from_canonical_cbor(bytes)
        .map_err(|e| anyhow::anyhow!("Invalid canonical consignment CBOR: {}", e))?;

    if consignment.version != CONSIGNMENT_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported consignment version {}; expected {}",
            consignment.version,
            CONSIGNMENT_VERSION
        ));
    }

    if !consignment
        .binds_invoice_seal()
        .map_err(|e| anyhow::anyhow!("Invalid invoice seal binding: {}", e))?
    {
        return Err(anyhow::anyhow!(
            "Consignment proof is not assigned to the invoice seal"
        ));
    }

    let sanad_id = normalize_sanad_id(&consignment.sanad_id.bytes)?;
    if state.get_sanad(&sanad_id).is_some() {
        return Err(anyhow::anyhow!(
            "Replay rejected: Sanad {} is already recorded in this wallet",
            sanad_id
        ));
    }

    let seal_ref = encode_seal_ref(&consignment.proof_bundle.seal_ref)?;
    if state.storage.seals.iter().any(|s| s.seal_ref == seal_ref) {
        return Err(anyhow::anyhow!(
            "Replay rejected: destination seal is already recorded in this wallet"
        ));
    }

    let seal_id = hex::encode(&consignment.proof_bundle.seal_ref.id);
    let seal_registry = |seal_id: &[u8]| -> bool {
        state.is_seal_consumed(&hex::encode(seal_id))
            || state
                .storage
                .seals
                .iter()
                .any(|s| s.consumed && s.seal_ref == hex::encode(seal_id))
    };
    // VERIFY-SIGNER-BINDING-001: bind the proof-bundle signatures to the
    // recipient's trusted verifier set (supplied by the caller from local
    // config). Empty ⇒ verify_proof fails closed; surface an actionable message.
    if authorized_signers.is_empty() {
        return Err(anyhow::anyhow!(
            "No approved verifier keys configured: cannot authenticate the consignment's signer. \
             Add the destination registry's verifier public key(s) under [verifier] approved_keys \
             in ~/.csv/config.toml, then retry accept."
        ));
    }
    // VERIFY-DOMAIN-SEPARATION-001: bind the proof bundle to the Sanad this
    // consignment declares (the bundle's anchor must match), rejecting a bundle
    // built for a different transfer/domain. `sanad_id` is the normalized 32-byte
    // hex decoded above; the consignment is already bound to the trusted invoice
    // seal via `binds_invoice_seal()`.
    let expected_domain = {
        let bytes = hex::decode(&sanad_id)
            .map_err(|e| anyhow::anyhow!("Invalid consignment sanad_id: {}", e))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        csv_verifier::ExpectedDomain {
            sanad_id: Some(arr),
            source_chain: None,
        }
    };
    let result = csv_verifier::verify_proof_bound(
        &consignment.proof_bundle,
        seal_registry,
        consignment.proof_bundle.signature_scheme,
        authorized_signers,
        &expected_domain,
    );
    if !result.is_valid || !result.errors.is_empty() {
        for error in &result.errors {
            output::error(&format!("✗ {}", error));
        }
        return Err(anyhow::anyhow!("Consignment proof verification failed"));
    }

    validate_algebra_acceptance(&consignment)?;

    let dest_chain = csv_hash::ChainId::new(consignment.invoice.seal.chain());
    let source_chain = consignment_source_chain(&consignment).ok_or_else(|| {
        anyhow::anyhow!(
            "Consignment is missing recognized source-chain provenance; refusing to accept \
             because provenance strength cannot be evaluated"
        )
    })?;
    let provenance_strength = provenance_strength_signal(&source_chain, &dest_chain);
    let owner = owner_from_invoice(&consignment.invoice)?;
    let commitment = hex::encode(
        consignment
            .proof_bundle
            .transition_dag
            .root_commitment
            .as_bytes(),
    );

    Ok(AcceptedConsignment {
        sanad_id,
        source_chain: Some(source_chain),
        dest_chain,
        seal_ref,
        seal_id,
        owner,
        commitment,
        anchor_height: consignment.proof_bundle.anchor_ref.block_height,
        verification_level: result.level,
        provenance_strength,
        consignment,
    })
}

fn validate_algebra_acceptance(consignment: &WireConsignment) -> Result<()> {
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(
        consignment
            .proof_bundle
            .inclusion_proof
            .block_hash
            .as_bytes(),
    );
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(consignment.proof_bundle.inclusion_proof.root.as_bytes());
    let proof = CanonicalProof::new(
        consignment.proof_bundle.anchor_ref.block_height,
        block_hash,
        state_root,
        vec![consignment.proof_bundle.inclusion_proof.proof_bytes.clone()],
        chain_discriminant(consignment.invoice.seal.chain()),
    );
    let awaiting = AwaitingFinality {
        proof,
        required_confirmations: 6,
    };
    let evidence = FinalityEvidence::new(
        block_hash,
        consignment.proof_bundle.anchor_ref.block_height,
        consignment
            .proof_bundle
            .finality_proof
            .finality_data
            .clone(),
        now_unix_secs(),
    );
    let _validated = awaiting.accept(evidence);
    Ok(())
}

fn record_accepted_consignment(
    accepted: &AcceptedConsignment,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let created_at = now_unix_secs();
    state.add_sanad(SanadRecord {
        id: accepted.sanad_id.clone(),
        chain: accepted.dest_chain.clone(),
        seal_ref: accepted.seal_ref.clone(),
        owner: accepted.owner.clone(),
        value: 0,
        commitment: accepted.commitment.clone(),
        nullifier: None,
        status: SanadStatus::Active,
        created_at,
        anchor_tx_hash: Some(hex::encode(
            &accepted.consignment.proof_bundle.anchor_ref.anchor_id,
        )),
        nonce: Some(accepted.consignment.invoice.nonce),
        provenance_strength: accepted.provenance_strength.clone(),
    });
    state.add_seal(SealRecord {
        seal_ref: accepted.seal_ref.clone(),
        chain: accepted.dest_chain.clone(),
        value: 0,
        consumed: false,
        status: SealStatus::Active,
        created_at,
        sanad_id: Some(accepted.sanad_id.clone()),
        content: Some(accepted.commitment.clone()),
        proof_ref: Some(hex::encode(
            &accepted.consignment.proof_bundle.anchor_ref.anchor_id,
        )),
    });
    state.save()
}

fn normalize_sanad_id(value: &str) -> Result<String> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow::anyhow!("Invalid consignment sanad_id hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Invalid consignment sanad_id length: {} bytes",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

fn encode_seal_ref(seal: &SealPoint) -> Result<String> {
    let bytes = seal
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to encode destination seal: {}", e))?;
    Ok(hex::encode(bytes))
}

fn owner_from_invoice(invoice: &Invoice) -> Result<String> {
    let seal = invoice
        .bound_seal_point()
        .map_err(|e| anyhow::anyhow!("Invalid invoice seal: {}", e))?;
    Ok(hex::encode(seal.id))
}

fn chain_discriminant(chain: &str) -> u32 {
    let digest = csv_hash::csv_tagged_hash("csv.cli.chain-discriminant.v1", chain.as_bytes());
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct AcceptLock {
    path: PathBuf,
}

impl AcceptLock {
    fn acquire(state: &UnifiedStateManager) -> Result<Self> {
        let path = PathBuf::from(format!("{}.accept.lock", state.file_path()));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("Failed to create accept lock directory: {}", e))?;
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Another consignment accept appears to be in progress; refusing to race replay checks: {}",
                    e
                )
            })?;
        Ok(Self { path })
    }
}

impl Drop for AcceptLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Recipient consignment acceptance (`accept`).
///
/// Client-side validates the consignment via `csv-verifier` and records
/// ownership in the wallet; no chain transaction.
pub async fn cmd_accept(
    consignment: String,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Accept Consignment (accept)");

    let _lock = AcceptLock::acquire(state)?;
    // VERIFY-SIGNER-BINDING-001: the recipient's approved verifier set, from
    // trusted local config, binds the proof-bundle signatures to an authorized
    // signer. Empty ⇒ validate_consignment_bytes fails closed.
    let authorized_signers = config.approved_verifier_keys()?;
    let bytes = std::fs::read(&consignment)
        .map_err(|e| anyhow::anyhow!("Failed to read consignment file: {}", e))?;
    output::progress(1, 5, "Decoding canonical consignment...");
    let accepted = validate_consignment_bytes(&bytes, state, &authorized_signers)?;

    output::progress(2, 5, "Verifying invoice seal binding...");
    output::kv("Sanad", &accepted.sanad_id);
    if let Some(source_chain) = &accepted.source_chain {
        output::kv("Source Chain", source_chain.as_str());
    }
    output::kv("Destination Chain", accepted.dest_chain.as_str());

    output::progress(3, 5, "Verifying transition proof, anchor, and finality...");
    output::kv(
        "Verification Level",
        &format!("{:?}", accepted.verification_level).to_lowercase(),
    );

    output::progress(4, 5, "Checking replay status...");
    output::kv("Destination Seal", &accepted.seal_ref);

    output::progress(5, 5, "Recording wallet ownership...");
    record_accepted_consignment(&accepted, state)?;

    if let Some(signal) = &accepted.provenance_strength {
        emit_provenance_strength_warning(signal);
    }
    output::warning(
        "Accepted via client-side validation; preserve the consignment and verify provenance with the sender out-of-band.",
    );
    output::success("Consignment accepted and ownership recorded");
    Ok(())
}

/// Materialize a Sanad as an on-chain object via the thin-registry mint.
///
/// This is the on-chain transfer mode. It wraps the same lock + thin-registry
/// mint path as the coordinator drives for any cross-chain transfer (and so
/// inherits the no-mint-without-verified-finality invariant: off-chain
/// verification always precedes mint and strict finality is enforced), gated by
/// an explicit `--proof` authenticity selector:
///
///   * [`ProofMode::Attestor`] — interim RFC §9 verifier-signed attestation
///     (available now).
///   * [`ProofMode::Zk`] — deferred RFC §9.5 ZkSeal path (TXMODE-ZK-001); returns
///     a clear not-available error and never falls back to the attestor path.
///
/// The `resume`/`retry`/`status` lifecycle verbs apply to materialize: it shares
/// the coordinator's execution journal, so a materialize that stops at
/// `Pending` (awaiting source finality) is advanced by `cross-chain resume`.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_materialize(
    from: Chain,
    to: Chain,
    sanad_id: String,
    dest_owner: Option<String>,
    proof: ProofMode,
    finality_depth: Option<u64>,
    opts: WaitOpts,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let from_chain = to_protocol_chain(from.clone());
    let to_chain = to_protocol_chain(to.clone());

    output::header(&format!(
        "Materialize Sanad: {:?} → {:?}",
        from_chain, to_chain
    ));
    if let Some(signal) = provenance_strength_signal(&from, &to) {
        emit_provenance_strength_warning(&signal);
    }

    // The authenticity path is chosen explicitly by the operator. `zk` must fail
    // closed until the prover lands (TXMODE-ZK-001) — it never quietly
    // downgrades to the attestor path.
    ensure_proof_available(proof)?;
    output::info("Authenticity: attestor (RFC §9 verifier-signed mint attestation)");
    ensure_destination_attestor_ready(&to, config).await?;

    lock_and_mint(
        from,
        to,
        sanad_id,
        dest_owner,
        finality_depth,
        opts,
        config,
        state,
    )
    .await
}

/// Chain-scoped mint-verifier env var for a destination chain, or `None` for
/// chains that do not use the verifier-attested mint path. Mirrors
/// `csv_adapter_factory::mint_signer` so the CLI preflight and the factory agree
/// on which key(s) authorize a given destination mint (MINT-KEYS-001).
fn chain_scoped_verifier_env(chain: &str) -> Option<&'static str> {
    match chain {
        "aptos" => Some("CSV_MINT_VERIFIER_KEY_APTOS"),
        "sui" => Some("CSV_MINT_VERIFIER_KEY_SUI"),
        "solana" => Some("CSV_MINT_VERIFIER_KEY_SOLANA"),
        "ethereum" => Some("CSV_MINT_VERIFIER_KEY_ETHEREUM"),
        _ => None,
    }
}

/// Resolve the destination-chain verifier secret entries the factory would load,
/// with the same precedence: a non-empty chain-scoped `CSV_MINT_VERIFIER_KEY_<CHAIN>`
/// (comma-separated list) is authoritative for that chain and is NOT mixed with
/// the legacy default; otherwise the legacy `CSV_MINT_VERIFIER_KEY` is used.
///
/// Returns the env var name the operator should set (for messaging) and the
/// trimmed, `0x`-stripped hex entries (never logged).
fn resolve_destination_verifier_secrets(chain: &str) -> (String, Vec<String>) {
    let split = |raw: &str| -> Vec<String> {
        raw.split(',')
            .map(|e| e.trim().trim_start_matches("0x").to_string())
            .filter(|e| !e.is_empty())
            .collect()
    };

    if let Some(scoped) = chain_scoped_verifier_env(chain)
        && let Ok(raw) = std::env::var(scoped)
        && !raw.trim().is_empty()
    {
        // Chain-scoped var is authoritative even if malformed: do not fall back to
        // the default, which could be a different verifier set.
        return (scoped.to_string(), split(&raw));
    }

    let default = std::env::var("CSV_MINT_VERIFIER_KEY").unwrap_or_default();
    let var_name = chain_scoped_verifier_env(chain)
        .unwrap_or("CSV_MINT_VERIFIER_KEY")
        .to_string();
    (var_name, split(&default))
}

async fn ensure_destination_attestor_ready(to: &Chain, config: &Config) -> Result<()> {
    let chain = to.as_str();
    if !matches!(chain, "sui" | "aptos" | "solana") {
        return Ok(());
    }

    let (scoped_var, verifier_secrets) = resolve_destination_verifier_secrets(chain);
    if verifier_secrets.is_empty() {
        output::error(&format!(
            "{} materialization requires a mint verifier key before the source Sanad is locked",
            to
        ));
        output::info(&format!(
            "Set {scoped_var} (or the legacy CSV_MINT_VERIFIER_KEY) to the secp256k1 verifier \
             signing key(s) registered in the destination registry — comma-separate multiple \
             keys for an M-of-N registry — then rerun materialize or resume.",
        ));
        return Err(anyhow::anyhow!(
            "Destination mint verifier key missing for {chain}; refusing to proceed without destination mint attestation"
        ));
    }

    if chain == "solana" {
        ensure_solana_verifier_registered(config, &verifier_secrets).await?;
    }
    Ok(())
}

async fn ensure_solana_verifier_registered(
    config: &Config,
    verifier_secrets: &[String],
) -> Result<()> {
    let chain_config = config.chain(&Chain::new("solana"))?;
    let program_id = chain_config
        .program_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Solana program_id is not configured"))?;
    let program_id = solana_sdk::pubkey::Pubkey::from_str(program_id)
        .map_err(|e| anyhow::anyhow!("Invalid Solana program_id: {}", e))?;
    let rpc_url = chain_config.rpc_url.trim();
    if rpc_url.is_empty() {
        return Err(anyhow::anyhow!(
            "Solana RPC URL is not configured; cannot preflight verifier registry"
        ));
    }

    // Derive the compressed pubkey of every configured verifier secret so we can
    // require that at least one is registered on-chain. A malformed secret is a
    // hard error rather than being silently dropped, so the operator learns the
    // configured key set is not what the registry will accept.
    let mut verifier_pubkeys = Vec::with_capacity(verifier_secrets.len());
    for secret in verifier_secrets {
        verifier_pubkeys.push(compressed_secp256k1_pubkey(secret)?);
    }

    let registry = solana_verifier_registry_pda(&program_id);
    let registry_account = fetch_solana_account_data(rpc_url, &registry).await?;
    let registered = decode_solana_verifier_registry(&registry_account)?;
    if !verifier_pubkeys.iter().any(|pk| registered.contains(pk)) {
        output::error(
            "None of the configured mint verifier keys are registered in the Solana verifier registry",
        );
        output::kv("Program ID", &program_id.to_string());
        output::kv("Registry PDA", &registry.to_string());
        output::kv(
            "Configured Verifier Pubkeys",
            &verifier_pubkeys
                .iter()
                .map(|v| format!("0x{}", hex::encode(v)))
                .collect::<Vec<_>>()
                .join(", "),
        );
        output::kv(
            "Registered Verifiers",
            &registered
                .iter()
                .map(|v| format!("0x{}", hex::encode(v)))
                .collect::<Vec<_>>()
                .join(", "),
        );
        output::info(
            "Seed or rotate the Solana verifier registry to include one of these compressed secp256k1 pubkeys, or configure a registered CSV_MINT_VERIFIER_KEY_SOLANA / CSV_MINT_VERIFIER_KEY.",
        );
        return Err(anyhow::anyhow!(
            "Solana destination verifier key is not registered"
        ));
    }
    Ok(())
}

fn compressed_secp256k1_pubkey(secret_hex: &str) -> Result<[u8; 33]> {
    let bytes = hex::decode(secret_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("CSV_MINT_VERIFIER_KEY must be hex: {}", e))?;
    let secret = secp256k1::SecretKey::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("CSV_MINT_VERIFIER_KEY is not a secp256k1 key: {}", e))?;
    let secp = secp256k1::Secp256k1::new();
    Ok(secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize())
}

fn solana_verifier_registry_pda(
    program_id: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::pubkey::Pubkey {
    solana_sdk::pubkey::Pubkey::find_program_address(&[b"verifier_registry"], program_id).0
}

async fn fetch_solana_account_data(
    rpc_url: &str,
    pubkey: &solana_sdk::pubkey::Pubkey,
) -> Result<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct RpcResponse {
        result: Option<RpcResult>,
        error: Option<serde_json::Value>,
    }

    #[derive(serde::Deserialize)]
    struct RpcResult {
        value: Option<RpcAccount>,
    }

    #[derive(serde::Deserialize)]
    struct RpcAccount {
        data: (String, String),
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            pubkey.to_string(),
            { "encoding": "base64", "commitment": "confirmed" }
        ]
    });
    let response: RpcResponse = reqwest::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if let Some(error) = response.error {
        return Err(anyhow::anyhow!(
            "Solana RPC getAccountInfo failed for {}: {}",
            pubkey,
            error
        ));
    }
    let account = response
        .result
        .and_then(|r| r.value)
        .ok_or_else(|| anyhow::anyhow!("Solana verifier registry {} is not initialized", pubkey))?;
    if account.data.1 != "base64" {
        return Err(anyhow::anyhow!(
            "Unexpected Solana account encoding for verifier registry: {}",
            account.data.1
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(account.data.0)
        .map_err(|e| anyhow::anyhow!("Failed to decode Solana verifier registry: {}", e))
}

fn decode_solana_verifier_registry(data: &[u8]) -> Result<Vec<[u8; 33]>> {
    const DISCRIMINATOR: usize = 8;
    const AUTHORITY: usize = 32;
    const THRESHOLD: usize = 1;
    const VEC_LEN: usize = 4;
    let offset = DISCRIMINATOR + AUTHORITY + THRESHOLD;
    if data.len() < offset + VEC_LEN {
        return Err(anyhow::anyhow!(
            "Solana verifier registry account is truncated"
        ));
    }
    let count_bytes: [u8; VEC_LEN] = data[offset..offset + VEC_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Solana verifier registry account is corrupted"))?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    let mut cursor = offset + VEC_LEN;
    let needed = cursor + count * 33;
    if data.len() < needed {
        return Err(anyhow::anyhow!(
            "Solana verifier registry declares {} verifier(s) but account data is truncated",
            count
        ));
    }
    let mut verifiers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut verifier = [0u8; 33];
        verifier.copy_from_slice(&data[cursor..cursor + 33]);
        verifiers.push(verifier);
        cursor += 33;
    }
    Ok(verifiers)
}

/// Shared lock + thin-registry mint core.
///
/// The coordinator owns the lock -> await-finality -> prove -> verify -> mint
/// state machine and returns `Pending` when the lock has not yet reached
/// finality; off-chain verification always precedes mint and finality is never
/// skipped. Callers print their own header before invoking this.
#[allow(clippy::too_many_arguments)]
async fn lock_and_mint(
    from: Chain,
    to: Chain,
    sanad_id: String,
    dest_owner: Option<String>,
    finality_depth: Option<u64>,
    opts: WaitOpts,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let from_chain = to_protocol_chain(from.clone());
    let to_chain = to_protocol_chain(to.clone());

    // Parse sanad ID using canonical parser
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_id_hash = Hash::new(*sanad_id_parsed.as_bytes());

    // Check if we have the sanad
    if state.get_sanad(&sanad_id_hash.to_hex()).is_none() {
        return Err(anyhow::anyhow!(
            "Sanad {} not found in local state",
            sanad_id_hash
        ));
    }

    // Get destination owner address using centralized identity resolver
    let dest_owner_str = if dest_owner.is_none() {
        if state.storage.wallet.mnemonic.is_some() {
            let identity = WalletIdentity::from_state(state)?;
            Some(identity.address(&to, 0, 0)?)
        } else {
            state.get_address(&to).map(|s| s.to_string())
        }
    } else {
        dest_owner
    };

    let Some(dest_addr) = dest_owner_str else {
        return Err(anyhow::anyhow!(
            "No destination address specified and no wallet address found for {:?}",
            to_chain
        ));
    };

    // Capability checks: ensure the source can be a cross-chain source and the
    // destination can be a cross-chain destination before we lock anything.
    let mut sdk_config_check = csv_sdk::config::Config::default();
    if let Ok(from_chain_config) = config.chain(&from) {
        sdk_config_check
            .chains
            .insert(from.to_string(), capability_chain_config(from_chain_config));
    }
    if let Ok(to_chain_config) = config.chain(&to) {
        sdk_config_check
            .chains
            .insert(to.to_string(), capability_chain_config(to_chain_config));
    }

    let check_client = CsvClient::builder()
        .with_chain(from_chain.clone())
        .with_chain(to_chain.clone())
        .with_config(sdk_config_check)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client for capability check: {}", e))?;

    let runtime = check_client.chain_runtime();

    let from_readiness = runtime
        .check_readiness(from_chain.clone(), 0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check source chain readiness: {}", e))?;
    if !from_readiness.cross_chain_source_supported {
        output::error(&format!(
            "Chain {:?} cannot be used as cross-chain transfer source",
            from_chain
        ));
        return Err(anyhow::anyhow!(
            "Cross-chain transfer not supported: source chain lacks capability"
        ));
    }

    let to_readiness = runtime
        .check_readiness(to_chain.clone(), 0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check destination chain readiness: {}", e))?;
    if !to_readiness.cross_chain_destination_supported {
        output::error(&format!(
            "Chain {:?} cannot be used as cross-chain transfer destination",
            to_chain
        ));
        return Err(anyhow::anyhow!(
            "Cross-chain transfer not supported: destination chain lacks capability"
        ));
    }

    output::success("Chain capability checks passed");

    let client = build_client(&from, &to, finality_depth, config, state).await?;
    let manager = client.transfers();

    // Lock on the source chain and take the first advance. The coordinator owns
    // the lock -> await-finality -> prove -> verify -> mint state machine and
    // returns Pending when the lock has not yet reached finality.
    output::info(&format!(
        "Locking Sanad {} on {:?}",
        sanad_id_hash, from_chain
    ));
    let sanad = SanadId(sanad_id_hash);
    let outcome = manager
        .cross_chain(sanad.clone(), to_chain.clone())
        .to_address(dest_addr.clone())
        .from_chain(from_chain.clone())
        .execute_outcome()
        .await
        .map_err(|e| anyhow::anyhow!("Transfer execution failed: {}", e))?;

    drive(
        &manager,
        outcome,
        sanad,
        from,
        to,
        &opts,
        Some(dest_addr),
        state,
    )
    .await
}

/// Resume an already-locked transfer that is awaiting finality (never re-locks).
pub async fn cmd_resume(
    transfer_id: String,
    opts: WaitOpts,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Resume Cross-Chain Transfer: {}", transfer_id));
    let resume_ctx = if let Some(record) = state.get_transfer(&transfer_id).cloned() {
        let sanad_id = SanadId::parse_hex(&record.sanad_id)
            .map_err(|e| anyhow::anyhow!("Invalid stored Sanad ID: {}", e))?;
        ResumeContext {
            from: record.source_chain,
            to: record.dest_chain,
            sanad_id,
        }
    } else if let Some(ctx) = recover_resume_context_from_journal(&transfer_id, config)? {
        output::info("Transfer not found in local display cache; recovering from runtime journal");
        ctx
    } else {
        return Err(anyhow::anyhow!(
            "Transfer {} not found in local state or runtime journal",
            transfer_id
        ));
    };

    ensure_destination_attestor_ready(&resume_ctx.to, config).await?;
    let dest_owner = resolve_destination_owner(&resume_ctx.to, None, state)?;

    let client = build_client(&resume_ctx.from, &resume_ctx.to, None, config, state).await?;
    let manager = client.transfers();

    let from_id = to_protocol_chain(resume_ctx.from.clone());
    let to_id = to_protocol_chain(resume_ctx.to.clone());
    let outcome = manager
        .resume(
            &transfer_id,
            resume_ctx.sanad_id.clone(),
            from_id,
            to_id,
            dest_owner.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Resume failed: {}", e))?;

    drive(
        &manager,
        outcome,
        resume_ctx.sanad_id,
        resume_ctx.from,
        resume_ctx.to,
        &opts,
        dest_owner,
        state,
    )
    .await
}

fn resolve_destination_owner(
    to: &Chain,
    explicit: Option<String>,
    state: &UnifiedStateManager,
) -> Result<Option<String>> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    if state.storage.wallet.mnemonic.is_some() {
        let identity = WalletIdentity::from_state(state)?;
        Ok(Some(identity.address(to, 0, 0)?))
    } else {
        Ok(state.get_address(to).map(|s| s.to_string()))
    }
}

/// Drive an outcome to completion according to the selected wait mode.
///
/// Poll-and-block (`--wait`) loops `resume` until `Completed` or the timeout;
/// otherwise a `Pending` outcome is reported and persisted for a later `resume`.
async fn drive(
    manager: &TransferManager,
    first: TransferOutcome,
    sanad_id: SanadId,
    from: Chain,
    to: Chain,
    opts: &WaitOpts,
    dest_owner: Option<String>,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let started = Instant::now();
    let mut outcome = first;
    let mut transfer_id_announced = false;

    loop {
        match outcome {
            TransferOutcome::Completed(receipt) => {
                record_completed(state, &receipt, &from, &to, &sanad_id, dest_owner.clone());
                state.save()?;
                output::success(&format!(
                    "Transfer {} completed. Sanad locked on source chain and minted on destination chain.",
                    receipt.transfer_id
                ));
                output::kv("Transfer ID", &receipt.transfer_id);
                output::kv("Replay ID", &receipt.replay_id.to_string());
                output::kv("Source Chain", receipt.source_chain.as_ref());
                output::kv("Destination Chain", receipt.destination_chain.as_ref());
                output::kv(
                    "Lock Tx Hash",
                    &display_tx_hash(&from, &receipt.lock_tx_hash),
                );
                output::kv("Mint Tx Hash", &receipt.mint_tx_hash);
                output_materialization_metadata(&receipt.materialization);
                return Ok(());
            }
            TransferOutcome::Pending {
                transfer_id,
                lock_tx_hash,
                confirmations,
                required,
            } => {
                record_pending(
                    state,
                    &transfer_id,
                    &lock_tx_hash,
                    &from,
                    &to,
                    &sanad_id,
                    dest_owner.clone(),
                );
                state.save()?;

                if !transfer_id_announced {
                    output::kv("Transfer ID", &transfer_id);
                    transfer_id_announced = true;
                }

                if !opts.wait {
                    output::info(&format!(
                        "Transfer {} locked — awaiting finality ({}/{} confirmations).",
                        transfer_id, confirmations, required
                    ));
                    output::kv("Transfer ID", &transfer_id);
                    output::kv("Lock Tx Hash", &display_tx_hash(&from, &lock_tx_hash));
                    output::info(&format!(
                        "Run `csv cross-chain resume {}` (optionally with --wait) once the lock confirms.",
                        transfer_id
                    ));
                    return Ok(());
                }

                if started.elapsed() >= opts.timeout {
                    output::error(&format!(
                        "Timed out after {}s waiting for finality ({}/{} confirmations). Transfer {} is locked; resume it later.",
                        opts.timeout.as_secs(),
                        confirmations,
                        required,
                        transfer_id
                    ));
                    return Err(anyhow::anyhow!(
                        "timed out awaiting finality for transfer {}",
                        transfer_id
                    ));
                }

                output::info(&format!(
                    "Awaiting finality for lock {}: {}/{} confirmations. Re-checking in {}s…",
                    display_tx_hash(&from, &lock_tx_hash),
                    confirmations,
                    required,
                    opts.poll_interval.as_secs()
                ));
                tokio::time::sleep(opts.poll_interval).await;

                let from_id = to_protocol_chain(from.clone());
                let to_id = to_protocol_chain(to.clone());
                outcome = manager
                    .resume(
                        &transfer_id,
                        sanad_id.clone(),
                        from_id,
                        to_id,
                        dest_owner.clone(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Resume failed: {}", e))?;
            }
        }
    }
}

fn recover_resume_context_from_journal(
    transfer_id: &str,
    config: &Config,
) -> Result<Option<ResumeContext>> {
    let journal_path = runtime_journal_path(config);
    if !journal_path.exists() {
        return Ok(None);
    }

    let journal = RocksDbExecutionJournal::open(&journal_path.to_string_lossy())
        .map_err(|e| anyhow::anyhow!("Failed to open runtime journal: {}", e))?;
    let entry = match journal
        .latest_entry(transfer_id)
        .map_err(|e| anyhow::anyhow!("Failed to read runtime journal: {}", e))?
    {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let ctx = match entry.transfer_context {
        Some(ctx) => ctx,
        None => return Ok(None),
    };

    let from = crate::config::parse_chain(&ctx.source_chain)
        .map_err(|e| anyhow::anyhow!("Invalid source chain in runtime journal: {}", e))?;
    let to = crate::config::parse_chain(&ctx.destination_chain)
        .map_err(|e| anyhow::anyhow!("Invalid destination chain in runtime journal: {}", e))?;
    let sanad_id = SanadId::parse_hex(&ctx.sanad_id.bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID in runtime journal: {}", e))?;

    Ok(Some(ResumeContext { from, to, sanad_id }))
}

fn runtime_journal_path(config: &Config) -> PathBuf {
    let data_dir = if let Some(stripped) = config.data_dir.strip_prefix("~/") {
        dirs::home_dir()
            .map(|home| home.join(stripped))
            .unwrap_or_else(|| PathBuf::from(&config.data_dir))
    } else {
        PathBuf::from(&config.data_dir)
    };

    data_dir.join("runtime").join("journal")
}

/// Minimal chain config used only for capability probing (no wallet material).
fn capability_chain_config(
    chain_config: &crate::config::ChainConfig,
) -> csv_sdk::config::ChainConfig {
    csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_config.rpc_url.clone(),
            indexer_url: chain_config.indexer_url.clone(),
            indexer_backend: chain_config.indexer_backend.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_config.finality_depth as u32,
        enabled: true,
        xpub: None,
        seed: None,
        contract_address: chain_config.contract_address.clone(),
        program_id: chain_config.program_id.clone(),
        account: 0,
        index: 0,
        utxos: Vec::new(),
        sanad_seals: Vec::new(),
    }
}

fn display_tx_hash(chain: &Chain, tx_hash: &str) -> String {
    if chain.as_str() != "bitcoin" {
        return tx_hash.to_string();
    }

    let normalized = tx_hash.trim_start_matches("0x");
    match hex::decode(normalized) {
        Ok(mut bytes) if bytes.len() == 32 => {
            bytes.reverse();
            hex::encode(bytes)
        }
        _ => tx_hash.to_string(),
    }
}

/// Persist a completed transfer to the local display cache and consume the Sanad.
fn record_completed(
    state: &mut UnifiedStateManager,
    receipt: &SdkReceipt,
    from: &Chain,
    to: &Chain,
    sanad_id: &SanadId,
    dest_owner: Option<String>,
) {
    let now = chrono::Utc::now().timestamp() as u64;
    let sender = state.get_address(from).map(|s| s.to_string());
    let sanad_hex = hex::encode(sanad_id.as_bytes());

    state.add_transfer(TransferRecord {
        id: receipt.transfer_id.clone(),
        source_chain: from.clone(),
        dest_chain: to.clone(),
        sanad_id: sanad_hex.clone(),
        sender_address: sender,
        destination_address: dest_owner,
        source_tx_hash: Some(receipt.lock_tx_hash.clone()),
        source_fee: None,
        dest_tx_hash: Some(receipt.mint_tx_hash.clone()),
        dest_fee: None,
        destination_contract: receipt.materialization.registry_ref.clone(),
        proof: None,
        status: TransferStatus::Completed,
        created_at: now,
        completed_at: Some(now),
        provenance_strength: provenance_strength_signal(from, to),
    });

    // The source seal is consumed on-chain, but the user-facing Sanad lifecycle
    // is a completed materialization onto the destination chain. Keep the local
    // display cache searchable as Transferred and point at the transfer record
    // for the destination mint evidence.
    if let Err(e) = state.update_sanad_status(&sanad_hex, SanadStatus::Transferred) {
        log::warn!(
            "Failed to mark source Sanad as transferred in local store: {}",
            e
        );
    }
}

fn output_materialization_metadata(materialization: &DestinationMaterialization) {
    if !materialization.has_display_metadata() {
        output::info("Destination materialization metadata: not reported by adapter");
        return;
    }
    output::header("Destination Materialization");
    if let Some(object_id) = &materialization.object_id {
        output::kv("Object ID", object_id);
    }
    if let Some(seal_ref) = &materialization.seal_ref {
        output::kv("Seal Ref", seal_ref);
    }
    if let Some(registry_ref) = &materialization.registry_ref {
        output::kv("Registry Ref", registry_ref);
    }
    if let Some(commitment) = materialization.commitment {
        output::kv("Commitment", &hex::encode(commitment));
    }
    if let Some(owner) = &materialization.owner {
        output::kv("Owner", &hex::encode(owner));
    }
}

/// Persist a locked-but-not-yet-final transfer so it can be resumed later.
fn record_pending(
    state: &mut UnifiedStateManager,
    transfer_id: &str,
    lock_tx_hash: &str,
    from: &Chain,
    to: &Chain,
    sanad_id: &SanadId,
    dest_owner: Option<String>,
) {
    let now = chrono::Utc::now().timestamp() as u64;
    let sender = state.get_address(from).map(|s| s.to_string());
    let sanad_hex = hex::encode(sanad_id.as_bytes());

    state.add_transfer(TransferRecord {
        id: transfer_id.to_string(),
        source_chain: from.clone(),
        dest_chain: to.clone(),
        sanad_id: sanad_hex.clone(),
        sender_address: sender,
        destination_address: dest_owner,
        source_tx_hash: Some(display_tx_hash(from, lock_tx_hash)),
        source_fee: None,
        dest_tx_hash: None,
        dest_fee: None,
        destination_contract: None,
        proof: None,
        status: TransferStatus::Locked,
        created_at: now,
        completed_at: None,
        provenance_strength: provenance_strength_signal(from, to),
    });

    // The local Sanad cache has no Locked state. Once the source lock is
    // broadcast the original source seal is no longer active, so Consumed is
    // the least misleading local display state until runtime-backed canonical
    // transfer state is shown here.
    if let Err(e) = state.consume_sanad(&sanad_hex) {
        log::warn!(
            "Failed to mark locked source Sanad as consumed in local store: {}",
            e
        );
    }
}

/// Persist a completed send-mode transfer to the local display cache.
///
/// Authority state is already in csv-runtime's execution journal/replay DB; this
/// cache row is only for `cross-chain status/list` and user inspection.
fn record_send_completed(
    state: &mut UnifiedStateManager,
    transfer_id: &str,
    from: &Chain,
    to: &Chain,
    sanad_id: &SanadId,
    consignment_path: &Path,
) {
    let now = chrono::Utc::now().timestamp() as u64;
    let sender = state.get_address(from).map(|s| s.to_string());
    let sanad_hex = hex::encode(sanad_id.as_bytes());

    state.add_transfer(TransferRecord {
        id: transfer_id.to_string(),
        source_chain: from.clone(),
        dest_chain: to.clone(),
        sanad_id: sanad_hex.clone(),
        sender_address: sender,
        destination_address: None,
        source_tx_hash: None,
        source_fee: None,
        dest_tx_hash: None,
        dest_fee: None,
        destination_contract: None,
        proof: Some(consignment_path.display().to_string()),
        status: TransferStatus::Completed,
        created_at: now,
        completed_at: Some(now),
        provenance_strength: provenance_strength_signal(from, to),
    });

    if let Err(e) = state.consume_sanad(&sanad_hex) {
        log::warn!(
            "Failed to mark sent Sanad as consumed in local store: {}",
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::UtxoRecord;
    use clap::ValueEnum;
    use csv_hash::dag::{DAGNode, DAGSegment};
    use csv_hash::seal::CommitAnchor;
    use csv_protocol::SignatureScheme;
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};

    // ── Mint verifier key resolution (MINT-KEYS-001) ────────────────────────

    // Serialize the env-mutating tests; they share process-wide env vars.
    static VERIFIER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const VK1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const VK2: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn clear_verifier_env() {
        for v in [
            "CSV_MINT_VERIFIER_KEY",
            "CSV_MINT_VERIFIER_KEY_APTOS",
            "CSV_MINT_VERIFIER_KEY_SUI",
            "CSV_MINT_VERIFIER_KEY_SOLANA",
            "CSV_MINT_VERIFIER_KEY_ETHEREUM",
        ] {
            // SAFETY: guarded by VERIFIER_ENV_LOCK; single-threaded within the test.
            unsafe { std::env::remove_var(v) };
        }
    }

    #[test]
    fn verifier_secrets_missing_resolves_empty() {
        let _g = VERIFIER_ENV_LOCK.lock().unwrap();
        clear_verifier_env();
        let (var, keys) = resolve_destination_verifier_secrets("aptos");
        assert_eq!(var, "CSV_MINT_VERIFIER_KEY_APTOS");
        assert!(
            keys.is_empty(),
            "no config must resolve to no keys (fail closed)"
        );
        clear_verifier_env();
    }

    #[test]
    fn verifier_secrets_default_applies_when_no_scoped_override() {
        let _g = VERIFIER_ENV_LOCK.lock().unwrap();
        clear_verifier_env();
        unsafe { std::env::set_var("CSV_MINT_VERIFIER_KEY", VK1) };
        let (_, keys) = resolve_destination_verifier_secrets("sui");
        assert_eq!(keys, vec![VK1.to_string()]);
        clear_verifier_env();
    }

    #[test]
    fn verifier_secrets_scoped_isolated_to_its_chain() {
        let _g = VERIFIER_ENV_LOCK.lock().unwrap();
        clear_verifier_env();
        unsafe {
            std::env::set_var("CSV_MINT_VERIFIER_KEY", VK1);
            std::env::set_var("CSV_MINT_VERIFIER_KEY_SOLANA", format!("{VK1},0x{VK2}"));
        }
        // Solana sees its two scoped keys (0x stripped)…
        let (_, sol) = resolve_destination_verifier_secrets("solana");
        assert_eq!(sol, vec![VK1.to_string(), VK2.to_string()]);
        // …while Aptos, with no scoped override, sees only the default. A key
        // configured for one destination is never reused for another.
        let (_, apt) = resolve_destination_verifier_secrets("aptos");
        assert_eq!(apt, vec![VK1.to_string()]);
        clear_verifier_env();
    }

    // ── Seal-reference parsing ──────────────────────────────────────────────

    #[test]
    fn parse_seal_ref_bitcoin_reverses_to_internal_byte_order() {
        // Display order in, internal (reversed) order pinned in the definition.
        let txid_display = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let def = parse_seal_ref(&format!("bitcoin:{txid_display}:7")).unwrap();
        match def {
            SealDefinition::Bitcoin { txid, vout } => {
                assert_eq!(vout, 7);
                let mut expected = hex::decode(txid_display).unwrap();
                expected.reverse();
                assert_eq!(txid, expected);
            }
            other => panic!("expected Bitcoin, got {other:?}"),
        }
    }

    #[test]
    fn parse_seal_ref_covers_all_chains() {
        assert!(matches!(
            parse_seal_ref(&format!("sui:{}:42", hex::encode([0xCDu8; 32]))).unwrap(),
            SealDefinition::Sui { version: 42, .. }
        ));
        assert!(matches!(
            parse_seal_ref(&format!(
                "aptos:{}:{}",
                hex::encode([0xEFu8; 32]),
                hex::encode([1u8, 2, 3])
            ))
            .unwrap(),
            SealDefinition::Aptos { .. }
        ));
        assert!(matches!(
            parse_seal_ref(&format!(
                "ethereum:{}:{}",
                hex::encode([0x11u8; 20]),
                hex::encode([0x22u8; 32])
            ))
            .unwrap(),
            SealDefinition::Ethereum { .. }
        ));
    }

    #[test]
    fn parse_seal_ref_rejects_malformed_and_unknown_chains() {
        assert!(parse_seal_ref("bitcoin:onlyonefield").is_err());
        assert!(parse_seal_ref("bitcoin::7").is_err()); // empty txid field
        assert!(parse_seal_ref("dogecoin:aa:0").is_err());
        assert!(parse_seal_ref(&format!("bitcoin:{}:notanumber", hex::encode([0u8; 32]))).is_err());
        // A 31-byte txid must be rejected by the definition constructor.
        assert!(parse_seal_ref(&format!("bitcoin:{}:0", hex::encode([0u8; 31]))).is_err());
    }

    // ── Schema encoding ─────────────────────────────────────────────────────

    #[test]
    fn encode_schema_id_accepts_label_and_hex() {
        assert_eq!(encode_schema_id("payment").unwrap(), b"payment".to_vec());
        assert_eq!(encode_schema_id("0xdead").unwrap(), vec![0xDE, 0xAD]);
        assert!(encode_schema_id("").is_err());
        assert!(encode_schema_id("0x").is_err());
        assert!(encode_schema_id("0xzz").is_err());
    }

    // ── Offline ownership verification ──────────────────────────────────────

    fn wallet_state() -> UnifiedStateManager {
        UnifiedStateManager::new("test-pass")
    }

    fn temp_state() -> (tempfile::TempDir, UnifiedStateManager) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = UnifiedStateManager::load_from(path.to_str().unwrap(), "test-pass").unwrap();
        (dir, state)
    }

    fn add_utxo(state: &mut UnifiedStateManager, txid_display: &str, vout: u32) {
        state.storage.wallet.utxos.push(UtxoRecord {
            txid: txid_display.to_string(),
            vout,
            value: 100_000,
            account: 0,
            index: 0,
            derivation_path: "m/86'/1'/0'/0/0".to_string(),
            script_pubkey: None,
        });
    }

    #[test]
    fn bitcoin_seal_is_controlled_only_when_utxo_is_held() {
        let txid_display = "aa".repeat(32);
        let def = parse_seal_ref(&format!("bitcoin:{txid_display}:3")).unwrap();

        // No matching UTXO → fail closed.
        let mut state = wallet_state();
        assert!(verify_seal_controlled(&def, &state).is_err());

        // Wrong vout → still fail closed.
        add_utxo(&mut state, &txid_display, 9);
        assert!(verify_seal_controlled(&def, &state).is_err());

        // Exact OutPoint held → controlled.
        add_utxo(&mut state, &txid_display, 3);
        assert!(verify_seal_controlled(&def, &state).is_ok());
    }

    #[test]
    fn aptos_seal_is_controlled_only_for_the_wallets_own_account() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut state = wallet_state();
        state.storage.wallet.mnemonic = Some(PHRASE.to_string());

        // Derive the wallet's real Aptos account address to build an owned seal.
        let identity = WalletIdentity::from_mnemonic(PHRASE).unwrap();
        let addr = identity.address(&Chain::new("aptos"), 0, 0).unwrap();
        let addr_hex = addr.trim_start_matches("0x");

        let owned =
            parse_seal_ref(&format!("aptos:{addr_hex}:{}", hex::encode(b"balance"))).unwrap();
        assert!(verify_seal_controlled(&owned, &state).is_ok());

        // A resource under a different account is not controlled.
        let foreign = parse_seal_ref(&format!(
            "aptos:{}:{}",
            hex::encode([0x99u8; 32]),
            hex::encode(b"balance")
        ))
        .unwrap();
        assert!(verify_seal_controlled(&foreign, &state).is_err());
    }

    #[test]
    fn sui_and_ethereum_ownership_fails_closed_offline() {
        let state = wallet_state();
        let sui = parse_seal_ref(&format!("sui:{}:1", hex::encode([0u8; 32]))).unwrap();
        let eth = parse_seal_ref(&format!(
            "ethereum:{}:{}",
            hex::encode([0u8; 20]),
            hex::encode([0u8; 32])
        ))
        .unwrap();
        assert!(verify_seal_controlled(&sui, &state).is_err());
        assert!(verify_seal_controlled(&eth, &state).is_err());
    }

    // ── Full invoice issuance (happy path) ──────────────────────────────────

    #[tokio::test]
    async fn cmd_invoice_emits_a_well_formed_invoice_for_an_owned_seal() {
        use csv_wire::Invoice;

        let txid_display = "bb".repeat(32);
        let mut state = wallet_state();
        add_utxo(&mut state, &txid_display, 1);

        let config = Config::default();
        cmd_invoice(
            "payment".to_string(),
            format!("bitcoin:{txid_display}:1"),
            &config,
            &state,
        )
        .await
        .expect("invoice for an owned Bitcoin seal should succeed");

        // Reconstruct the same invoice shape to prove it encodes through
        // csv-wire canonical CBOR and binds the nonce into its seal point.
        let def = parse_seal_ref(&format!("bitcoin:{txid_display}:1")).unwrap();
        let inv = Invoice::new(def, b"payment".to_vec(), 42).unwrap();
        assert!(!inv.canonical_cbor().unwrap().is_empty());
        assert!(!inv.canonical_id().unwrap().is_empty());
        assert_eq!(inv.bound_seal_point().unwrap().nonce, Some(42));
    }

    #[tokio::test]
    async fn cmd_invoice_rejects_an_unowned_seal() {
        let state = wallet_state(); // no UTXOs held
        let config = Config::default();
        let err = cmd_invoice(
            "payment".to_string(),
            format!("bitcoin:{}:0", "cc".repeat(32)),
            &config,
            &state,
        )
        .await
        .expect_err("invoice for an unowned seal must fail closed");
        assert!(
            err.to_string().contains("does not control"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn zk_proof_is_not_available_and_never_falls_back() {
        let err = ensure_proof_available(ProofMode::Zk)
            .expect_err("`--proof zk` must fail closed until the prover lands");
        let msg = err.to_string();
        // The error must be explicit and must not silently accept the request…
        assert!(
            msg.contains("not available"),
            "zk rejection should state it is not available: {msg}"
        );
        // …and must not imply an automatic downgrade to attestor.
        assert!(
            msg.contains("does not fall back"),
            "zk rejection must state there is no automatic fallback: {msg}"
        );
    }

    #[test]
    fn attestor_proof_is_available() {
        // The interim RFC §9 attestor path is the one available in M0.
        assert!(ensure_proof_available(ProofMode::Attestor).is_ok());
    }

    #[test]
    fn proof_mode_parses_from_cli_values_and_defaults_to_attestor() {
        // `--proof attestor` is the documented default and both values parse.
        assert_eq!(
            ProofMode::from_str("attestor", true).unwrap(),
            ProofMode::Attestor
        );
        assert_eq!(ProofMode::from_str("zk", true).unwrap(), ProofMode::Zk);
        assert!(ProofMode::from_str("groth16", true).is_err());
    }

    // Deterministic verifier key so tests can build the approved-signer set that
    // VERIFY-SIGNER-BINDING-001 now requires on the accept path.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// The approved verifier set matching `signed_consignment`'s signer: the raw
    /// 32-byte ed25519 public key.
    fn authorized() -> Vec<Vec<u8>> {
        vec![test_signing_key().verifying_key().to_bytes().to_vec()]
    }

    fn make_ed25519_signature_bytes(message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(message);
        let mut encoded = Vec::with_capacity(4 + 32 + 64);
        encoded.extend_from_slice(&32u32.to_le_bytes());
        encoded.extend_from_slice(&verifying_key.to_bytes());
        encoded.extend_from_slice(&signature.to_bytes());
        encoded
    }

    fn signed_consignment_from_source(nonce: u64, source_chain: &str) -> WireConsignment {
        let invoice = Invoice::new(
            SealDefinition::sui(vec![0xCD; 32], 7).unwrap(),
            vec![0xAA; 32],
            nonce,
        )
        .unwrap();
        let seal = invoice.bound_seal_point().unwrap();
        let root = Hash::zero();
        let signature = make_ed25519_signature_bytes(root.as_bytes());
        let proof_bytes = vec![0x44; 32];
        let bundle = ProofBundle::with_signature_scheme(
            SignatureScheme::Ed25519,
            DAGSegment::new(
                vec![DAGNode::new(
                    Hash::new([1u8; 32]),
                    vec![0x01, 0x02],
                    vec![signature.clone()],
                    vec![],
                    vec![],
                )],
                root,
            ),
            vec![signature],
            seal,
            // Anchor id must equal the Sanad id (the real adapter convention:
            // build_inclusion_proof sets anchor_id = transfer.sanad_id), so the
            // VERIFY-DOMAIN-SEPARATION-001 binding in the accept path holds. The
            // consignment's declared Sanad below is [0x55; 32].
            CommitAnchor::new(vec![0x55u8; 32], 100, proof_bytes.clone()).unwrap(),
            {
                let mut proof =
                    InclusionProof::new(proof_bytes, Hash::new([2u8; 32]), 100, 0).unwrap();
                proof.source = source_chain.to_string();
                proof
            },
            {
                let mut proof = FinalityProof::new(vec![0xAB; 16], 6, false).unwrap();
                proof.block_hash = Hash::new([2u8; 32]);
                proof.source = source_chain.to_string();
                proof
            },
        )
        .unwrap();
        WireConsignment::new(
            invoice,
            SanadIdWire {
                bytes: hex::encode([0x55u8; 32]),
            },
            bundle,
        )
    }

    fn signed_consignment(nonce: u64) -> WireConsignment {
        signed_consignment_from_source(nonce, "sui")
    }

    #[test]
    fn provenance_strength_warns_only_for_weak_source_to_strong_destination() {
        let solana = Chain::new("solana");
        let ethereum = Chain::new("ethereum");
        let aptos = Chain::new("aptos");
        let bitcoin = Chain::new("bitcoin");
        let sui = Chain::new("sui");

        let weak_to_strong = provenance_strength_signal(&solana, &sui)
            .expect("solana to sui must produce a receiver warning");
        assert_eq!(weak_to_strong.source_rank, 1);
        assert_eq!(weak_to_strong.destination_rank, 4);
        assert_eq!(weak_to_strong.provenance_gap, 3);
        assert!(weak_to_strong.warning.contains("Solana"));
        assert!(
            weak_to_strong
                .warning
                .contains("Destination strength does not upgrade")
        );
        assert!(weak_to_strong.warning.contains("deeper Solana finality"));

        assert!(provenance_strength_signal(&bitcoin, &ethereum).is_none());
        assert!(provenance_strength_signal(&bitcoin, &sui).is_none());
        assert!(provenance_strength_signal(&sui, &bitcoin).is_none());
        assert!(provenance_strength_signal(&aptos, &aptos).is_none());
    }

    #[test]
    fn accept_validator_records_provenance_strength_signal_for_weak_source() {
        let (_dir, mut state) = temp_state();
        let bytes = signed_consignment_from_source(6, "solana")
            .canonical_cbor()
            .unwrap();

        let accepted = validate_consignment_bytes(&bytes, &state, &authorized()).unwrap();
        let signal = accepted
            .provenance_strength
            .as_ref()
            .expect("solana source into sui destination must warn");
        assert_eq!(signal.source_chain.as_str(), "solana");
        assert_eq!(signal.destination_chain.as_str(), "sui");
        assert_eq!(signal.provenance_gap, 3);

        record_accepted_consignment(&accepted, &mut state).unwrap();
        let recorded = state.get_sanad(&accepted.sanad_id).unwrap();
        assert_eq!(recorded.provenance_strength.as_ref(), Some(signal));
    }

    #[test]
    fn accept_validator_does_not_record_provenance_signal_for_equal_rank() {
        let (_dir, state) = temp_state();
        let bytes = signed_consignment_from_source(7, "bitcoin")
            .canonical_cbor()
            .unwrap();

        let accepted = validate_consignment_bytes(&bytes, &state, &authorized()).unwrap();
        assert!(accepted.provenance_strength.is_none());
    }

    #[test]
    fn accept_validator_rejects_missing_source_provenance() {
        let (_dir, state) = temp_state();
        let consignment = signed_consignment_from_source(8, "dogecoin");

        let err = validate_consignment_bytes(
            &consignment.canonical_cbor().unwrap(),
            &state,
            &authorized(),
        )
        .expect_err("unrecognized source provenance must not suppress warnings");
        assert!(err.to_string().contains("source-chain provenance"));
    }

    #[test]
    fn accept_validator_accepts_signed_canonical_consignment() {
        let (_dir, state) = temp_state();
        let consignment = signed_consignment(1);
        let bytes = consignment.canonical_cbor().unwrap();

        let accepted = validate_consignment_bytes(&bytes, &state, &authorized()).unwrap();

        assert_eq!(accepted.sanad_id, hex::encode([0x55u8; 32]));
        assert_eq!(accepted.dest_chain.as_str(), "sui");
        assert_eq!(accepted.anchor_height, 100);
        assert!(matches!(
            accepted.verification_level,
            VerificationLevel::FullyVerified
        ));
    }

    #[test]
    fn accept_records_wallet_ownership_after_validation() {
        let (_dir, mut state) = temp_state();
        let bytes = signed_consignment(2).canonical_cbor().unwrap();
        let accepted = validate_consignment_bytes(&bytes, &state, &authorized()).unwrap();

        record_accepted_consignment(&accepted, &mut state).unwrap();

        assert!(state.get_sanad(&accepted.sanad_id).is_some());
        assert!(state.storage.seals.iter().any(|s| {
            s.seal_ref == accepted.seal_ref
                && s.sanad_id.as_deref() == Some(accepted.sanad_id.as_str())
                && !s.consumed
        }));
        assert!(validate_consignment_bytes(&bytes, &state, &authorized()).is_err());
    }

    #[test]
    fn accept_rejects_tampered_consignment_signature() {
        let (_dir, state) = temp_state();
        let mut consignment = signed_consignment(3);
        let last = consignment.proof_bundle.signatures[0].len() - 1;
        consignment.proof_bundle.signatures[0][last] ^= 0x01;

        let err = validate_consignment_bytes(
            &consignment.canonical_cbor().unwrap(),
            &state,
            &authorized(),
        )
        .expect_err("tampered signature must fail closed");
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn accept_rejects_replayed_invoice_nonce_seal() {
        let (_dir, mut state) = temp_state();
        let consignment = signed_consignment(4);
        let bytes = consignment.canonical_cbor().unwrap();
        let accepted = validate_consignment_bytes(&bytes, &state, &authorized()).unwrap();
        state.add_seal(SealRecord {
            seal_ref: accepted.seal_ref.clone(),
            chain: accepted.dest_chain.clone(),
            value: 0,
            consumed: false,
            status: SealStatus::Active,
            created_at: 1,
            sanad_id: Some("other".to_string()),
            content: None,
            proof_ref: None,
        });

        let err = validate_consignment_bytes(&bytes, &state, &authorized())
            .expect_err("replayed invoice-bound seal must fail closed");
        assert!(err.to_string().contains("Replay rejected"));
    }

    #[test]
    fn accept_rejects_invalid_anchor_binding() {
        let (_dir, state) = temp_state();
        let mut consignment = signed_consignment(5);
        consignment.proof_bundle.anchor_ref.block_height = 101;

        let err = validate_consignment_bytes(
            &consignment.canonical_cbor().unwrap(),
            &state,
            &authorized(),
        )
        .expect_err("anchor mismatch must fail closed");
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn accept_rejects_legacy_json_structural_input() {
        let (_dir, state) = temp_state();
        let json = br#"{"version":1,"proof_bundle":{}}"#;

        let err = validate_consignment_bytes(json, &state, &authorized())
            .expect_err("legacy JSON consignment input must not be accepted");
        assert!(
            err.to_string()
                .contains("Invalid canonical consignment CBOR")
        );
    }
}
