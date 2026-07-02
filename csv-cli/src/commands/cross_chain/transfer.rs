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
//! The `resume` subcommand advances an already-locked transfer without re-locking.

use std::time::{Duration, Instant};

use anyhow::Result;

use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_sdk::CsvClient;
use csv_sdk::transfers::{TransferManager, TransferOutcome, TransferReceipt as SdkReceipt};

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferRecord, TransferStatus, UnifiedStateManager};

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

/// Build a runtime-backed CSV client for the given source/destination chains.
///
/// Shared by both `transfer` (fresh lock) and `resume` (advance existing lock),
/// so the adapter/wallet wiring can never drift between the two entry points.
async fn build_client(
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

/// Execute (or begin) a cross-chain transfer.
pub async fn cmd_transfer(
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

    output::header(&format!(
        "Cross-Chain Transfer: {:?} → {:?}",
        from_chain, to_chain
    ));

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

    drive(&manager, outcome, sanad, from, to, &opts, state).await
}

/// Resume an already-locked transfer that is awaiting finality (never re-locks).
pub async fn cmd_resume(
    transfer_id: String,
    opts: WaitOpts,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let record = state
        .get_transfer(&transfer_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Transfer {} not found in local state", transfer_id))?;

    output::header(&format!("Resume Cross-Chain Transfer: {}", transfer_id));

    let from = record.source_chain.clone();
    let to = record.dest_chain.clone();
    let sanad_id = SanadId::parse_hex(&record.sanad_id)
        .map_err(|e| anyhow::anyhow!("Invalid stored Sanad ID: {}", e))?;

    let client = build_client(&from, &to, None, config, state).await?;
    let manager = client.transfers();

    let from_id = to_protocol_chain(from.clone());
    let to_id = to_protocol_chain(to.clone());
    let outcome = manager
        .resume(&transfer_id, sanad_id.clone(), from_id, to_id)
        .await
        .map_err(|e| anyhow::anyhow!("Resume failed: {}", e))?;

    drive(&manager, outcome, sanad_id, from, to, &opts, state).await
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
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let started = Instant::now();
    let mut outcome = first;

    loop {
        match outcome {
            TransferOutcome::Completed(receipt) => {
                record_completed(state, &receipt, &from, &to, &sanad_id);
                output::success(&format!(
                    "Transfer {} completed. Sanad locked on source chain and minted on destination chain.",
                    receipt.transfer_id
                ));
                output::kv("Transfer ID", &receipt.transfer_id);
                output::kv("Replay ID", &receipt.replay_id.to_string());
                output::kv("Source Chain", &receipt.source_chain.to_string());
                output::kv("Destination Chain", &receipt.destination_chain.to_string());
                output::kv("Lock Tx Hash", &receipt.lock_tx_hash);
                output::kv("Mint Tx Hash", &receipt.mint_tx_hash);
                return Ok(());
            }
            TransferOutcome::Pending {
                transfer_id,
                confirmations,
                required,
            } => {
                record_pending(state, &transfer_id, &from, &to, &sanad_id);

                if !opts.wait {
                    output::info(&format!(
                        "Transfer {} locked — awaiting finality ({}/{} confirmations).",
                        transfer_id, confirmations, required
                    ));
                    output::kv("Transfer ID", &transfer_id);
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
                    "Awaiting finality: {}/{} confirmations. Re-checking in {}s…",
                    confirmations,
                    required,
                    opts.poll_interval.as_secs()
                ));
                tokio::time::sleep(opts.poll_interval).await;

                let from_id = to_protocol_chain(from.clone());
                let to_id = to_protocol_chain(to.clone());
                outcome = manager
                    .resume(&transfer_id, sanad_id.clone(), from_id, to_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("Resume failed: {}", e))?;
            }
        }
    }
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

/// Persist a completed transfer to the local display cache and consume the Sanad.
fn record_completed(
    state: &mut UnifiedStateManager,
    receipt: &SdkReceipt,
    from: &Chain,
    to: &Chain,
    sanad_id: &SanadId,
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
        destination_address: None,
        source_tx_hash: Some(receipt.lock_tx_hash.clone()),
        source_fee: None,
        dest_tx_hash: Some(receipt.mint_tx_hash.clone()),
        dest_fee: None,
        destination_contract: None,
        proof: None,
        status: TransferStatus::Completed,
        created_at: now,
        completed_at: Some(now),
    });

    // The runtime only reports Completed after the destination mint confirms and
    // the replay entry is promoted to Consumed, so it is safe to mark the source
    // Sanad consumed in the local display cache.
    if let Err(e) = state.consume_sanad(&sanad_hex) {
        log::warn!(
            "Failed to mark source Sanad as consumed in local store: {}",
            e
        );
    }
}

/// Persist a locked-but-not-yet-final transfer so it can be resumed later.
fn record_pending(
    state: &mut UnifiedStateManager,
    transfer_id: &str,
    from: &Chain,
    to: &Chain,
    sanad_id: &SanadId,
) {
    let now = chrono::Utc::now().timestamp() as u64;
    let sender = state.get_address(from).map(|s| s.to_string());
    let sanad_hex = hex::encode(sanad_id.as_bytes());

    state.add_transfer(TransferRecord {
        id: transfer_id.to_string(),
        source_chain: from.clone(),
        dest_chain: to.clone(),
        sanad_id: sanad_hex,
        sender_address: sender,
        destination_address: None,
        source_tx_hash: None,
        source_fee: None,
        dest_tx_hash: None,
        dest_fee: None,
        destination_contract: None,
        proof: None,
        status: TransferStatus::Locked,
        created_at: now,
        completed_at: None,
    });
}
