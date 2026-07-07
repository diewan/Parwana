//! Sanad lifecycle commands

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Subcommand;
use sha2::Digest;

use csv_content::ContentTree;
use csv_hash::ChainId;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;

use crate::config::{Chain, Config, Network};
use crate::output;
use crate::state::{
    SanadRecord, SanadStatus, TransferRecord, TransferStatus, UnifiedStateManager, UtxoRecord,
};

use crate::wallet_identity::WalletIdentity;
use csv_store::state::{CanonicalSanadState, SanadLifecycleState};

#[derive(Subcommand)]
pub enum SanadAction {
    /// Create a new Sanad
    Create {
        /// Chain name
        #[arg(short, long, value_enum)]
        chain: Chain,
        /// Value (chain-specific: sats for Bitcoin, etc.)
        #[arg(short = 'V', long)]
        value: Option<u64>,
        /// Account index for HD wallet derivation (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Address index for HD wallet derivation (default: 0)
        #[arg(long, default_value = "0")]
        index: u32,
        /// Skip publishing the commitment (for testing lock functionality)
        #[arg(long)]
        skip_publish: bool,
        /// Schema ID or file path for content descriptor
        #[arg(long)]
        schema: Option<String>,
        /// Payload file path (JSON or binary)
        #[arg(long)]
        payload: Option<String>,
        /// Content root hash (hex) for content-addressed data
        #[arg(long)]
        content_root: Option<String>,
        /// Attachment file paths (comma-separated)
        #[arg(long)]
        attachments: Option<String>,
        /// Disclosure policy file path or parameters
        #[arg(long)]
        disclosure_policy: Option<String>,
        /// Proof policy file path or parameters
        #[arg(long)]
        proof_policy: Option<String>,
        /// Schema hash (hex) for content descriptor (legacy, use --schema instead)
        #[arg(long)]
        schema_hash: Option<String>,
        /// Disclosure policy hash (hex) (legacy, use --disclosure-policy instead)
        #[arg(long)]
        disclosure_policy_hash: Option<String>,
        /// Proof policy hash (hex) (legacy, use --proof-policy instead)
        #[arg(long)]
        proof_policy_hash: Option<String>,
    },
    /// Show Sanad details
    Show {
        /// Sanad ID (hex)
        sanad_id: String,
    },
    /// List all tracked Sanads
    List {
        /// Filter by chain
        #[arg(short, long, value_enum)]
        chain: Option<Chain>,
        /// Update local status by querying on-chain state
        #[arg(long)]
        update: bool,
    },
    /// Transfer a Sanad to a new owner
    Transfer {
        /// Sanad ID (hex)
        sanad_id: String,
        /// New owner address
        to: String,
    },
    /// Consume a Sanad (seal consumption)
    Consume {
        /// Chain name
        #[arg(short, long, value_enum)]
        chain: Chain,
        /// Sanad ID (hex)
        sanad_id: String,
    },
    /// Remove a Sanad from local tracking
    Remove {
        /// Sanad ID (hex) to remove
        #[arg(required = false)]
        sanad_id: Option<String>,
        /// Remove all tracked Sanads
        #[arg(long)]
        all: bool,
    },
    /// Show canonical on-chain state of a Sanad
    State {
        /// Chain name
        #[arg(short, long, value_enum)]
        chain: Chain,
        /// Sanad ID (hex)
        sanad_id: String,
    },
    /// Show full lifecycle trace of a Sanad
    Trace {
        /// Chain name
        #[arg(short, long, value_enum)]
        chain: Chain,
        /// Sanad ID (hex)
        sanad_id: String,
    },
}

pub async fn execute(
    action: SanadAction,
    config: &Config,
    state: &mut UnifiedStateManager,
    canonical: bool,
) -> Result<()> {
    match action {
        SanadAction::Create {
            chain,
            value,
            account,
            index,
            skip_publish,
            schema,
            payload,
            content_root,
            attachments,
            disclosure_policy,
            proof_policy,
            schema_hash,
            disclosure_policy_hash,
            proof_policy_hash,
        } => {
            cmd_create(
                chain,
                value,
                account,
                index,
                skip_publish,
                schema,
                payload,
                content_root,
                attachments,
                disclosure_policy,
                proof_policy,
                schema_hash,
                disclosure_policy_hash,
                proof_policy_hash,
                canonical,
                config,
                state,
            )
            .await
        }
        SanadAction::Show { sanad_id } => cmd_show(sanad_id, state),
        SanadAction::List { chain, update } => cmd_list(chain, update, config, state).await,
        SanadAction::Transfer { sanad_id, to } => cmd_transfer(sanad_id, to, state),
        SanadAction::Consume { chain, sanad_id } => {
            cmd_consume(chain, sanad_id, config, state).await
        }
        SanadAction::Remove { sanad_id, all } => cmd_remove(sanad_id, all, state),
        SanadAction::State { chain, sanad_id } => cmd_state(chain, sanad_id, config, state).await,
        SanadAction::Trace { chain, sanad_id } => cmd_trace(chain, sanad_id, config, state).await,
    }
}

/// Parse an optional `0x`-prefixed (or bare) 32-byte hex string into a `Hash`.
/// Returns `Ok(None)` when the input is absent, and a typed error when the hex
/// is malformed or not exactly 32 bytes.
fn parse_opt_hash(value: &Option<String>, label: &str) -> Result<Option<Hash>> {
    let Some(hash_str) = value else {
        return Ok(None);
    };
    let bytes = hex::decode(hash_str.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid {} hex: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("{} must be 32 bytes", label));
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    Ok(Some(Hash::new(hash_bytes)))
}

fn default_content_hash(domain: &str) -> Hash {
    Hash::sha256(domain.as_bytes())
}

async fn cmd_create(
    chain: Chain,
    value: Option<u64>,
    account: u32,
    index: u32,
    skip_publish: bool,
    schema: Option<String>,
    payload: Option<String>,
    content_root: Option<String>,
    attachments: Option<String>,
    disclosure_policy: Option<String>,
    proof_policy: Option<String>,
    schema_hash: Option<String>,
    disclosure_policy_hash: Option<String>,
    proof_policy_hash: Option<String>,
    _canonical: bool,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Creating Sanad on {}", chain));

    // Run readiness check before proceeding (CHAIN-READINESS-001)
    output::info("Checking chain readiness...");
    let chain_config = config.chain(&chain)?;

    use csv_hash::ChainId;
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;

    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(chain.as_str());
    let identity = WalletIdentity::from_state(state)?;

    // Convert CLI config to SDK config format
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.network = match config.chain(&chain)?.network {
        crate::config::Network::Test => csv_sdk::config::Network::Testnet,
        crate::config::Network::Main => csv_sdk::config::Network::Mainnet,
        crate::config::Network::Dev => csv_sdk::config::Network::Devnet,
    };

    // Convert chain config to SDK format
    let sdk_chain_config = csv_sdk::config::ChainConfig {
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
        xpub: config.wallets.get(&chain).and_then(|w| w.xpub.clone()),
        seed: (chain.as_str() == "bitcoin").then(|| identity.bitcoin_seed_hex()),
        contract_address: chain_config.contract_address.clone(),
        program_id: chain_config.program_id.clone(),
        account,
        index,
        utxos: vec![],
        sanad_seals: vec![],
    };
    sdk_config
        .chains
        .insert(chain.as_str().to_string(), sdk_chain_config);

    // Build CSV client for readiness check
    let mut builder = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(StoreBackend::InMemory);

    builder = builder.with_private_keys(identity.signing_map(&[(&chain, account, index)], state)?);

    let client = builder
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client for readiness check: {}", e))?;

    let runtime = client.chain_runtime();

    // Check readiness via the chain backend
    let readiness = runtime
        .check_readiness(core_chain.clone(), account, index)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check chain readiness: {}", e))?;

    // Abort if chain is not ready for write operations
    if !readiness.signer_configured {
        output::error("Chain readiness check failed: Signer not configured");
        output::info("Use 'csv wallet init' or 'csv wallet import' to configure a signer");
        return Err(anyhow::anyhow!(
            "Cannot create sanad: signer not configured"
        ));
    }

    if !readiness.write_capable {
        output::error("Chain readiness check failed: Write capability not available");
        return Err(anyhow::anyhow!(
            "Cannot create sanad: write capability not available"
        ));
    }

    if !readiness.sanad_create_supported {
        output::error("Chain readiness check failed: Sanad creation not supported on this chain");
        return Err(anyhow::anyhow!(
            "Cannot create sanad: sanad creation not supported"
        ));
    }

    // For contract chains (Ethereum, Solana, Sui, Aptos), check contract deployment
    let is_contract_chain = matches!(chain.as_str(), "ethereum" | "solana" | "sui" | "aptos");
    if is_contract_chain && !readiness.contract_configured {
        output::error("Chain readiness check failed: Contract/program not deployed or configured");
        output::info(&format!(
            "Use 'csv chain set-contract --chain {} <address>' to configure the contract",
            chain
        ));
        return Err(anyhow::anyhow!(
            "Cannot create sanad: contract/program not configured"
        ));
    }

    output::success("Chain readiness check passed");

    // Handle content descriptor parameters (B-013)
    // Parse schema file, load payload, process attachments
    let (schema_hash_final, payload_hash_final, attachment_root_final) = if schema.is_some()
        || payload.is_some()
        || attachments.is_some()
    {
        output::info("Processing content descriptor parameters (B-013)");

        // Parse schema file if provided
        let schema_hash_val = if let Some(ref schema_path) = schema {
            output::kv("Schema file", schema_path);

            // Check if it's a file path or a direct hex hash
            if schema_path.starts_with("0x") || schema_path.len() == 64 {
                // Direct hex hash
                let bytes = hex::decode(schema_path.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("Invalid schema hash hex: {}", e))?;
                if bytes.len() != 32 {
                    return Err(anyhow::anyhow!("Schema hash must be 32 bytes"));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes);
                Some(Hash::new(hash_bytes))
            } else {
                // File path - read and parse JSON schema
                let schema_content = std::fs::read_to_string(schema_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read schema file: {}", e))?;

                // Parse JSON schema to extract schema_hash
                let schema_json: serde_json::Value = serde_json::from_str(&schema_content)
                    .map_err(|e| anyhow::anyhow!("Failed to parse schema JSON: {}", e))?;

                let schema_hash_str = schema_json
                    .get("schema_hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Schema file missing 'schema_hash' field"))?;

                let bytes = hex::decode(schema_hash_str.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("Invalid schema_hash in file: {}", e))?;
                if bytes.len() != 32 {
                    return Err(anyhow::anyhow!("Schema hash must be 32 bytes"));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes);

                output::kv("Schema hash", schema_hash_str);
                Some(Hash::new(hash_bytes))
            }
        } else {
            None
        };

        // Load payload file if provided
        let payload_hash_val = if let Some(ref payload_path) = payload {
            output::kv("Payload file", payload_path);

            // Read payload file
            let payload_bytes = std::fs::read(payload_path)
                .map_err(|e| anyhow::anyhow!("Failed to read payload file: {}", e))?;

            // Check if it's JSON or binary
            if payload_path.ends_with(".json") {
                // Validate JSON
                let _payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to parse payload JSON: {}", e))?;
            }

            // Compute SHA256 hash of payload
            let mut hasher = sha2::Sha256::new();
            hasher.update(&payload_bytes);
            let hash_bytes = hasher.finalize();

            let hash_hex = hex::encode(&hash_bytes);
            output::kv("Payload hash", &hash_hex);
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_bytes);
            Some(Hash::new(hash_array))
        } else {
            None
        };

        // Process attachments if provided
        let attachment_root_val = if let Some(ref attachments_str) = attachments {
            output::kv("Attachments", attachments_str);

            // Split comma-separated file paths
            let attachment_paths: Vec<&str> = attachments_str
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            if !attachment_paths.is_empty() {
                // Compute Merkle root of attachment hashes
                let mut attachment_hashes = Vec::new();

                for (i, attachment_path) in attachment_paths.iter().enumerate() {
                    output::info(&format!(
                        "Processing attachment {}/{}: {}",
                        i + 1,
                        attachment_paths.len(),
                        attachment_path
                    ));

                    // Read attachment file
                    let attachment_bytes = std::fs::read(attachment_path).map_err(|e| {
                        anyhow::anyhow!("Failed to read attachment file {}: {}", attachment_path, e)
                    })?;

                    // Compute SHA256 hash
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&attachment_bytes);
                    let hash_bytes = hasher.finalize();
                    attachment_hashes.push(hash_bytes);

                    output::kv(
                        &format!("Attachment {} hash", i + 1),
                        &hex::encode(&hash_bytes),
                    );
                }

                // Compute Merkle root using csv-content ContentTree
                let leaf_data: Vec<Vec<u8>> =
                    attachment_hashes.iter().map(|h| h.to_vec()).collect();
                let tree = ContentTree::from_leaves(leaf_data);
                let root = tree.root_hash;

                let root_hex = hex::encode(&root);
                output::kv("Attachment root", &root_hex);
                Some(root)
            } else {
                None
            }
        } else {
            None
        };

        // Parse disclosure policy if provided
        if let Some(ref disclosure_policy_path) = disclosure_policy {
            output::kv("Disclosure policy", disclosure_policy_path);
            return Err(anyhow::anyhow!(
                "Disclosure policy parsing is not yet implemented. Policy file: {}. \
                 This feature requires Phase 5 policy engine integration.",
                disclosure_policy_path
            ));
        }

        // Parse proof policy if provided
        if let Some(ref proof_policy_path) = proof_policy {
            output::kv("Proof policy", proof_policy_path);
            return Err(anyhow::anyhow!(
                "Proof policy parsing is not yet implemented. Policy file: {}. \
                 This feature requires Phase 5 policy engine integration.",
                proof_policy_path
            ));
        }

        (schema_hash_val, payload_hash_val, attachment_root_val)
    } else {
        (None, None, None)
    };

    // Show derivation parameters for Bitcoin
    if chain.as_str() == "bitcoin" {
        output::kv("Account", &account.to_string());
        output::kv("Index", &index.to_string());
        output::kv(
            "Derivation Path",
            &format!("m/86'/1'/{}'/0/{}", account, index),
        );

        // Derive and show the funding address using centralized identity resolver
        if state.storage.wallet.mnemonic.is_some() {
            let address = identity.address(&chain, account, index)?;

            output::kv("Funding Address", &address);
            output::info("Make sure this address has UTXOs before creating a sanad.");
        }
    }

    // Check signer readiness for Sui before proceeding
    if chain.as_str() == "sui" {
        // Verify wallet mnemonic is available for signer derivation
        if state.storage.wallet.mnemonic.is_none() {
            return Err(anyhow::anyhow!(
                "Sui signer not configured. Initialize or import a wallet first using 'csv wallet init' or 'csv wallet import'."
            ));
        }

        // Verify wallet has mnemonic configured for Sui signer derivation
        if state.storage.wallet.mnemonic.is_none() {
            output::warn("Wallet mnemonic not configured");
            output::info("The signer will be derived from the wallet mnemonic");
        }

        output::info("Sui signer will be derived from wallet mnemonic");
    }

    // For Bitcoin, always refresh UTXOs from chain before creating a sanad
    let bitcoin_utxos: Option<Vec<(String, u32, u64, Option<String>)>> =
        if chain.as_str() == "bitcoin" {
            // Derive the expected address for this account/index using centralized identity resolver
            let seed_array = *identity.seed();
            let chain_id = csv_hash::ChainId::new("bitcoin");
            let expected_address = identity.address(&chain, account, index)?;

            output::kv("Expected Address", &expected_address);

            // Address→UTXO scanning is a REST/esplora capability. Use the
            // explicitly-configured indexer_url; fall back to rpc_url only when no
            // indexer is set (correct when rpc_url is itself a REST endpoint). A
            // JSON-RPC rpc_url with no indexer will fail closed with a clear error
            // rather than being silently rerouted to a public indexer.
            let chain_cfg = config.chain(&chain)?;
            let scan_url = chain_cfg
                .indexer_url
                .clone()
                .unwrap_or_else(|| chain_cfg.rpc_url.clone());
            // Explicit indexer transport ("esplora" | "blockbook"); None = default.
            let indexer_kind = chain_cfg.indexer_backend.clone();

            // Initialize wallet factory before UTXO scan
            let _factory = csv_coordinator::init_wallet_factory();

            // Scan for UTXOs using wallet operations from csv-coordinator
            output::info("Scanning for UTXOs...");
            let wallet_ops = csv_coordinator::get_wallet_operations(&chain_id);
            let scanned_utxos = if let Some(ops) = wallet_ops {
                ops.scan_utxos(
                    &seed_array,
                    account,
                    index,
                    &scan_url,
                    indexer_kind.as_deref(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to scan UTXOs: {}", e))?
            } else {
                output::warning("Wallet operations not available, skipping UTXO scan");
                Vec::new()
            };

            if scanned_utxos.is_empty() {
                output::warning(
                    "No UTXOs found for this address. Make sure the address has been funded.",
                );
                output::info("You can fund the address using: ");
                output::info(&format!("  {}", expected_address));
            } else {
                output::kv("Found UTXOs", &scanned_utxos.len().to_string());
                for (i, utxo) in scanned_utxos.iter().enumerate() {
                    output::info(&format!(
                        "  UTXO {}: {}:{} ({} sats)",
                        i + 1,
                        &utxo.0[..16],
                        utxo.1,
                        utxo.2
                    ));
                }
            }

            // Clear old UTXOs for this account and add new ones
            state.storage.wallet.utxos.retain(|u| u.account != account);
            for utxo in &scanned_utxos {
                state.storage.wallet.utxos.push(UtxoRecord {
                    txid: utxo.0.clone(),
                    vout: utxo.1,
                    value: utxo.2,
                    account,
                    index,
                    derivation_path: format!("m/86'/1'/{}'/0/{}", account, index),
                    script_pubkey: utxo.3.clone(),
                });
            }
            state.save()?;

            Some(scanned_utxos)
        } else {
            None
        };

    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(chain.as_str());

    // Convert CLI config to SDK config format
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.network = match config.chain(&chain)?.network {
        Network::Test => csv_sdk::config::Network::Testnet,
        Network::Main => csv_sdk::config::Network::Mainnet,
        Network::Dev => csv_sdk::config::Network::Devnet,
    };

    // Convert chain config to SDK format
    let chain_cfg = config.chain(&chain)?;

    // Derive seed for SDK config (Bitcoin needs 64-byte BIP-39 seed in config)
    let seed_array = *identity.seed();
    let seed_hex = identity.bitcoin_seed_hex();

    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            // Carry the explicit REST indexer selection through to the SDK so the
            // runtime adapter scans/queries via the right transport (e.g. Alchemy
            // Blockbook) instead of appending esplora paths to a JSON-RPC URL.
            indexer_url: chain_cfg.indexer_url.clone(),
            indexer_backend: chain_cfg.indexer_backend.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(&chain).and_then(|w| w.xpub.clone()),
        seed: if chain.as_str() == "bitcoin" {
            Some(seed_hex.clone())
        } else {
            None
        },
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account,
        index,
        utxos: bitcoin_utxos
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(
                |(txid, vout, value, scriptpubkey_hex): (String, u32, u64, Option<String>)| {
                    // Pass txid as-is from blockchain scan (display format)
                    // Bitcoin adapter's from_config loads UTXOs in display format
                    csv_sdk::config::UtxoConfig {
                        txid: txid.clone(),
                        vout,
                        value,
                        account,
                        index,
                        script_pubkey: scriptpubkey_hex,
                    }
                },
            )
            .collect(),
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
    sdk_config
        .chains
        .insert(chain.as_str().to_string(), sdk_chain_config);

    // Extract UTXOs from SDK config before building client (config is moved)
    let sdk_utxos = sdk_config
        .chains
        .get(chain.as_str())
        .and_then(|c| Some(c.utxos.clone()))
        .unwrap_or_default();

    let private_keys = identity.signing_map(&[(&chain, account, index)], state)?;

    // Build CSV client with the requested chain enabled
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_private_keys(private_keys)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    // Note: SDK adapters are automatically created via bitcoin_from_config during client build
    // Do NOT call init_adapters here as it has been removed from SDK

    // Validate UTXOs via runtime before proceeding (Bitcoin only)
    // Skip validation if wallet operations weren't available during scan (adapter will fetch from RPC)
    if chain.as_str() == "bitcoin" && !sdk_utxos.is_empty() {
        output::info("Validating UTXOs via runtime...");
        let runtime = client.chain_runtime();

        // Validate each UTXO is still unspent on-chain
        let mut validated_utxos = Vec::new();
        for utxo_config in &sdk_utxos {
            // Use runtime to check transaction status
            match runtime
                .get_transaction(core_chain.clone(), &utxo_config.txid)
                .await
            {
                Ok(tx_info) => {
                    // Check if transaction is confirmed and UTXO is unspent
                    match tx_info.status {
                        csv_protocol::chain_adapter_traits::TransactionStatus::Confirmed {
                            ..
                        } => {
                            output::info(&format!(
                                "  UTXO {}:{} validated on-chain",
                                &utxo_config.txid[..16],
                                utxo_config.vout
                            ));
                            validated_utxos.push(utxo_config.clone());
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Pending => {
                            output::warning(&format!(
                                "  UTXO {}:{} is pending, skipping",
                                &utxo_config.txid[..16],
                                utxo_config.vout
                            ));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Failed {
                            reason,
                        } => {
                            output::warning(&format!(
                                "  UTXO {}:{} failed: {}, skipping",
                                &utxo_config.txid[..16],
                                utxo_config.vout,
                                reason
                            ));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Dropped => {
                            output::warning(&format!(
                                "  UTXO {}:{} was dropped, skipping",
                                &utxo_config.txid[..16],
                                utxo_config.vout
                            ));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Unknown => {
                            output::warning(&format!(
                                "  UTXO {}:{} has unknown status, skipping",
                                &utxo_config.txid[..16],
                                utxo_config.vout
                            ));
                        }
                    }
                }
                Err(e) => {
                    // Fail closed if RPC is unavailable - this is a security requirement
                    return Err(anyhow::anyhow!(
                        "Failed to validate UTXO {}:{} via runtime: {}. RPC or validation support unavailable - cannot proceed without on-chain validation.",
                        &utxo_config.txid[..16],
                        utxo_config.vout,
                        e
                    ));
                }
            }
        }

        if validated_utxos.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid UTXOs after runtime validation. Ensure RPC is configured and UTXOs are unspent."
            ));
        }

        output::kv("Validated UTXOs", &validated_utxos.len().to_string());
    } else if chain.as_str() == "bitcoin" {
        output::info("Skipping CLI-level UTXO validation (Bitcoin adapter will fetch from RPC)");
    }

    // Generate a commitment for the sanad
    let commitment_bytes: [u8; 32] = {
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(b"commitment-");
        hasher.update(chain.to_string().as_bytes());
        hasher.update(value.unwrap_or(0).to_le_bytes());
        if let Some(nanos) = chrono::Utc::now().timestamp_nanos_opt() {
            hasher.update(nanos.to_le_bytes());
        }
        // Add random nonce to guarantee uniqueness even for rapid successive calls
        let mut nonce = [0u8; 8];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
        hasher.update(nonce);
        hasher.finalize().into()
    };
    let commitment = Hash::new(commitment_bytes);

    let runtime = client.chain_runtime();

    // ────────────────────────────────────────────────────────────────────
    // Resolve the content descriptor and derive the canonical sanad_id BEFORE
    // publishing anything. Two reasons this must happen pre-publish:
    //   1. On-chain lifecycle state is keyed by the canonical sanad_id
    //      (e.g. Ethereum `create_seal(commitment, sanad_id)`), so we need the
    //      id in hand to pass down into publish_seal.
    //   2. A missing required descriptor field must fail closed *before* we
    //      broadcast/spend anything, not after — otherwise we burn gas/an anchor
    //      and then abort (SANAD-CREATE-001).
    // ────────────────────────────────────────────────────────────────────

    // Derive owner address for ownership proof / descriptor request.
    let owner_address = identity.address(&chain, account, index)?;

    // Parse content descriptor hashes from hex strings (legacy parameters, take
    // precedence over file-parsed values).
    let schema_hash_legacy = parse_opt_hash(&schema_hash, "schema hash")?;
    let content_root_parsed = parse_opt_hash(&content_root, "content root")?;
    let disclosure_policy_hash_parsed =
        parse_opt_hash(&disclosure_policy_hash, "disclosure policy hash")?;
    let proof_policy_hash_parsed = parse_opt_hash(&proof_policy_hash, "proof policy hash")?;

    // Resolve each required descriptor field. The simple CLI create path uses
    // deterministic, non-zero default hashes for omitted content metadata so
    // `csv sanad create --chain <chain> --value <n>` creates a real published
    // Sanad without requiring hidden descriptor flags. Explicit user-provided
    // hashes always take precedence, and the SDK still fails closed if any
    // required field reaches it as `None`.
    let content_descriptor = csv_sdk::sanads::ContentDescriptorInput {
        schema_id: None,
        schema_hash: schema_hash_legacy
            .or(schema_hash_final)
            .or_else(|| Some(default_content_hash("csv.sanad.default.schema.v1"))),
        payload_codec: None,
        payload_hash: payload_hash_final
            .or_else(|| Some(default_content_hash("csv.sanad.default.payload.v1"))),
        content_root: content_root_parsed,
        attachment_root: attachment_root_final,
        disclosure_policy_hash: disclosure_policy_hash_parsed
            .or_else(|| Some(default_content_hash("csv.sanad.default.disclosure.v1"))),
        proof_policy_hash: proof_policy_hash_parsed
            .or_else(|| Some(default_content_hash("csv.sanad.default.proof.v1"))),
    };

    let publish_policy = if skip_publish {
        csv_sdk::sanads::PublishPolicy::DraftOnly
    } else {
        csv_sdk::sanads::PublishPolicy::Publish
    };

    // Build the typed creation request. `funding_selector` is not consumed by
    // the finalize/draft paths (funding/publication is driven imperatively
    // below), so we set it to Automatic here where the selected UTXO is not yet
    // known.
    let create_request = csv_sdk::sanads::CreateSanadRequest {
        chain: core_chain.clone(),
        owner: owner_address.as_bytes().to_vec(),
        value,
        content_descriptor,
        funding_selector: csv_sdk::sanads::FundingSelector::Automatic,
        publish_policy,
    };

    // Fail closed here (before publishing/broadcasting anything) if a required
    // descriptor field is missing, and derive the canonical descriptor hash.
    let descriptor = create_request
        .build_descriptor()
        .map_err(|e| anyhow::anyhow!("Cannot create sanad: {}", e))?;

    // Salt and canonical sanad_id. The SAME salt is threaded into
    // finalize_published() below so the persisted sanad_id matches exactly the
    // id written on-chain during publish.
    let salt: [u8; 16] = rand::random();
    let sanad_id = csv_hash::sanad::SanadId::from_descriptor_commitment(
        descriptor.compute_hash(),
        commitment,
        &salt,
    );
    let sanad_id_hash = Hash::new(*sanad_id.as_bytes());
    output::kv_hash("Sanad ID", sanad_id.as_bytes());

    // For Bitcoin, use existing UTXOs instead of creating new seals
    // We need to track both the seal and the anchor since we publish during UTXO selection
    let (seal, selected_utxo_ref, anchor) = if chain.as_str() == "bitcoin" && !sdk_utxos.is_empty()
    {
        output::info("BITCOIN: Selecting UTXO for seal creation");

        // Use pre-extracted SDK config utxos (display format from blockchain scan)
        // Bitcoin adapter's from_config loads these into wallet in display format

        // Sort UTXOs by value descending to try largest first
        let mut sorted_utxos: Vec<_> = sdk_utxos.iter().collect();
        sorted_utxos.sort_by_key(|u| std::cmp::Reverse(u.value));

        let mut last_error = None;
        let mut successful_seal = None;
        let mut successful_utxo_ref = None;
        let mut successful_anchor = None;

        // Try UTXOs in order until one succeeds
        for (attempt, selected_utxo) in sorted_utxos.iter().enumerate() {
            output::info(&format!(
                "Attempt {}/{}: Using UTXO {}:{} ({} sats) for seal",
                attempt + 1,
                sorted_utxos.len(),
                &selected_utxo.txid[..16],
                selected_utxo.vout,
                selected_utxo.value
            ));

            // Convert display format txid to internal byte order for seal
            // SDK config has display format, but Bitcoin adapter reverses when loading into wallet
            let txid_bytes = hex::decode(&selected_utxo.txid)
                .map_err(|e| anyhow::anyhow!("Invalid txid: {}", e))?;
            if txid_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Invalid txid length"));
            }
            let mut txid_array = [0u8; 32];
            txid_array.copy_from_slice(&txid_bytes);
            txid_array.reverse(); // Convert display to internal byte order

            // Create a seal from the UTXO
            let mut id_bytes = Vec::with_capacity(36);
            id_bytes.extend_from_slice(&txid_array);
            id_bytes.extend_from_slice(&selected_utxo.vout.to_le_bytes());

            let seal = csv_hash::seal::SealPoint {
                id: id_bytes,
                nonce: Some(selected_utxo.value),
                version: None,
            };

            // Try to publish with this UTXO
            match runtime
                .publish_seal(core_chain.clone(), seal.clone(), commitment, sanad_id_hash)
                .await
            {
                Ok(anchor) => {
                    output::info(&format!(
                        "Successfully published using UTXO {}:{} ({} sats)",
                        &selected_utxo.txid[..16],
                        selected_utxo.vout,
                        selected_utxo.value
                    ));
                    successful_seal = Some(seal);
                    successful_utxo_ref = Some((selected_utxo.txid.clone(), selected_utxo.vout));
                    successful_anchor = Some(anchor);
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    output::warning(&format!(
                        "Failed to publish with UTXO {}:{}: {}",
                        &selected_utxo.txid[..16],
                        selected_utxo.vout,
                        error_str
                    ));

                    // Check if this is a "missing or spent" error - if so, try next UTXO
                    if error_str.contains("bad-txns-inputs-missingorspent")
                        || error_str.contains("already spent")
                        || error_str.contains("missing")
                    {
                        output::info("UTXO appears to be spent or missing, trying next UTXO...");
                        last_error = Some(anyhow::anyhow!("{}", e));
                        continue;
                    } else {
                        // For other errors, don't retry - fail immediately
                        return Err(anyhow::anyhow!("Failed to publish seal: {}", e));
                    }
                }
            }
        }

        let seal = successful_seal.ok_or_else(|| {
            last_error
                .unwrap_or_else(|| anyhow::anyhow!("All UTXOs failed - no valid UTXOs available"))
        })?;

        let anchor = successful_anchor
            .ok_or_else(|| anyhow::anyhow!("No anchor from successful publish"))?;

        (seal, successful_utxo_ref, Some(anchor))
    } else {
        // For other chains, or when Bitcoin UTXOs weren't scanned (adapter will fetch from RPC),
        // use the normal create_seal flow
        if chain.as_str() == "bitcoin" {
            output::info("BITCOIN: Using adapter to create seal (will fetch UTXOs from RPC)");
        }
        log::info!(
            "{}: Creating seal via chain adapter",
            chain.as_str().to_uppercase()
        );
        let seal = runtime
            .create_seal(core_chain.clone(), value)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create seal: {}", e))?;
        log::info!(
            "{}: Seal created successfully",
            chain.as_str().to_uppercase()
        );
        (seal, None, None)
    };

    // Step 2: Publish the commitment under the seal (skip for Bitcoin since we already did it during UTXO selection)
    let anchor: Option<csv_protocol::CommitAnchor> = if skip_publish {
        // Skip publishing - return None for anchor
        log::info!(
            "{}: Skipping commitment publishing (--skip-publish flag set)",
            chain.as_str().to_uppercase()
        );
        output::info(&format!(
            "Skipping commitment publishing (--skip-publish flag set)"
        ));
        None
    } else if let Some(ref anchor) = anchor {
        // Bitcoin: already published during UTXO selection
        log::info!(
            "{}: Commitment already published during UTXO selection (anchor_id: 0x{})",
            chain.as_str().to_uppercase(),
            hex::encode(&anchor.anchor_id[..8])
        );
        output::info(&format!("Commitment published to {}", chain.as_str()));
        Some(anchor.clone())
    } else {
        // Other chains: publish now
        log::info!(
            "{}: Publishing commitment under seal",
            chain.as_str().to_uppercase()
        );
        output::info(&format!("Publishing commitment to {}...", chain.as_str()));
        let anchor = runtime
            .publish_seal(core_chain.clone(), seal.clone(), commitment, sanad_id_hash)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish seal: {}", e))?;
        log::info!(
            "{}: Commitment published successfully (anchor_id: 0x{})",
            chain.as_str().to_uppercase(),
            hex::encode(&anchor.anchor_id[..8])
        );
        output::info(&format!("Commitment published to {}", chain.as_str()));
        Some(anchor)
    };

    // For Bitcoin, mark the used UTXO as spent in wallet state to prevent reuse
    if chain.as_str() == "bitcoin" {
        if let Some((ref used_txid, used_vout)) = selected_utxo_ref {
            // Remove the spent UTXO from wallet state
            state
                .storage
                .wallet
                .utxos
                .retain(|u| !(&u.txid == used_txid && u.vout == used_vout));
            state.save()?;
        }
    }

    // Create ownership proof from the owner address
    // For canonical mode, generate a signature over the commitment hash
    let proof_bytes = if chain.as_str() == "bitcoin" {
        // Derive the private key for Bitcoin (BIP-86 Taproot)
        use secp256k1::{Message, Secp256k1, SecretKey};

        // Derive the BIP-86 path for the account/index
        let path = csv_keys::bip44::DerivationPath::new_bip86(account, index);

        // Derive the private key from the seed using the existing bip44 module
        let secret_key = csv_keys::bip44::derive_key_from_path(&seed_array, &path, &core_chain)
            .map_err(|e| anyhow::anyhow!("Failed to derive private key: {}", e))?;

        // Convert to secp256k1 SecretKey
        let key_bytes = secret_key.as_bytes();
        let private_key = SecretKey::from_slice(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create secp256k1 key: {}", e))?;

        // Sign the commitment hash
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(commitment.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to create message: {}", e))?;
        let signature = secp.sign_ecdsa(&message, &private_key);
        Some(signature.serialize_compact().to_vec())
    } else {
        // Fail closed: only Bitcoin has a real ownership-proof signing path
        // wired here. Emitting anything else (previously the raw wallet seed,
        // which leaked key material) would persist a forged proof labeled as a
        // valid signature. Leave the proof unsigned; the publish path below
        // refuses to finalize it, while --skip-publish can still build a local
        // unsigned draft.
        None
    };

    let ownership_proof = match &proof_bytes {
        Some(sig) => csv_protocol::OwnershipProof {
            owner: owner_address.as_bytes().to_vec(),
            proof: sig.clone(),
            scheme: Some(csv_protocol::SignatureScheme::Secp256k1),
        },
        None => csv_protocol::OwnershipProof {
            owner: owner_address.as_bytes().to_vec(),
            proof: vec![],
            scheme: None,
        },
    };

    // `--skip-publish` can, at most, produce a local unsigned/unpublished
    // draft (SanadsManager::create_draft). It must never reach the path that
    // persists a SanadRecord with SanadStatus::Active or claims a seal/anchor
    // exists, because no commitment was actually published anywhere
    // (SANAD-CREATE-001).
    if matches!(
        create_request.publish_policy,
        csv_sdk::sanads::PublishPolicy::DraftOnly
    ) {
        let draft = client
            .sanads()
            .create_draft(&create_request, commitment, ownership_proof, &salt)
            .map_err(|e| anyhow::anyhow!("Failed to build sanad draft: {}", e))?;

        let descriptor_hash = draft.descriptor.compute_hash();

        output::kv("Chain", chain.as_ref());
        output::kv_hash("Descriptor Hash", descriptor_hash.as_bytes());
        output::kv_hash("Commitment", draft.commitment.as_bytes());
        output::kv(
            "Value",
            &value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "default".to_string()),
        );
        output::kv("Status", "Draft (not published, no seal, no anchor)");
        println!();
        output::warning(
            "This is an unpublished local draft, not a real Sanad. \
             No seal was created and nothing was anchored on-chain. \
             Re-run without --skip-publish to create and publish a real Sanad.",
        );

        return Ok(());
    }

    // Fail closed: never persist a published, Active sanad with an unsigned
    // ownership proof. Only Bitcoin can currently produce a real signature
    // above; other chains reach here with `proof_bytes == None`.
    if proof_bytes.is_none() {
        return Err(anyhow::anyhow!(
            "Cannot publish a sanad on chain '{}': ownership-proof signing is \
             not implemented for this chain. Only 'bitcoin' is supported for \
             canonical (published) sanad creation at this time. Re-run with \
             --skip-publish to produce an unsigned local draft instead.",
            chain.as_str()
        ));
    }

    // Create the sanad through the runtime and persist the canonical,
    // published result.
    match client.sanads().finalize_published(
        &create_request,
        commitment,
        ownership_proof,
        &salt,
        seal.to_vec(),
        anchor.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "Internal error: publish policy requires an anchor but none was produced"
            )
        })?,
        false,
    ) {
        Ok(result) => {
            let sanad = result.sanad;
            let sanad_id_hex = sanad.id.bytes.clone();

            // Convert seal to base64 for storage
            let seal_ref_encoded = STANDARD.encode(seal.to_vec());

            // Extract nonce from seal_ref for Aptos (stored in first 9 bytes: flag + 8-byte nonce)
            let nonce = if chain.as_str() == "aptos" {
                if let Ok(seal_bytes) = STANDARD.decode(&seal_ref_encoded) {
                    if seal_bytes.len() >= 9 && seal_bytes[0] == 1 {
                        if let Ok(nonce_bytes) = seal_bytes[1..9].try_into() {
                            Some(u64::from_le_bytes(nonce_bytes))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Track the sanad in local state with anchor_tx_hash populated
            let tracked = SanadRecord {
                id: sanad_id_hex.clone(),
                chain: chain.clone(),
                seal_ref: seal_ref_encoded,
                owner: String::new(),
                value: value.unwrap_or(0),
                commitment: hex::encode(commitment.as_bytes()),
                nullifier: None,
                status: SanadStatus::Active,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                anchor_tx_hash: Some(hex::encode(&result.anchor.anchor_id)),
                nonce,
                provenance_strength: None,
            };

            state.storage.sanads.push(tracked);

            // Register the sanad_id -> seal mapping on the Bitcoin adapter for cross-chain lock lookups
            if chain.as_str() == "bitcoin" {
                let anchor = &result.anchor;
                let _sanad_id_bytes = hex::decode(&sanad.id.bytes).unwrap_or_default();
                let anchor_txid_hex = hex::encode(&anchor.anchor_id);
                let output_index = u32::from_le_bytes(
                    anchor.metadata[..4.min(anchor.metadata.len())]
                        .try_into()
                        .unwrap_or([0, 0, 0, 0]),
                );
                // Note: SDK runtime automatically registers sanad seals during publish_seal
                // Manual registration is no longer needed and causes "adapter not found" warnings

                // Persist the mapping to state for cross-run lookups
                state
                    .storage
                    .wallet
                    .sanad_seals
                    .push(csv_store::state::wallet::SanadSealRecord {
                        sanad_id: sanad_id_hex.clone(),
                        anchor_txid: anchor_txid_hex.clone(),
                        vout: output_index,
                    });
                state.save()?;
                log::info!(
                    "Persisted sanad seal to state: sanad_id={}, txid={}, vout={}",
                    sanad_id_hex,
                    anchor_txid_hex,
                    output_index
                );
            }

            output::kv("Chain", chain.as_ref());
            output::kv("Sanad ID", &sanad.id.bytes);
            output::kv_hash("Commitment", commitment.as_bytes());
            output::kv(
                "Value",
                &value
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "default".to_string()),
            );
            output::kv("Anchor TX Hash", &hex::encode(&result.anchor.anchor_id));
            output::kv("Block Height", &result.anchor.block_height.to_string());
            output::kv("Status", "Created and published via runtime");

            // UnifiedStateManager is automatically saved after command execution
            println!();
            output::info(
                "Sanad created and published successfully. Use 'csv sanad show <sanad_id>' to view details",
            );
        }
        Err(e) => {
            output::error(&format!("Failed to create sanad via runtime: {}", e));
            return Err(anyhow::anyhow!("Sanad creation failed: {}", e));
        }
    }

    Ok(())
}

fn cmd_show(sanad_id: String, state: &UnifiedStateManager) -> Result<()> {
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_id_hash = Hash::new(*sanad_id_parsed.as_bytes());

    output::header(&format!("Sanad: {}", hex::encode(sanad_id_hash.as_bytes())));
    output::info(
        "Source: local display cache (non-canonical). Use 'csv sanad state' for canonical on-chain state.",
    );

    if let Some(tracked) = state.get_sanad(&sanad_id_hash.to_hex()) {
        output::kv("Chain", tracked.chain.as_ref());
        output::kv("Commitment", &tracked.commitment);
        output::kv(
            "Local Status",
            match tracked.status {
                SanadStatus::Consumed => "Consumed",
                SanadStatus::Transferred => "Transferred",
                SanadStatus::Active => "Active",
            },
        );
        if let Some(nullifier) = &tracked.nullifier {
            output::kv_hash("Nullifier", nullifier.as_bytes());
        }
        if let Some(transfer) = latest_transfer_for_sanad(&state.storage.transfers, &tracked.id) {
            output::header("Latest Transfer");
            output::kv("Transfer ID", &transfer.id);
            output::kv("Status", &transfer_status_label(transfer, tracked.status));
            output::kv("Destination Chain", transfer.dest_chain.as_ref());
            if let Some(dest_addr) = &transfer.destination_address {
                output::kv("Destination Owner", dest_addr);
            }
            if let Some(dest_tx) = &transfer.dest_tx_hash {
                output::kv("Destination Tx", dest_tx);
            }
            if let Some(source_tx) = &transfer.source_tx_hash {
                output::kv("Source Tx", source_tx);
            }
        }
    } else {
        output::warning("Sanad not found in local tracking");
        output::info("This Sanad may exist on-chain but hasn't been tracked locally");
    }

    Ok(())
}

fn latest_transfer_for_sanad<'a>(
    transfers: &'a [TransferRecord],
    sanad_id: &str,
) -> Option<&'a TransferRecord> {
    transfers
        .iter()
        .filter(|transfer| transfer.sanad_id == sanad_id)
        .max_by_key(|transfer| transfer.completed_at.unwrap_or(transfer.created_at))
}

fn transfer_status_label(transfer: &TransferRecord, local_status: SanadStatus) -> String {
    match transfer.status {
        TransferStatus::Completed => {
            if local_status == SanadStatus::Transferred {
                "Transferred".to_string()
            } else {
                "Transfer completed".to_string()
            }
        }
        TransferStatus::Locked => "Locked awaiting finality".to_string(),
        TransferStatus::Failed => "Transfer failed".to_string(),
        other => format!("{:?}", other),
    }
}

fn transfer_destination_label(transfer: &TransferRecord) -> String {
    match &transfer.destination_address {
        Some(address) if !address.is_empty() => {
            format!("{}:{}", transfer.dest_chain, address)
        }
        _ => transfer.dest_chain.to_string(),
    }
}

/// Resolved display label and (optional) status update for a single `cmd_list` row.
struct ResolvedSanadRow {
    label: String,
    /// `Some(status)` only when the new status was derived from a canonical
    /// on-chain query. Local-only fallback must never produce a status update.
    status_update: Option<SanadStatus>,
}

/// Pure decision logic for a single Sanad row in `csv sanad list`.
///
/// This is the load-bearing rule for CLI-STATE-001: a local cache must never be
/// presented as canonical, and must never silently overwrite local state as if
/// it were a fresh canonical result. When `--update` is requested but the
/// canonical chain query fails (`on_chain_state == None`), the row is labeled
/// explicitly as stale local data and no status update is produced.
fn resolve_sanad_row_status(
    update_requested: bool,
    has_valid_seal: bool,
    local_status: SanadStatus,
    on_chain_state: Option<SanadLifecycleState>,
) -> ResolvedSanadRow {
    let local_label = || {
        if !has_valid_seal {
            SanadLifecycleState::Invalid.label()
        } else {
            SanadLifecycleState::from_local_status(local_status).label()
        }
    };

    match on_chain_state {
        Some(canonical) => {
            let status_update = Some(match canonical {
                SanadLifecycleState::Consumed | SanadLifecycleState::Invalid => {
                    SanadStatus::Consumed
                }
                _ => SanadStatus::Active,
            });
            ResolvedSanadRow {
                label: canonical.label().to_string(),
                status_update,
            }
        }
        None if update_requested => ResolvedSanadRow {
            label: format!("{} (local cache, chain query failed)", local_label()),
            status_update: None,
        },
        None => ResolvedSanadRow {
            label: local_label().to_string(),
            status_update: None,
        },
    }
}

async fn cmd_list(
    chain: Option<Chain>,
    update: bool,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Tracked Sanads");
    if update {
        output::info("Querying on-chain status for all sanads...");
    } else {
        output::info(
            "Source: local display cache (non-canonical). Use --update to query canonical chain state, or 'csv sanad state' for a single Sanad.",
        );
    }

    let headers = vec![
        "Sanad ID",
        "Chain",
        "State",
        "Transfer ID",
        "Destination",
        "Destination Tx",
    ];
    let mut rows = Vec::new();
    let mut updates_to_apply: Vec<(String, SanadStatus)> = Vec::new();

    for sanad in &state.storage.sanads {
        if let Some(ref filter_chain) = chain
            && sanad.chain != *filter_chain
        {
            continue;
        }

        let latest_transfer =
            latest_transfer_for_sanad(&state.storage.transfers, &sanad.id).cloned();

        // Check if sanad has a valid seal_ref (required for non-Bitcoin chains)
        let has_valid_seal = if sanad.chain.as_str() != "bitcoin" {
            base64::engine::general_purpose::STANDARD
                .decode(&sanad.seal_ref)
                .is_ok()
        } else {
            true
        };

        // Only query on-chain state when --update flag is set
        let on_chain_state = if update {
            query_sanad_on_chain_state(&sanad.chain, &sanad.id, Some(sanad), config, state).await
        } else {
            None
        };

        let mut resolved = resolve_sanad_row_status(
            update,
            has_valid_seal,
            sanad.status,
            on_chain_state.as_ref().map(|cs| cs.state),
        );

        if let Some(transfer) = &latest_transfer
            && transfer.status == TransferStatus::Completed
            && transfer.dest_tx_hash.is_some()
        {
            resolved.label = "Transferred".to_string();
            resolved.status_update =
                (sanad.status != SanadStatus::Transferred).then_some(SanadStatus::Transferred);
        }

        if let Some(new_status) = resolved.status_update
            && sanad.status != new_status
        {
            updates_to_apply.push((sanad.id.clone(), new_status));
        }

        let (transfer_id, destination, destination_tx) = latest_transfer
            .as_ref()
            .map(|transfer| {
                (
                    transfer.id.clone(),
                    transfer_destination_label(transfer),
                    transfer
                        .dest_tx_hash
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                )
            })
            .unwrap_or_else(|| ("-".to_string(), "-".to_string(), "-".to_string()));

        rows.push(vec![
            sanad.id.clone(),
            sanad.chain.to_string(),
            resolved.label,
            transfer_id,
            destination,
            destination_tx,
        ]);
    }

    // Apply updates after the loop to avoid borrow checker issues
    let mut updated_count = 0u32;
    for (id, new_status) in updates_to_apply {
        if let Ok(()) = state.update_sanad_status(&id, new_status) {
            updated_count += 1;
        }
    }

    if rows.is_empty() {
        output::info("No Sanads tracked. Use 'csv sanad create' to create one.");
    } else {
        output::table(&headers, &rows);
        if update && updated_count > 0 {
            output::info(&format!(
                "Updated {} sanad(s) status in local store",
                updated_count
            ));
            state.save()?;
        }
    }

    Ok(())
}

fn cmd_transfer(sanad_id: String, to: String, _state: &UnifiedStateManager) -> Result<()> {
    // Validate via the canonical parser so malformed IDs are rejected here
    // rather than silently passed through to the (unimplemented) local path.
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

    output::header(&format!("Transferring Sanad to {}", to));
    output::kv("Sanad ID", &hex::encode(sanad_id_parsed.as_bytes()));
    output::kv("New Owner", &to);
    output::info(
        "Cross-chain transfer: pick a mode — 'csv cross-chain send' (off-chain) \
         or 'csv cross-chain materialize' (on-chain) instead",
    );
    Ok(())
}

async fn cmd_consume(
    chain: Chain,
    sanad_id: String,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Consuming Sanad on {}", chain));

    // Parse sanad_id from hex using canonical parser
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

    output::kv("Sanad ID", &hex::encode(sanad_id_parsed.as_bytes()));

    // Check if sanad exists in local state
    let tracked_sanad = state.get_sanad(&hex::encode(sanad_id_parsed.as_bytes()));
    if tracked_sanad.is_none() {
        output::warning("Sanad not found in local tracking");
        output::info("This Sanad may exist on-chain but hasn't been tracked locally");
        return Err(anyhow::anyhow!(
            "Sanad not found in local state. Use 'csv sanad list' to see tracked Sanads."
        ));
    }

    // Use the runtime to consume the sanad
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;

    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(chain.as_str());
    let identity = WalletIdentity::from_state(state)?;

    // Convert CLI config to SDK config format
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.network = match config.chain(&chain)?.network {
        Network::Test => csv_sdk::config::Network::Testnet,
        Network::Main => csv_sdk::config::Network::Mainnet,
        Network::Dev => csv_sdk::config::Network::Devnet,
    };

    // Convert chain config to SDK format
    let chain_cfg = config.chain(&chain)?;
    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            // Carry the explicit REST indexer selection through to the SDK so the
            // runtime adapter scans/queries via the right transport (e.g. Alchemy
            // Blockbook) instead of appending esplora paths to a JSON-RPC URL.
            indexer_url: chain_cfg.indexer_url.clone(),
            indexer_backend: chain_cfg.indexer_backend.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(&chain).and_then(|w| w.xpub.clone()),
        seed: (chain.as_str() == "bitcoin").then(|| identity.bitcoin_seed_hex()),
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account: 0,
        index: 0,
        utxos: Vec::new(),
        sanad_seals: Vec::new(),
    };
    sdk_config
        .chains
        .insert(chain.as_str().to_string(), sdk_chain_config);

    let private_keys = identity.signing_map(&[(&chain, 0, 0)], state)?;

    // Build CSV client with the requested chain enabled
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_private_keys(private_keys)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    // Initialize chain adapters for the configured network
    let _network_type = match config.chain(&chain)?.network {
        Network::Test => csv_sdk::client::NetworkType::Testnet,
        Network::Main => csv_sdk::client::NetworkType::Mainnet,
        Network::Dev => csv_sdk::client::NetworkType::Testnet, // Dev uses testnet
    };

    // Note: SDK adapters are automatically created during client build
    // Do NOT call init_adapters here as it has been removed from SDK

    let runtime = client.chain_runtime();

    // Consume the sanad via the runtime
    output::info(&format!("Consuming sanad on {}...", chain));
    let result = runtime
        .consume_sanad(core_chain.clone(), &sanad_id_parsed, "default")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to consume sanad: {}", e))?;

    output::kv("Status", "Consumed successfully");
    output::kv("Transaction Hash", &result.transaction_hash);
    output::kv("Block Height", &result.block_height.to_string());

    // Update sanad status in local state
    if let Some(tracked) = state
        .storage
        .sanads
        .iter_mut()
        .find(|s| s.id == hex::encode(sanad_id_parsed.as_bytes()))
    {
        tracked.status = SanadStatus::Consumed;
        state.save()?;
        output::info("Sanad status updated in local state");
    }

    Ok(())
}

fn cmd_remove(sanad_id: Option<String>, all: bool, state: &mut UnifiedStateManager) -> Result<()> {
    if all {
        output::header("Removing All Sanads");
        let count = state.storage.sanads.len();
        state.storage.sanads.clear();

        // Also clear wallet sanad_seals to free UTXOs marked as SanadAnchor
        let seal_count = state.storage.wallet.sanad_seals.len();
        if seal_count > 0 {
            state.storage.wallet.sanad_seals.clear();
            output::info(&format!(
                "Cleared {} sanad_seal mappings from wallet state",
                seal_count
            ));
            output::info("UTXOs previously marked as SanadAnchor are now available for spending.");
        }

        state.save()?;

        if count > 0 {
            output::info(&format!("Removed {} Sanad(s) from local tracking", count));
        } else {
            output::info("No Sanads to remove");
        }
        return Ok(());
    }

    let sanad_id = sanad_id.ok_or_else(|| anyhow::anyhow!("Must provide --all or a Sanad ID"))?;
    output::header(&format!(
        "Removing Sanad {}",
        &sanad_id[..8.min(sanad_id.len())]
    ));

    // Parse sanad_id using the canonical parser so 0x/non-0x forms, invalid
    // length, and non-hex input are all rejected consistently with the other
    // sanad subcommands (create/show/consume/state/trace).
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let normalized_id = hex::encode(sanad_id_parsed.as_bytes());

    // Check if sanad exists
    if state.get_sanad(&normalized_id).is_none() {
        output::error(&format!("Sanad {} not found in local tracking", sanad_id));
        return Err(anyhow::anyhow!("Sanad not found in local state"));
    }

    // Remove the sanad
    state.remove_sanad(&normalized_id)?;
    state.save()?;

    output::info(&format!("Sanad {} removed from local tracking", sanad_id));
    Ok(())
}

/// Show canonical on-chain state of a Sanad (Contracts-Audit.md § "CLI fixes")
async fn cmd_state(
    chain: Chain,
    sanad_id: String,
    config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_id_hash = csv_hash::Hash::new(*sanad_id_parsed.as_bytes());
    let sanad_id_hex = sanad_id_hash.to_hex();

    output::header(&format!("Sanad State: {}", sanad_id_hex));
    output::kv("Chain", chain.as_ref());

    // Use runtime-backed canonical state query (CLI-STATE-001)
    let core_chain = csv_hash::ChainId::new(chain.as_str());

    // Build SDK client for runtime access
    let sdk_config = build_sdk_config_from_cli_config(config, &chain, state)?;
    let client = csv_sdk::CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(csv_sdk::StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    let runtime = client.chain_runtime();

    // Query canonical state via ChainBackend (fail closed if unavailable)
    match runtime.get_adapter(core_chain.clone()).await {
        Ok(adapter) => {
            match adapter.get_sanad_state(&sanad_id_parsed).await {
                Ok(canonical_state) => {
                    // Display canonical state from chain
                    let lifecycle_state = SanadLifecycleState::from_u8(canonical_state.state);
                    output::kv("State", lifecycle_state.label());
                    output::kv("Owner", &canonical_state.owner);
                    if canonical_state.commitment.as_bytes() == &[0u8; 32] {
                        if let Some(local) = state.get_sanad(&sanad_id_hex) {
                            output::kv(
                                "Commitment",
                                &format!("{} (local cache)", local.commitment),
                            );
                        } else {
                            output::kv("Commitment", "unknown on this chain");
                        }
                    } else {
                        output::kv_hash("Commitment", canonical_state.commitment.as_bytes());
                    }
                    if let Some(nullifier) = &canonical_state.nullifier {
                        output::kv_hash("Nullifier", nullifier.as_bytes());
                    }
                    if canonical_state.created_at > 0 {
                        output::kv(
                            "Created",
                            &chrono::DateTime::from_timestamp(canonical_state.created_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| canonical_state.created_at.to_string()),
                        );
                    }
                    if let Some(locked_at) = canonical_state.locked_at {
                        output::kv(
                            "Locked",
                            &chrono::DateTime::from_timestamp(locked_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| locked_at.to_string()),
                        );
                    }
                    if let Some(consumed_at) = canonical_state.consumed_at {
                        output::kv(
                            "Consumed",
                            &chrono::DateTime::from_timestamp(consumed_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| consumed_at.to_string()),
                        );
                    }
                    if let Some(minted_at) = canonical_state.minted_at {
                        output::kv(
                            "Minted",
                            &chrono::DateTime::from_timestamp(minted_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| minted_at.to_string()),
                        );
                    }
                    if let Some(refunded_at) = canonical_state.refunded_at {
                        output::kv(
                            "Refunded",
                            &chrono::DateTime::from_timestamp(refunded_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| refunded_at.to_string()),
                        );
                    }
                    output::success("Canonical state from chain");
                }
                Err(e) => {
                    // Chain query failed - fail closed (CLI-STATE-001)
                    return Err(anyhow::anyhow!(
                        "Failed to query canonical sanad state from chain: {}. \
                         Local state cannot be used as canonical truth.",
                        e
                    ));
                }
            }
        }
        Err(e) => {
            // Adapter not available - fail closed (CLI-STATE-001)
            return Err(anyhow::anyhow!(
                "Chain adapter not available for {}: {}. \
                 Cannot determine canonical state without chain access.",
                chain,
                e
            ));
        }
    }

    // Show local display cache if available (non-canonical)
    if let Some(local_sanad) = state.get_sanad(&sanad_id_hex) {
        output::info("---");
        output::info("Local display cache (non-canonical, for reference only):");
        output::kv("Local Status", &format!("{:?}", local_sanad.status));
        output::kv("Local Owner", &local_sanad.owner);
        if let Some(anchor) = &local_sanad.anchor_tx_hash {
            output::kv("Local Anchor TX", anchor);
        }
    }

    Ok(())
}

/// Show full lifecycle trace of a Sanad (Contracts-Audit.md § "CLI fixes")
async fn cmd_trace(
    chain: Chain,
    sanad_id: String,
    config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    let sanad_id_parsed =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_id_hash = csv_hash::Hash::new(*sanad_id_parsed.as_bytes());
    let sanad_id_hex = sanad_id_hash.to_hex();

    output::header(&format!("Sanad Lifecycle Trace: {}", sanad_id_hex));
    output::kv("Chain", chain.as_ref());

    // Use runtime-backed canonical trace query (CLI-STATE-001)
    let core_chain = csv_hash::ChainId::new(chain.as_str());

    // Build SDK client for runtime access
    let sdk_config = build_sdk_config_from_cli_config(config, &chain, state)?;
    let client = csv_sdk::CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(csv_sdk::StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    let runtime = client.chain_runtime();

    // Query canonical trace via ChainBackend (fail closed if unavailable)
    match runtime.get_adapter(core_chain.clone()).await {
        Ok(adapter) => {
            match adapter.trace_sanad(&sanad_id_parsed).await {
                Ok(events) => {
                    if events.is_empty() {
                        output::info(
                            "No lifecycle events found on-chain. This Sanad may not exist yet.",
                        );
                    } else {
                        output::info(&format!(
                            "Found {} canonical lifecycle event(s)",
                            events.len()
                        ));
                        println!();

                        for event in &events {
                            let time = chrono::DateTime::from_timestamp(event.timestamp, 0)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| event.timestamp.to_string());

                            output::kv("Time", &time);
                            output::kv("Event", &event.event_type);
                            output::kv("TX", &event.tx_hash);
                            for (key, value) in &event.data {
                                output::kv(key, value);
                            }
                            println!();
                        }
                        output::success("Canonical trace from chain");
                    }
                }
                Err(e) => {
                    // Chain query failed - fail closed (CLI-STATE-001)
                    return Err(anyhow::anyhow!(
                        "Failed to query canonical sanad trace from chain: {}. \
                         Local state cannot be used as canonical truth.",
                        e
                    ));
                }
            }
        }
        Err(e) => {
            // Adapter not available - fail closed (CLI-STATE-001)
            return Err(anyhow::anyhow!(
                "Chain adapter not available for {}: {}. \
                 Cannot determine canonical trace without chain access.",
                chain,
                e
            ));
        }
    }

    // Show local display cache if available (non-canonical)
    if let Some(local_sanad) = state.get_sanad(&sanad_id_hex) {
        output::info("---");
        output::info("Local display cache (non-canonical, for reference only):");
        output::kv("Local Status", &format!("{:?}", local_sanad.status));
        output::kv("Local Created", &local_sanad.created_at.to_string());
        if let Some(anchor) = &local_sanad.anchor_tx_hash {
            output::kv("Local Anchor TX", anchor);
        }
    }

    Ok(())
}

/// Query canonical on-chain state for a Sanad via the runtime-backed chain adapter
/// (`SanadStateReader::get_sanad_state`). This is the single, uniform path for all
/// chains — no chain gets a hand-rolled RPC parser or a local-only fabricated state
/// (CLI-STATE-001). Returns `None` if the adapter/chain query is unavailable; callers
/// must treat `None` as "canonical state unknown", never as "Active".
async fn query_sanad_on_chain_state(
    chain: &Chain,
    sanad_id_hex: &str,
    local_sanad: Option<&SanadRecord>,
    config: &Config,
    state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    let sanad_id_parsed = SanadId::parse_hex(sanad_id_hex).ok()?;

    let sdk_config = build_sdk_config_from_cli_config(config, chain, state).ok()?;
    let core_chain = csv_hash::ChainId::new(chain.as_str());

    let client = csv_sdk::CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(csv_sdk::StoreBackend::InMemory)
        .build()
        .await
        .ok()?;

    let runtime = client.chain_runtime();
    let adapter = match runtime.get_adapter(core_chain.clone()).await {
        Ok(adapter) => adapter,
        Err(e) => {
            log::warn!(
                "Chain adapter not available for {}: {}. Cannot determine canonical state.",
                chain,
                e
            );
            return None;
        }
    };

    match adapter.get_sanad_state(&sanad_id_parsed).await {
        Ok(canonical) => {
            let lifecycle_state = SanadLifecycleState::from_u8(canonical.state);
            Some(CanonicalSanadState {
                sanad_id: sanad_id_hex.to_string(),
                seal_id: None,
                chain: core_chain,
                state: lifecycle_state,
                owner: Some(canonical.owner),
                commitment: local_sanad.map(|s| s.commitment.clone()),
                nullifier: canonical
                    .nullifier
                    .map(|n| hex::encode(n.as_bytes()))
                    .or_else(|| local_sanad.and_then(|s| s.nullifier.clone())),
                source_chain: None,
                destination_chain: None,
                tx_hash: None,
                block_height: None,
                updated_at: canonical
                    .consumed_at
                    .or(canonical.minted_at)
                    .or(canonical.locked_at)
                    .map(|t| t as u64)
                    .or(Some(canonical.created_at as u64)),
            })
        }
        Err(e) => {
            log::warn!(
                "Failed to query canonical sanad state from chain {}: {}. Cannot return canonical state without on-chain validation.",
                chain,
                e
            );
            None
        }
    }
}

/// Build SDK config from CLI config for runtime client construction
/// This helper centralizes the conversion logic used across multiple commands
fn build_sdk_config_from_cli_config(
    config: &Config,
    chain: &Chain,
    state: &UnifiedStateManager,
) -> Result<csv_sdk::config::Config, anyhow::Error> {
    let chain_cfg = config.chain(chain)?;
    let identity = WalletIdentity::from_state(state)?;

    let mut sdk_config = csv_sdk::config::Config {
        network: match chain_cfg.network {
            crate::config::Network::Test => csv_sdk::config::Network::Testnet,
            crate::config::Network::Main => csv_sdk::config::Network::Mainnet,
            crate::config::Network::Dev => csv_sdk::config::Network::Devnet,
        },
        ..Default::default()
    };

    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            // Carry the explicit REST indexer selection through to the SDK so the
            // runtime adapter scans/queries via the right transport (e.g. Alchemy
            // Blockbook) instead of appending esplora paths to a JSON-RPC URL.
            indexer_url: chain_cfg.indexer_url.clone(),
            indexer_backend: chain_cfg.indexer_backend.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(chain).and_then(|w| w.xpub.clone()),
        seed: (chain.as_str() == "bitcoin").then(|| identity.bitcoin_seed_hex()),
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account: 0,
        index: 0,
        utxos: vec![],
        // Bitcoin has no on-chain contract mapping sanad_id -> state; the adapter
        // derives canonical state from each sanad's anchor/seal UTXO. Feed it the
        // locally-tracked sanad_id -> anchor_txid mappings so get_sanad_state can
        // resolve the seal and validate it on-chain. Other chains ignore this field.
        sanad_seals: if chain.as_str() == "bitcoin" {
            state
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
                .collect()
        } else {
            vec![]
        },
    };
    sdk_config
        .chains
        .insert(chain.as_str().to_string(), sdk_chain_config);

    Ok(sdk_config)
}

#[cfg(test)]
mod state_tests {
    use super::*;

    /// CLI-STATE-001: a Sanad that is canonically Consumed on-chain must never be
    /// displayed or persisted as Active because of stale/local data.
    #[test]
    fn canonical_consumed_overrides_local_active() {
        let resolved = resolve_sanad_row_status(
            true,
            true,
            SanadStatus::Active,
            Some(SanadLifecycleState::Consumed),
        );
        assert_eq!(resolved.label, "Consumed");
        assert_eq!(resolved.status_update, Some(SanadStatus::Consumed));
    }

    /// CLI-STATE-001: when --update is requested and the canonical on-chain query
    /// fails, the local cache must be labeled explicitly as stale/local and must
    /// NOT produce a status update (i.e. it cannot silently overwrite local state
    /// or be confused with a fresh canonical result).
    #[test]
    fn failed_chain_query_does_not_mark_active_or_persist_update() {
        let resolved = resolve_sanad_row_status(true, true, SanadStatus::Consumed, None);
        assert!(
            resolved.label.contains("local cache"),
            "label must disclose it is local-cache data, got: {}",
            resolved.label
        );
        assert!(
            resolved.label.contains("chain query failed"),
            "label must disclose the chain query failed, got: {}",
            resolved.label
        );
        assert_eq!(
            resolved.status_update, None,
            "a failed canonical query must never produce a local status overwrite"
        );
    }

    /// Without --update, the CLI must not fabricate a canonical-looking label;
    /// it falls back to the plain local status (no on-chain query was attempted).
    #[test]
    fn no_update_requested_uses_local_status_without_chain_query_failure_label() {
        let resolved = resolve_sanad_row_status(false, true, SanadStatus::Active, None);
        assert_eq!(resolved.label, "Active");
        assert_eq!(resolved.status_update, None);
    }

    /// An invalid seal reference must be treated as Invalid for local display,
    /// regardless of the locally recorded status.
    #[test]
    fn invalid_seal_overrides_local_status_label() {
        let resolved = resolve_sanad_row_status(false, false, SanadStatus::Active, None);
        assert_eq!(resolved.label, "Invalid");
        assert_eq!(resolved.status_update, None);
    }

    /// A canonical Active result is reflected as a status update, proving the
    /// update path is reachable (not just the fail-closed path).
    #[test]
    fn canonical_active_produces_status_update() {
        let resolved = resolve_sanad_row_status(
            true,
            true,
            SanadStatus::Consumed,
            Some(SanadLifecycleState::Active),
        );
        assert_eq!(resolved.label, "Active");
        assert_eq!(resolved.status_update, Some(SanadStatus::Active));
    }
}

#[cfg(test)]
mod create_defaults_tests {
    use super::*;

    #[test]
    fn default_content_hashes_are_non_zero_and_buildable() {
        let content_descriptor = csv_sdk::sanads::ContentDescriptorInput {
            schema_id: None,
            schema_hash: Some(default_content_hash("csv.sanad.default.schema.v1")),
            payload_codec: None,
            payload_hash: Some(default_content_hash("csv.sanad.default.payload.v1")),
            content_root: None,
            attachment_root: None,
            disclosure_policy_hash: Some(default_content_hash("csv.sanad.default.disclosure.v1")),
            proof_policy_hash: Some(default_content_hash("csv.sanad.default.proof.v1")),
        };

        for hash in [
            content_descriptor.schema_hash,
            content_descriptor.payload_hash,
            content_descriptor.disclosure_policy_hash,
            content_descriptor.proof_policy_hash,
        ]
        .into_iter()
        .flatten()
        {
            assert_ne!(hash.as_bytes(), &[0u8; 32]);
        }

        let request = csv_sdk::sanads::CreateSanadRequest {
            chain: ChainId::new("bitcoin"),
            owner: b"owner".to_vec(),
            value: Some(100_000),
            content_descriptor,
            funding_selector: csv_sdk::sanads::FundingSelector::Automatic,
            publish_policy: csv_sdk::sanads::PublishPolicy::Publish,
        };

        request
            .build_descriptor()
            .expect("CLI default descriptor hashes should satisfy SDK validation");
    }
}

/// CLI-ID-001: Sanad ID parsing/display must be normalized everywhere a
/// user-supplied ID string is turned into the canonical lookup key used to
/// match `SanadRecord.id` (e.g. in `cmd_consume`, `cmd_remove`, `cmd_show`,
/// `cmd_state`, `cmd_trace`). The lookup key MUST be derived via
/// `SanadId::parse_hex(..).as_bytes()` re-encoded as hex — never via
/// `String::as_bytes()` on the raw user input, which yields the ASCII bytes
/// of the hex string itself rather than the 32-byte identifier.
#[cfg(test)]
mod id_normalization_tests {
    use super::*;

    const VALID_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// The canonical lookup key (as stored in `SanadRecord.id`) must be
    /// identical regardless of `0x` prefix, matching how `cmd_create` stores
    /// `sanad.id.bytes` and how `cmd_consume`/`cmd_remove`/`cmd_show`/
    /// `cmd_state`/`cmd_trace` all re-derive the key.
    #[test]
    fn lookup_key_identical_across_0x_and_non_0x_forms() {
        let with_prefix = format!("0x{VALID_HEX}");

        let parsed_plain = SanadId::parse_hex(VALID_HEX).unwrap();
        let parsed_prefixed = SanadId::parse_hex(&with_prefix).unwrap();

        let key_plain = hex::encode(parsed_plain.as_bytes());
        let key_prefixed = hex::encode(parsed_prefixed.as_bytes());

        assert_eq!(
            key_plain, key_prefixed,
            "0x-prefixed and bare hex forms must resolve to the same lookup key"
        );
        assert_eq!(key_plain, VALID_HEX);
    }

    /// Regression for the bug fixed in `cmd_consume`: deriving the lookup key
    /// via `hex::encode(sanad_id.as_bytes())` where `sanad_id` is the raw
    /// `String` (not the parsed `SanadId`) re-encodes the ASCII bytes of the
    /// hex string itself, producing a 128-character string that can never
    /// match the 64-character canonical key stored in `SanadRecord.id`.
    #[test]
    fn ascii_bytes_of_raw_string_never_matches_canonical_key() {
        let raw_input: String = VALID_HEX.to_string();
        let parsed = SanadId::parse_hex(&raw_input).unwrap();

        let canonical_key = hex::encode(parsed.as_bytes());
        // This mirrors the bug: hex-encoding the ASCII bytes of the raw
        // input string instead of the parsed 32-byte identifier.
        let buggy_key = hex::encode(raw_input.as_bytes());

        assert_eq!(canonical_key.len(), 64);
        assert_eq!(buggy_key.len(), 128);
        assert_ne!(
            canonical_key, buggy_key,
            "the buggy ASCII-byte lookup key must never coincide with the canonical key"
        );
    }

    /// Malformed input (wrong length) must fail to parse rather than silently
    /// producing some other key, so commands like `cmd_remove`/`cmd_consume`
    /// fail closed instead of operating on a misderived identifier.
    #[test]
    fn invalid_length_input_fails_to_parse() {
        assert!(SanadId::parse_hex("deadbeef").is_err());
        assert!(SanadId::parse_hex(&format!("{VALID_HEX}ff")).is_err());
    }

    /// Non-hex input must fail to parse rather than being silently coerced.
    #[test]
    fn non_hex_input_fails_to_parse() {
        assert!(SanadId::parse_hex(&"zz".repeat(32)).is_err());
    }
}
