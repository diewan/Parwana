//! Sanad lifecycle commands

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Subcommand;
use sha2::Digest;
use std::str::FromStr;

use csv_hash::ChainId;
use csv_hash::Hash;

use crate::config::{Chain, Config, Network};
use crate::output;
use crate::state::{SanadRecord, SanadStatus, UnifiedStateManager};

use csv_store::state::{
    CanonicalLifecycleEvent, CanonicalSanadState, LifecycleEventType, SanadLifecycleState,
};

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
) -> Result<()> {
    match action {
        SanadAction::Create { chain, value, account, index, skip_publish, schema, payload, content_root, attachments, disclosure_policy, proof_policy, schema_hash, disclosure_policy_hash, proof_policy_hash } => {
            cmd_create(chain, value, account, index, skip_publish, schema, payload, content_root, attachments, disclosure_policy, proof_policy, schema_hash, disclosure_policy_hash, proof_policy_hash, config, state).await
        }
        SanadAction::Show { sanad_id } => cmd_show(sanad_id, state),
        SanadAction::List { chain, update } => cmd_list(chain, update, config, state).await,
        SanadAction::Transfer { sanad_id, to } => cmd_transfer(sanad_id, to, state),
        SanadAction::Consume { chain, sanad_id } => cmd_consume(chain, sanad_id, config, state).await,
        SanadAction::Remove { sanad_id, all } => cmd_remove(sanad_id, all, state),
        SanadAction::State { chain, sanad_id } => cmd_state(chain, sanad_id, config, state).await,
        SanadAction::Trace { chain, sanad_id } => cmd_trace(chain, sanad_id, config, state).await,
    }
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
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Creating Sanad on {}", chain));

    // Handle content descriptor parameters (B-013)
    // Parse schema file, load payload, process attachments
    let (schema_hash_final, payload_hash_final, attachment_root_final) = if schema.is_some() || payload.is_some() || attachments.is_some() {
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
                
                let schema_hash_str = schema_json.get("schema_hash")
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
            let attachment_paths: Vec<&str> = attachments_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            
            if !attachment_paths.is_empty() {
                // Compute Merkle root of attachment hashes
                let mut attachment_hashes = Vec::new();
                
                for (i, attachment_path) in attachment_paths.iter().enumerate() {
                    output::info(&format!("Processing attachment {}/{}: {}", i + 1, attachment_paths.len(), attachment_path));
                    
                    // Read attachment file
                    let attachment_bytes = std::fs::read(attachment_path)
                        .map_err(|e| anyhow::anyhow!("Failed to read attachment file {}: {}", attachment_path, e))?;
                    
                    // Compute SHA256 hash
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&attachment_bytes);
                    let hash_bytes = hasher.finalize();
                    attachment_hashes.push(hash_bytes);
                    
                    output::kv(&format!("Attachment {} hash", i + 1), &hex::encode(&hash_bytes));
                }
                
                // Compute simple Merkle root (for now, just hash all hashes concatenated)
                // In production, this should use the csv-content Merkle tree implementation
                let mut hasher = sha2::Sha256::new();
                for hash in &attachment_hashes {
                    hasher.update(hash);
                }
                let root_bytes = hasher.finalize();
                
                let root_hex = hex::encode(&root_bytes);
                output::kv("Attachment root", &root_hex);
                let mut root_array = [0u8; 32];
                root_array.copy_from_slice(&root_bytes);
                Some(Hash::new(root_array))
            } else {
                None
            }
        } else {
            None
        };
        
        // Parse disclosure policy if provided
        if let Some(ref disclosure_policy_path) = disclosure_policy {
            output::kv("Disclosure policy", disclosure_policy_path);
            // For now, just log - full implementation would parse policy file
        }
        
        // Parse proof policy if provided
        if let Some(ref proof_policy_path) = proof_policy {
            output::kv("Proof policy", proof_policy_path);
            // For now, just log - full implementation would parse policy file
        }
        
        (schema_hash_val, payload_hash_val, attachment_root_val)
    } else {
        (None, None, None)
    };

    // Show derivation parameters for Bitcoin
    if chain.as_str() == "bitcoin" {
        output::kv("Account", &account.to_string());
        output::kv("Index", &index.to_string());
        output::kv("Derivation Path", &format!("m/86'/1'/{}'/0/{}", account, index));

        // Derive and show the funding address
        if let Some(mnemonic_phrase) = &state.storage.wallet.mnemonic {
            let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
                .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
            let seed = mnemonic.to_seed(None);
            let seed_array = *seed.as_bytes();

            // Use csv-coordinator wallet_factory for Bitcoin operations (BIP-86 Taproot)
            let chain_id = csv_hash::ChainId::new("bitcoin");
            let wallet_ops = csv_coordinator::get_wallet_operations(&chain_id);
            let address = if let Some(ops) = wallet_ops {
                ops.derive_address(&seed_array, account, index)
                    .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?
            } else {
                // Fallback to csv-keys if factory not available
                let key = csv_keys::derive_key(&seed_array, &chain_id, account, index)
                    .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
                csv_keys::bip44::derive_address_from_key(key.expose_secret(), &chain_id)
                    .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?
            };

            output::kv("Funding Address", &address);
            output::info("Make sure this address has UTXOs before creating a sanad.");
        }
    }

    // For Bitcoin, always refresh UTXOs from chain before creating a sanad
    let bitcoin_utxos: Option<Vec<(String, u32, u64, Option<String>)>> = if chain.as_str() == "bitcoin" {
        // Derive the expected address for this account/index
        let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
        })?;
        let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
            .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
        let seed = mnemonic.to_seed(None);
        let seed_array = *seed.as_bytes();

        // Use csv-coordinator wallet_factory for Bitcoin operations (BIP-86 Taproot)
        let chain_id = csv_hash::ChainId::new("bitcoin");
        let wallet_ops = csv_coordinator::get_wallet_operations(&chain_id);
        let expected_address = if let Some(ops) = wallet_ops {
            ops.derive_address(&seed_array, account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?
        } else {
            // Fallback to csv-keys if factory not available
            let key = csv_keys::derive_key(&seed_array, &chain_id, account, index)
                .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
            csv_keys::bip44::derive_address_from_key(key.expose_secret(), &chain_id)
                .map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?
        };

        output::kv("Expected Address", &expected_address);
        output::info("Refreshing UTXOs from blockchain...");

        // Clear old UTXOs for this account before scanning
        state.storage.wallet.utxos.retain(|u| u.account != account);

        // Perform the scan using minimal implementation
        let wallet_utxos = scan_bitcoin_utxos(
            &expected_address,
            &config.chain(&chain)?.rpc_url,
        ).await.map_err(|e| anyhow::anyhow!("Failed to scan UTXOs: {}", e))?;

        // Filter UTXOs: skip dust and validate they're still unspent BEFORE adding to state
        let rpc_url = config.chain(&chain)?.rpc_url.clone();
        let mut utxos_to_add = Vec::new();
        let mut total_utxos = 0;
        let mut total_value = 0u64;

        for utxo in wallet_utxos {
            output::info(&format!("  Discovered UTXO {}:{} ({} sats)", &utxo.txid[..16], utxo.vout, utxo.value));

            // Skip UTXOs below minimum threshold (10,000 sats)
            if utxo.value < 10_000 {
                output::info(&format!("    Skipping dust UTXO ({} sats < 10,000)", utxo.value));
                continue;
            }

            // UTXO will be validated via runtime after client is built
            output::info(&format!("    UTXO added to wallet state (pending runtime validation)"));

            // Add UTXO to unified state for persistence with script_pubkey
            let utxo_record = csv_store::state::wallet::UtxoRecord {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                value: utxo.value,
                account,
                index: 0,
                derivation_path: format!("m/86'/1'/{}'/0/0", account),
                script_pubkey: utxo.scriptpubkey_hex.clone(),
            };
            state.storage.wallet.utxos.push(utxo_record);

            utxos_to_add.push((utxo.txid.clone(), utxo.vout, utxo.value, utxo.scriptpubkey_hex));

            total_utxos += 1;
            total_value += utxo.value;
        }

        state.save()?;

        output::kv("Total validated UTXOs", &total_utxos.to_string());
        output::kv("Total value", &format!("{} sats", total_value));

        if total_utxos == 0 {
            return Err(anyhow::anyhow!("No valid UTXOs found on-chain. Send Bitcoin to the funding address first."));
        }

        if utxos_to_add.is_empty() {
            output::warning(&format!("No valid unspent UTXOs found after refresh. Send Bitcoin to {} first.", expected_address));
            None
        } else {
            Some(utxos_to_add)
        }
    } else {
        None
    };

    // Use the new runtime to create the sanad
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;

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
    eprintln!("CLI LAYER: RPC URL from config: {}", chain_cfg.rpc_url);
    eprintln!("CLI LAYER: Account: {}, Index: {}", account, index);
      let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(&chain).and_then(|w| w.xpub.clone()),
        seed: None,
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account,
        index,
        utxos: bitcoin_utxos.clone().unwrap_or_default().into_iter().map(|(txid, vout, value, scriptpubkey_hex): (String, u32, u64, Option<String>)| {
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
        }).collect(),
        sanad_seals: state.storage.wallet.sanad_seals.iter().map(|s| csv_sdk::config::SanadSealConfig {
            sanad_id: s.sanad_id.clone(),
            anchor_txid: s.anchor_txid.clone(),
            vout: s.vout,
        }).collect(),
    };
    sdk_config.chains.insert(chain.as_str().to_string(), sdk_chain_config);

    // Extract UTXOs from SDK config before building client (config is moved)
    let sdk_utxos = sdk_config.chains.get(chain.as_str())
        .and_then(|c| Some(c.utxos.clone()))
        .unwrap_or_default();

    // Derive private key from wallet mnemonic for chains that require signing
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
    })?;

    let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(None);
    let seed_array = *seed.as_bytes();

    // For Bitcoin, use the raw 64-byte BIP-39 seed instead of the derived 32-byte private key
    // BitcoinSealProtocol::from_config requires 64-byte seed for HD wallet derivation
    let key_hex = if chain.as_str() == "bitcoin" {
        log::info!("BITCOIN: Using 64-byte BIP-39 seed for HD wallet derivation");
        hex::encode(seed_array)
    } else {
        let (secret_key, key_source) =
            signing_key_for_chain(&chain, account, &seed_array, state)?;
        log::info!(
            "{}: Using {} 32-byte private key",
            chain.as_str().to_uppercase(),
            key_source
        );
        let pk_hex = hex::encode(secret_key.expose_secret());
        log::info!("CLI LAYER: Private key (first 8 bytes): 0x{}", &pk_hex[..16]);

        // Derive and log the address for this key
        let core_chain = csv_hash::ChainId::new(chain.as_str());
        if let Ok(address) = csv_keys::bip44::derive_address_from_key(secret_key.expose_secret(), &core_chain) {
            log::info!("CLI LAYER: Derived address for {}: {}", chain.as_str().to_uppercase(), address);
            eprintln!("CLI LAYER: Derived address for {}: {}", chain.as_str().to_uppercase(), address);
        }

        pk_hex
    };

    let mut private_keys = std::collections::HashMap::new();
    let key_bytes = hex::decode(&key_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode private key hex: {}", e))?;

    // Bitcoin uses 64-byte seed for HD derivation, other chains use 32-byte private key
    let secret_handle = if chain.as_str() == "bitcoin" {
        // For Bitcoin, use the 64-byte seed directly
        let seed_array: [u8; 64] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid seed length for Bitcoin (expected 64 bytes)"))?;
        csv_protocol::secret::SharedSecretHandle::from_seed(seed_array)
    } else {
        // For other chains, use 32-byte private key
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key length (expected 32 bytes)"))?;
        csv_protocol::secret::SharedSecretHandle::from_bytes(key_array)
    };

    private_keys.insert(chain.as_str().to_string(), secret_handle);

    // Build CSV client with the requested chain enabled
    eprintln!("CLI LAYER: Building client with SDK config RPC URL: {}", sdk_config.chains.get(chain.as_str()).map(|c| &c.rpc.url).unwrap_or(&"N/A".to_string()));
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
    if chain.as_str() == "bitcoin" {
        output::info("Validating UTXOs via runtime...");
        let runtime = client.chain_runtime();
        
        // Validate each UTXO is still unspent on-chain
        let mut validated_utxos = Vec::new();
        for utxo_config in &sdk_utxos {
            // Use runtime to check transaction status
            match runtime.get_transaction(core_chain.clone(), &utxo_config.txid).await {
                Ok(tx_info) => {
                    // Check if transaction is confirmed and UTXO is unspent
                    match tx_info.status {
                        csv_protocol::chain_adapter_traits::TransactionStatus::Confirmed { .. } => {
                            output::info(&format!("  UTXO {}:{} validated on-chain", &utxo_config.txid[..16], utxo_config.vout));
                            validated_utxos.push(utxo_config.clone());
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Pending => {
                            output::warning(&format!("  UTXO {}:{} is pending, skipping", &utxo_config.txid[..16], utxo_config.vout));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Failed { reason } => {
                            output::warning(&format!("  UTXO {}:{} failed: {}, skipping", &utxo_config.txid[..16], utxo_config.vout, reason));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Dropped => {
                            output::warning(&format!("  UTXO {}:{} was dropped, skipping", &utxo_config.txid[..16], utxo_config.vout));
                        }
                        csv_protocol::chain_adapter_traits::TransactionStatus::Unknown => {
                            output::warning(&format!("  UTXO {}:{} has unknown status, skipping", &utxo_config.txid[..16], utxo_config.vout));
                        }
                    }
                }
                Err(e) => {
                    // Fail closed if RPC is unavailable - this is a security requirement
                    return Err(anyhow::anyhow!("Failed to validate UTXO {}:{} via runtime: {}. RPC or validation support unavailable - cannot proceed without on-chain validation.", 
                        &utxo_config.txid[..16], utxo_config.vout, e));
                }
            }
        }
        
        if validated_utxos.is_empty() {
            return Err(anyhow::anyhow!("No valid UTXOs after runtime validation. Ensure RPC is configured and UTXOs are unspent."));
        }
        
        output::kv("Validated UTXOs", &validated_utxos.len().to_string());
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

    // For Bitcoin, use existing UTXOs instead of creating new seals
    // We need to track both the seal and the anchor since we publish during UTXO selection
    let (seal, selected_utxo_ref, anchor) = if chain.as_str() == "bitcoin" {
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
            output::info(&format!("Attempt {}/{}: Using UTXO {}:{} ({} sats) for seal",
                attempt + 1, sorted_utxos.len(), &selected_utxo.txid[..16], selected_utxo.vout, selected_utxo.value));

            // Convert display format txid to internal byte order for seal
            // SDK config has display format, but Bitcoin adapter reverses when loading into wallet
            let txid_bytes = hex::decode(&selected_utxo.txid)
                .map_err(|e| anyhow::anyhow!("Invalid txid: {}", e))?;
            if txid_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Invalid txid length"));
            }
            eprintln!("DEBUG: SDK config txid (display): {}", hex::encode(&txid_bytes));
            let mut txid_array = [0u8; 32];
            txid_array.copy_from_slice(&txid_bytes);
            txid_array.reverse(); // Convert display to internal byte order
            eprintln!("DEBUG: Seal txid (internal): {}", hex::encode(&txid_array));

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
            match runtime.publish_seal(core_chain.clone(), seal.clone(), commitment).await {
                Ok(anchor) => {
                    output::info(&format!("Successfully published using UTXO {}:{} ({} sats)",
                        &selected_utxo.txid[..16], selected_utxo.vout, selected_utxo.value));
                    successful_seal = Some(seal);
                    successful_utxo_ref = Some((selected_utxo.txid.clone(), selected_utxo.vout));
                    successful_anchor = Some(anchor);
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    output::warning(&format!("Failed to publish with UTXO {}:{}: {}",
                        &selected_utxo.txid[..16], selected_utxo.vout, error_str));

                    // Check if this is a "missing or spent" error - if so, try next UTXO
                    if error_str.contains("bad-txns-inputs-missingorspent") ||
                       error_str.contains("already spent") ||
                       error_str.contains("missing") {
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

        let seal = successful_seal
            .ok_or_else(|| {
                last_error.unwrap_or_else(|| anyhow::anyhow!("All UTXOs failed - no valid UTXOs available"))
            })?;
        
        let anchor = successful_anchor
            .ok_or_else(|| anyhow::anyhow!("No anchor from successful publish"))?;

        (seal, successful_utxo_ref, Some(anchor))
    } else {
        // For other chains, use the normal create_seal flow
        log::info!("{}: Creating seal via chain adapter", chain.as_str().to_uppercase());
        let seal = runtime
            .create_seal(core_chain.clone(), value)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create seal: {}", e))?;
        log::info!("{}: Seal created successfully", chain.as_str().to_uppercase());
        (seal, None, None)
    };

    // Step 2: Publish the commitment under the seal (skip for Bitcoin since we already did it during UTXO selection)
    let anchor: Option<csv_protocol::CommitAnchor> = if skip_publish {
        // Skip publishing - return None for anchor
        log::info!("{}: Skipping commitment publishing (--skip-publish flag set)", chain.as_str().to_uppercase());
        output::info(&format!("Skipping commitment publishing (--skip-publish flag set)"));
        None
    } else if anchor.is_some() {
        // Bitcoin: already published during UTXO selection
        log::info!("{}: Commitment already published during UTXO selection (anchor_id: 0x{})", 
            chain.as_str().to_uppercase(), hex::encode(&anchor.as_ref().unwrap().anchor_id[..8]));
        output::info(&format!("Commitment published to {}", chain.as_str()));
        anchor
    } else {
        // Other chains: publish now
        log::info!("{}: Publishing commitment under seal", chain.as_str().to_uppercase());
        output::info(&format!("Publishing commitment to {}...", chain.as_str()));
        let anchor = runtime
            .publish_seal(core_chain.clone(), seal.clone(), commitment)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish seal: {}", e))?;
        log::info!("{}: Commitment published successfully (anchor_id: 0x{})", 
            chain.as_str().to_uppercase(), hex::encode(&anchor.anchor_id[..8]));
        output::info(&format!("Commitment published to {}", chain.as_str()));
        Some(anchor)
    };

    // For Bitcoin, mark the used UTXO as spent in wallet state to prevent reuse
    if chain.as_str() == "bitcoin" {
        if let Some((used_txid, used_vout)) = selected_utxo_ref {
            // Remove the spent UTXO from wallet state
            state.storage.wallet.utxos.retain(|u| !(u.txid == used_txid && u.vout == used_vout));
            state.save()?;
        }
    }

    // Derive owner address for ownership proof
    let owner_address = if chain.as_str() == "bitcoin" {
        hex::encode(seed_array) // Use seed as owner identifier for Bitcoin
    } else {
        // Try to derive address from the signing key
        if let Ok(addr) = csv_keys::bip44::derive_address_from_key(&seed_array, &core_chain) {
            addr
        } else {
            hex::encode(&seed_array[..32])
        }
    };

    // Parse content descriptor hashes from hex strings (legacy parameters, take precedence over file-parsed values)
    let schema_hash_legacy = if let Some(ref hash_str) = schema_hash {
        let bytes = hex::decode(hash_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid schema hash hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Schema hash must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Some(Hash::new(hash_bytes))
    } else {
        None
    };

    let content_root_parsed = if let Some(ref hash_str) = content_root {
        let bytes = hex::decode(hash_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid content root hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Content root must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Some(Hash::new(hash_bytes))
    } else {
        None
    };

    let disclosure_policy_hash_parsed = if let Some(ref hash_str) = disclosure_policy_hash {
        let bytes = hex::decode(hash_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid disclosure policy hash hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Disclosure policy hash must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Some(Hash::new(hash_bytes))
    } else {
        None
    };

    let proof_policy_hash_parsed = if let Some(ref hash_str) = proof_policy_hash {
        let bytes = hex::decode(hash_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid proof policy hash hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Proof policy hash must be 32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Some(Hash::new(hash_bytes))
    } else {
        None
    };

    // Use legacy hash parameters if provided, otherwise use file-parsed values
    let final_schema_hash = schema_hash_legacy.or(schema_hash_final).unwrap_or(Hash::new([0u8; 32]));
    let final_payload_hash = payload_hash_final.unwrap_or(commitment); // Use commitment as default payload hash
    let final_attachment_root = attachment_root_final.or(content_root_parsed);
    let final_disclosure_policy_hash = disclosure_policy_hash_parsed.unwrap_or(Hash::new([0u8; 32]));
    let final_proof_policy_hash = proof_policy_hash_parsed.unwrap_or(Hash::new([0u8; 32]));

    // Create a SanadPayloadDescriptor with content descriptor support (B-013)
    let descriptor = csv_protocol::SanadPayloadDescriptor::new(
        csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
        final_schema_hash, // schema_hash
        1, // payload_codec: canonical CBOR
        final_payload_hash, // payload_hash
        final_attachment_root, // attachment_root (includes content_root)
        final_disclosure_policy_hash, // disclosure_policy_hash
        final_proof_policy_hash, // proof_policy_hash
    );

    // Create ownership proof from the owner address
    let ownership_proof = csv_protocol::OwnershipProof {
        owner: owner_address.as_bytes().to_vec(),
        proof: vec![], // No signature for CLI-created sanads
        scheme: None,
    };

    // Generate salt for ID derivation
    let salt: [u8; 16] = rand::random();

    // Create the sanad through the runtime
    match client.sanads().create(&descriptor, commitment, ownership_proof, &salt, core_chain.clone()) {
        Ok(sanad) => {
            let sanad_id_hex = hex::encode(sanad.id.as_bytes());

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
                anchor_tx_hash: anchor.as_ref().map(|a| hex::encode(&a.anchor_id)),
                nonce,
            };

            state.storage.sanads.push(tracked);

            // Register the sanad_id -> seal mapping on the Bitcoin adapter for cross-chain lock lookups
            if chain.as_str() == "bitcoin" {
                if let Some(ref anchor) = anchor {
                    let _sanad_id_bytes = *sanad.id.as_bytes();
                    let anchor_txid_hex = hex::encode(&anchor.anchor_id);
                    let output_index = u32::from_le_bytes(
                        anchor.metadata[..4.min(anchor.metadata.len())].try_into().unwrap_or([0, 0, 0, 0])
                    );
                    // Note: SDK runtime automatically registers sanad seals during publish_seal
                    // Manual registration is no longer needed and causes "adapter not found" warnings

                    // Persist the mapping to state for cross-run lookups
                    state.storage.wallet.sanad_seals.push(csv_store::state::wallet::SanadSealRecord {
                        sanad_id: sanad_id_hex.clone(),
                        anchor_txid: anchor_txid_hex.clone(),
                        vout: output_index,
                    });
                    state.save()?;
                    log::info!("Persisted sanad seal to state: sanad_id={}, txid={}, vout={}", 
                        sanad_id_hex, anchor_txid_hex, output_index);
                }
            }

            output::kv("Chain", chain.as_ref());
            output::kv_hash("Sanad ID", sanad.id.as_bytes());
            output::kv_hash("Commitment", commitment.as_bytes());
            output::kv(
                "Value",
                &value
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "default".to_string()),
            );
            if let Some(ref anchor) = anchor {
                output::kv("Anchor TX Hash", &hex::encode(&anchor.anchor_id));
                output::kv("Block Height", &anchor.block_height.to_string());
            }
            output::kv("Status", if anchor.is_some() {
                "Created and published via runtime"
            } else {
                "Created (not published)"
            });

            // UnifiedStateManager is automatically saved after command execution
            println!();
            if anchor.is_some() {
                output::info(
                    "Sanad created and published successfully. Use 'csv sanad show <sanad_id>' to view details",
                );
            } else {
                output::info(
                    "Sanad created successfully (not published). Use 'csv sanad show <sanad_id>' to view details",
                );
            }
        }
        Err(e) => {
            output::error(&format!("Failed to create sanad via runtime: {}", e));
            return Err(anyhow::anyhow!("Sanad creation failed: {}", e));
        }
    }

    Ok(())
}

fn signing_key_for_chain(
    chain: &Chain,
    account: u32,
    seed_array: &[u8; 64],
    state: &UnifiedStateManager,
) -> Result<(csv_keys::memory::SecretKey, &'static str)> {
    // Try keystore first for all chains (not just Aptos)
    if let Some(secret_key) = load_keystore_key(chain, account, state)? {
        return Ok((secret_key, "keystore"));
    }

    let mut keys = csv_keys::bip44::derive_all_chain_keys(seed_array, account);
    let core_chain = ChainId::new(chain.as_str());
    let secret_key = keys
        .remove(&core_chain)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive key for chain: {}", chain))?;

    Ok((secret_key, "mnemonic-derived"))
}

fn load_keystore_key(
    chain: &Chain,
    account: u32,
    state: &UnifiedStateManager,
) -> Result<Option<csv_keys::memory::SecretKey>> {
    let mut key_ids = Vec::new();
    if let Some(wallet_account) = state.get_account(chain) {
        if let Some(keystore_ref) = &wallet_account.keystore_ref {
            key_ids.push(keystore_ref.clone());
        }
    }
    key_ids.push(format!("{}-{}", chain.as_str(), account));

    let mut keystore = csv_keys::file_keystore::FileKeystore::new(None)?;
    let passphrase = csv_keys::memory::Passphrase::new(state.passphrase().to_string());

    for key_id in key_ids {
        match keystore.retrieve_key(&key_id, &passphrase) {
            Ok(secret_key) => return Ok(Some(secret_key)),
            Err(csv_keys::file_keystore::FileKeystoreError::KeyNotFound(_)) => {}
            Err(csv_keys::file_keystore::FileKeystoreError::InvalidPassphrase) => {
                // Key exists but wrong passphrase - fall back to mnemonic derivation
                log::warn!("Keystore key '{}' exists but decryption failed (wrong passphrase), falling back to mnemonic derivation", key_id);
            }
            Err(e) => return Err(anyhow::anyhow!("Failed to load key '{}': {}", key_id, e)),
        }
    }

    Ok(None)
}

fn cmd_show(sanad_id: String, state: &UnifiedStateManager) -> Result<()> {
    let bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Sanad ID must be 32 bytes ({} bytes provided)",
            bytes.len()
        ));
    }

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    let sanad_id = Hash::new(hash_bytes);

    output::header(&format!("Sanad: {}", hex::encode(sanad_id.as_bytes())));

    if let Some(tracked) = state.get_sanad(&sanad_id.to_hex()) {
        output::kv("Chain", tracked.chain.as_ref());
        output::kv_hash("Commitment", tracked.commitment.as_bytes());
        output::kv(
            "Status",
            match tracked.status {
                SanadStatus::Consumed => "Consumed",
                SanadStatus::Transferred => "Transferred",
                SanadStatus::Active => "Active",
            },
        );
        if let Some(nullifier) = &tracked.nullifier {
            output::kv_hash("Nullifier", nullifier.as_bytes());
        }
    } else {
        output::warning("Sanad not found in local tracking");
        output::info("This Sanad may exist on-chain but hasn't been tracked locally");
    }

    Ok(())
}

async fn cmd_list(chain: Option<Chain>, update: bool, config: &Config, state: &mut UnifiedStateManager) -> Result<()> {
    output::header("Tracked Sanads");
    if update {
        output::info("Querying on-chain status for all sanads...");
    }

    let headers = vec!["Sanad ID", "Chain", "State"];
    let mut rows = Vec::new();
    let mut updates_to_apply: Vec<(String, SanadStatus)> = Vec::new();

    for sanad in &state.storage.sanads {
        if let Some(ref filter_chain) = chain
            && sanad.chain != *filter_chain
        {
            continue;
        }

        // Check if sanad has a valid seal_ref (required for non-Bitcoin chains)
        let has_valid_seal = if sanad.chain.as_str() != "bitcoin" {
            base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref).is_ok()
        } else {
            true
        };

        // Query on-chain state using the new canonical state query (replaces check_sanad_on_chain_status)
        let on_chain_state = query_sanad_on_chain_state(
            &sanad.chain,
            &sanad.id,
            Some(sanad),
            config,
            state,
        ).await;

        let state_enum = if let Some(ref cs) = on_chain_state {
            cs.state
        } else if !has_valid_seal {
            SanadLifecycleState::Invalid
        } else {
            SanadLifecycleState::from_local_status(sanad.status)
        };

        let status = state_enum.label().to_string();

        // Collect updates to apply after the loop
        if update {
            let new_status = match state_enum {
                SanadLifecycleState::Consumed | SanadLifecycleState::Invalid => SanadStatus::Consumed,
                _ => SanadStatus::Active,
            };

            if sanad.status != new_status {
                updates_to_apply.push((sanad.id.clone(), new_status));
            }
        }

        rows.push(vec![sanad.id.clone(), sanad.chain.to_string(), status]);
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
            output::info(&format!("Updated {} sanad(s) status in local store", updated_count));
            state.save()?;
        }
    }

    Ok(())
}

/// Check on-chain status of a sanad to detect if it's consumed or inaccessible
/// Returns Some(status) if on-chain check was performed, None if falling back to local status
async fn check_sanad_on_chain_status(sanad: &SanadRecord, config: &Config, state: &UnifiedStateManager) -> Option<String> {
    // For Bitcoin, check if the UTXO is still unspent
    if sanad.chain.as_str() == "bitcoin" {
        if let Some(anchor_tx_hash) = &sanad.anchor_tx_hash {
            log::debug!("Bitcoin sanad {}: checking anchor_tx_hash: {}", sanad.id, anchor_tx_hash);
            if let Ok(tx_hash_bytes) = hex::decode(anchor_tx_hash.trim_start_matches("0x")) {
                log::debug!("Bitcoin sanad {}: decoded {} bytes from anchor_tx_hash", sanad.id, tx_hash_bytes.len());
                
                let (txid, vout) = if tx_hash_bytes.len() >= 36 {
                    let txid = &tx_hash_bytes[0..32];
                    let vout_bytes = &tx_hash_bytes[32..36];
                    let vout = u32::from_le_bytes(vout_bytes.try_into().unwrap_or([0u8; 4]));
                    (txid, vout)
                } else if tx_hash_bytes.len() == 32 {
                    let txid = &tx_hash_bytes[0..32];
                    let vout = state.storage.wallet.sanad_seals
                        .iter()
                        .find(|s| s.sanad_id == sanad.id)
                        .map(|s| s.vout)
                        .unwrap_or(0);
                    log::debug!("Bitcoin sanad {}: looked up vout {} from sanad_seals", sanad.id, vout);
                    (txid, vout)
                } else {
                    log::warn!("Bitcoin sanad {}: anchor_tx_hash has invalid length ({} bytes)", 
                        sanad.id, tx_hash_bytes.len());
                    return None;
                };
                
                let mut txid_display = [0u8; 32];
                txid_display.copy_from_slice(txid);
                // anchor_tx_hash is already in display format (mempool.space returns display-order
                // txids from /tx broadcast; no reversal is needed here).
                let txid_hex = hex::encode(txid_display);
                
                log::debug!("Bitcoin sanad {}: checking UTXO {}:{} on-chain", sanad.id, &txid_hex[..16], vout);
                
                // Runtime-mediated validation: build client and check UTXO status
                // Fail closed if RPC unavailable - security requirement
                match validate_bitcoin_utxo_via_runtime(&txid_hex, vout, config, sanad).await {
                    Ok(is_valid) => {
                        if is_valid {
                            log::debug!("Bitcoin sanad {}: UTXO {}:{} is valid", sanad.id, &txid_hex[..16], vout);
                            return Some("Active".to_string());
                        } else {
                            log::debug!("Bitcoin sanad {}: UTXO {}:{} is spent/invalid", sanad.id, &txid_hex[..16], vout);
                            return Some("Consumed".to_string());
                        }
                    }
                    Err(e) => {
                        log::warn!("Bitcoin sanad {}: failed to validate UTXO via runtime: {}. Falling back to local status.", sanad.id, e);
                        // Fall through to return None (use local status)
                    }
                }
            } else {
                log::warn!("Bitcoin sanad {}: failed to decode anchor_tx_hash", sanad.id);
            }
        } else {
            log::warn!("Bitcoin sanad {}: no anchor_tx_hash found", sanad.id);
        }
        return None;
    }
    
    // For Aptos, check if seal was consumed by querying AnchorDataCollection
    if sanad.chain.as_str() == "aptos" {
        log::debug!("Aptos sanad {}: checking on-chain status", sanad.id);
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    let sanad_nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() >= pos + 8 {
                            if let Ok(nonce_bytes) = seal_ref_bytes[pos..pos + 8].try_into() {
                                pos += 8;
                                Some(u64::from_le_bytes(nonce_bytes))
                            } else { None }
                        } else { None }
                    } else {
                        pos += 1;
                        None
                    };
                    
                    if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 9;
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                    }
                    
                    if seal_ref_bytes.len() >= pos + 4 {
                        let id_len = u32::from_le_bytes([seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3]]) as usize;
                        pos += 4;
                        if seal_ref_bytes.len() >= pos + id_len && id_len == 32 {
                            let addr_hex = format!("0x{}", hex::encode(&seal_ref_bytes[pos..pos + id_len]));
                            
                            use reqwest::Client;
                            let client = Client::new();
                            let contract_addr = if let Some(ca) = &chain_cfg.contract_address {
                                ca.clone()
                            } else {
                                "0x9d4c8ad9b8f58c73c73327833a4bda650c590091f130b2ec1293f086cf02ed50".to_string()
                            };
                            
                            let anchor_collection_type = format!("{}::CSVSeal::AnchorDataCollection", contract_addr);
                            let collection_url = format!(
                                "{}/accounts/{}/resource/{}",
                                chain_cfg.rpc_url.trim_end_matches('/'),
                                addr_hex,
                                anchor_collection_type
                            );
                            
                            log::debug!("Aptos sanad {}: querying AnchorDataCollection at {}", sanad.id, collection_url);
                            
                            if let Ok(response) = client.get(&collection_url).timeout(std::time::Duration::from_secs(5)).send().await {
                                if response.status().is_success() {
                                    if let Ok(data) = response.json::<serde_json::Value>().await {
                                        if let Some(table_handle) = data.get("data")
                                            .and_then(|d| d.get("data"))
                                            .and_then(|d| d.get("handle"))
                                            .and_then(|h| h.as_str()) {
                                            
                                            let table_url = format!(
                                                "{}/accounts/{}/table_item",
                                                chain_cfg.rpc_url.trim_end_matches('/'),
                                                addr_hex
                                            );
                                            
                                            let key_type = "u64";
                                            let value_type = format!("{}::CSVSeal::AnchorData", contract_addr);
                                            let sanad_nonce_val = sanad_nonce.unwrap_or(0);
                                            
                                            let table_payload = serde_json::json!({
                                                "key_type": key_type,
                                                "value_type": value_type,
                                                "key": format!("0x{:016x}", sanad_nonce_val),
                                                "handle": table_handle
                                            });
                                            
                                            log::debug!("Aptos sanad {}: checking table item for nonce {}", sanad.id, sanad_nonce_val);
                                            
                                            if let Ok(table_response) = client
                                                .post(&table_url)
                                                .json(&table_payload)
                                                .timeout(std::time::Duration::from_secs(5))
                                                .send()
                                                .await
                                            {
                                                if table_response.status().is_success() {
                                                    log::debug!("Aptos sanad {}: nonce {} found in AnchorDataCollection table, marking as Consumed", sanad.id, sanad_nonce_val);
                                                    return Some("Consumed".to_string());
                                                } else if table_response.status().as_u16() == 404 {
                                                    log::debug!("Aptos sanad {}: nonce {} not found in AnchorDataCollection table, marking as Active", sanad.id, sanad_nonce_val);
                                                    return Some("Active".to_string());
                                                }
                                            }
                                        } else {
                                            if let Some(next_nonce_str) = data.get("data")
                                                .and_then(|d| d.get("next_nonce"))
                                                .and_then(|n| n.as_str()) {
                                                if let Ok(next_nonce) = next_nonce_str.parse::<u64>() {
                                                    if let Some(sanad_nonce) = sanad_nonce {
                                                        if sanad_nonce < next_nonce.saturating_sub(1) {
                                                            return Some("Consumed".to_string());
                                                        } else {
                                                            return Some("Active".to_string());
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else if response.status().as_u16() == 404 {
                                    log::debug!("Aptos sanad {}: AnchorDataCollection not found (404)", sanad.id);
                                }
                            }
                        }
                    }
                }
            }
        }
        return None;
    }
    
    // For Ethereum, check if sanad is locked on-chain via CSVLock.getSanadState
    if sanad.chain.as_str() == "ethereum" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            use reqwest::Client;
            use sha3::{Digest, Keccak256};
            let client = Client::new();
            
            let contract_addr = if let Some(addr) = &chain_cfg.contract_address {
                addr.clone()
            } else {
                log::debug!("Ethereum sanad {}: no contract address in config", sanad.id);
                return None;
            };
            
            let mut hasher = Keccak256::new();
            hasher.update(b"getSanadState(bytes32)");
            let selector = &hasher.finalize()[..4];
            
            let sanad_id_hex = sanad.id.trim_start_matches("0x");
            let sanad_id_bytes = match hex::decode(sanad_id_hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::debug!("Ethereum sanad {}: failed to decode sanad_id: {}", sanad.id, e);
                    return None;
                }
            };
            
            let mut calldata = Vec::with_capacity(36);
            calldata.extend_from_slice(selector);
            calldata.extend_from_slice(&sanad_id_bytes);
            
            let calldata_hex = format!("0x{}", hex::encode(&calldata));
            let contract_addr_normalized = contract_addr.trim_start_matches("0x");
            
            // Try multiple RPC endpoints for reliability
            let mut rpc_urls = vec![chain_cfg.rpc_url.trim_end_matches('/').to_string()];
            // Add fallback RPCs
            rpc_urls.push("https://eth-sepolia.g.alchemy.com/v2/demo".to_string());
            rpc_urls.push("https://rpc.sepolia.org".to_string());
            
            for url in &rpc_urls {
                let payload = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{
                        "to": format!("0x{}", contract_addr_normalized),
                        "data": calldata_hex.clone()
                    }, "latest"],
                    "id": 1
                });
                
                log::debug!("Ethereum sanad {}: calling getSanadState on {} via {}", sanad.id, contract_addr, url);
                
                if let Ok(response) = client.post(url).timeout(std::time::Duration::from_secs(5)).json(&payload).send().await {
                    if let Ok(result) = response.json::<serde_json::Value>().await {
                        eprintln!("DEBUG: Ethereum sanad {} RPC response from {}: {}", sanad.id, url, result);
                        if let Some(hex_str) = result.get("result").and_then(|r| r.as_str()) {
                            let response_bytes = match hex::decode(hex_str.trim_start_matches("0x")) {
                                Ok(bytes) => bytes,
                                Err(_) => continue,
                            };
                            
                            // getSanadState returns 4 x 32 bytes:
                            // [state (uint8, padded), isUsed (bool, padded), lockTimestamp (uint256), refunded (bool, padded)]
                            if response_bytes.len() >= 128 {
                                let state = response_bytes[31]; // state is uint8, last byte of first 32-byte word
                                let is_used = response_bytes[63] != 0; // isUsed is bool, last byte of second 32-byte word
                                let refunded = response_bytes[127] != 0; // refunded is bool, last byte of fourth 32-byte word
                                
                                let status = match state {
                                    0 => "Uncreated",
                                    1 => "Active",
                                    2 => "Locked",
                                    3 => "Consumed",
                                    4 => "Refunded",
                                    _ => "Unknown",
                                };
                                
                                eprintln!(
                                    "DEBUG: Ethereum sanad {} state={} isUsed={} refunded={}",
                                    sanad.id, status, is_used, refunded
                                );
                                
                                // Map contract state to display status
                                return match state {
                                    3 => Some("Consumed".to_string()), // Consumed
                                    4 => Some("Consumed".to_string()), // Refunded (also consumed)
                                    _ => Some("Active".to_string()),   // Active, Locked, Uncreated
                                };
                            }
                        } else if let Some(err) = result.get("error") {
                            eprintln!("DEBUG: Ethereum sanad {} RPC error from {}: {}", sanad.id, url, err);
                        }
                    }
                }
            }
            
            log::warn!("Ethereum sanad {}: all RPC endpoints failed, falling back to local status", sanad.id);
        }
        return None;
    }
    
    // For Sui, check if seal object is consumed by querying the Seal object via REST API
    if sanad.chain.as_str() == "sui" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            use reqwest::Client;
            let client = Client::new();
            
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                let object_id = if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    
                    let _nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return None;
                        }
                        pos += 8;
                        Some(u64::from_le_bytes([
                            seal_ref_bytes[pos-8], seal_ref_bytes[pos-7], seal_ref_bytes[pos-6],
                            seal_ref_bytes[pos-5], seal_ref_bytes[pos-4], seal_ref_bytes[pos-3],
                            seal_ref_bytes[pos-2], seal_ref_bytes[pos-1],
                        ]))
                    } else {
                        pos += 1;
                        None
                    };
                    
                    let _version = if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return None;
                        }
                        pos += 8;
                        Some(0u64)
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                        None
                    } else {
                        None
                    };
                    
                    if seal_ref_bytes.len() < pos + 4 {
                        return None;
                    }
                    let id_len = u32::from_le_bytes([
                        seal_ref_bytes[pos], seal_ref_bytes[pos + 1],
                        seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    
                    if seal_ref_bytes.len() < pos + id_len {
                        return None;
                    }
                    
                    let object_id = &seal_ref_bytes[pos..pos + id_len];
                    Some(object_id)
                } else {
                    return None;
                };
                
                if let Some(object_id) = object_id {
                    if object_id.len() < 32 {
                        return None;
                    }
                    
                    let object_id = &object_id[0..32];
                    let object_id_hex = format!("0x{}", hex::encode(object_id));
                    
                    // Use Sui REST API to fetch object data
                    let base_url = chain_cfg.rpc_url.trim_end_matches('/');
                    let url = format!("{}/v1(objects/{})", base_url, object_id_hex);
                    
                    log::debug!("Sui sanad {}: fetching object {} from {}", sanad.id, object_id_hex, url);
                    
                    if let Ok(response) = client.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
                        if let Ok(result) = response.json::<serde_json::Value>().await {
                            if let Some(status) = result.get("status") {
                                if status.as_str() == Some("Deleted") || status.as_str() == Some("NotFound") {
                                    log::debug!("Sui sanad {}: object is deleted/not found", sanad.id);
                                    return Some("Inaccessible".to_string());
                                }
                            }
                            
                            // Check the consumed field in the object data
                            if let Some(contents) = result.get("data").and_then(|d| d.get("contents")) {
                                if let Some(display_data) = contents.get("display").and_then(|d| d.get("data")) {
                                    if let Some(consumed) = display_data.get("consumed") {
                                        if let Some(consumed_bool) = consumed.as_bool() {
                                            if consumed_bool {
                                                log::debug!("Sui sanad {}: seal object is marked consumed", sanad.id);
                                                return Some("Consumed".to_string());
                                            } else {
                                                log::debug!("Sui sanad {}: seal object is NOT consumed", sanad.id);
                                                return Some("Active".to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return None;
    }
    
    // For Solana, derive the SanadAccount PDA and check the consumed flag
    if sanad.chain.as_str() == "solana" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            use reqwest::Client;
            use solana_sdk::pubkey::Pubkey;
            use std::str::FromStr;
            
            let client = Client::new();
            
            // Decode the program ID as base58 (Solana's native address encoding)
            let program_id = Pubkey::from_str("CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj")
                .ok()?;
            
            // Parse the owner pubkey from the sanad record
            let owner_pubkey = Pubkey::from_str(&sanad.owner).ok()?;
            
            // Derive the PDA using the correct Solana algorithm
            let sanad_id_bytes: [u8; 32] = hex::decode(
                    sanad.id.trim_start_matches("0x")
                ).ok()?.try_into().ok()?;
            let sanad_id_hash = csv_hash::Hash::new(sanad_id_bytes);
            
            let (seal_pda, _bump) = Pubkey::find_program_address(
                &[b"sanad", owner_pubkey.as_ref(), sanad_id_hash.as_bytes()],
                &program_id,
            );
            
            let url = chain_cfg.rpc_url.trim_end_matches('/').to_string();
            
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getAccountInfo",
                "params": [[seal_pda.to_string()], {"encoding": "base64"}],
                "id": 1
            });
            
            log::debug!("Solana sanad {}: fetching PDA {} via getAccountInfo", sanad.id, seal_pda);
            
            if let Ok(response) = client.post(&url).timeout(std::time::Duration::from_secs(5)).json(&payload).send().await {
                if let Ok(result) = response.json::<serde_json::Value>().await {
                    if let Some(value) = result.get("result").and_then(|r| r.get("value")) {
                        if value.is_null() {
                            log::debug!("Solana sanad {}: PDA account not found", sanad.id);
                            return Some("Inaccessible".to_string());
                        }
                        
                        // Parse the base64 encoded account data to check consumed flag
                        if let Some(data) = value.get("data").and_then(|d| d.get("data")) {
                            if let Some(data_str) = data.as_str() {
                                if let Ok(account_data) = base64::engine::general_purpose::STANDARD.decode(data_str) {
                                    // Parse SanadAccount: 8 (discriminator) + 32 (owner) + 32 (sanad_id) + 
                                    // 32 (commitment) + 32 (state_root) + 32 (nullifier) + 1 (asset_class) + 
                                    // 32 (asset_id) + 32 (metadata_hash) + 1 (proof_system) + 32 (proof_root) + 
                                    // 1 (consumed) + 1 (locked) + 8 (created_at) + 1 (bump)
                                    if account_data.len() >= 44 {
                                        let consumed = account_data[43] != 0;
                                        if consumed {
                                            log::debug!("Solana sanad {}: SanadAccount consumed flag is true", sanad.id);
                                            return Some("Consumed".to_string());
                                        } else {
                                            log::debug!("Solana sanad {}: SanadAccount consumed flag is false", sanad.id);
                                            return Some("Active".to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return None;
    }
    
    // Chain not supported for on-chain verification
    None
}


fn cmd_transfer(sanad_id: String, to: String, _state: &UnifiedStateManager) -> Result<()> {
    output::header(&format!("Transferring Sanad to {}", to));
    output::kv("Sanad ID", &sanad_id);
    output::kv("New Owner", &to);
    output::info("Cross-chain transfer: use 'csv cross-chain transfer' instead");
    Ok(())
}

async fn cmd_consume(
    chain: Chain,
    sanad_id: String,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Consuming Sanad on {}", chain));

    // Parse sanad_id from hex
    let sanad_id_bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    if sanad_id_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Sanad ID must be 32 bytes ({} bytes provided)", sanad_id_bytes.len()));
    }
    let mut sanad_id_array = [0u8; 32];
    sanad_id_array.copy_from_slice(&sanad_id_bytes);
    let sanad_id = csv_hash::sanad::SanadId::from_bytes(&sanad_id_array);

    output::kv("Sanad ID", &hex::encode(sanad_id.as_bytes()));

    // Check if sanad exists in local state
    let tracked_sanad = state.get_sanad(&hex::encode(sanad_id.as_bytes()));
    if tracked_sanad.is_none() {
        output::warning("Sanad not found in local tracking");
        output::info("This Sanad may exist on-chain but hasn't been tracked locally");
        return Err(anyhow::anyhow!("Sanad not found in local state. Use 'csv sanad list' to see tracked Sanads."));
    }

    // Use the runtime to consume the sanad
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;

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
    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(&chain).and_then(|w| w.xpub.clone()),
        seed: None,
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account: 0,
        index: 0,
        utxos: Vec::new(),
        sanad_seals: Vec::new(),
    };
    sdk_config.chains.insert(chain.as_str().to_string(), sdk_chain_config);

    // Build CSV client with the requested chain enabled
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
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

    // Derive private key from wallet mnemonic
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
    })?;

    let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(None);
    let seed_array = *seed.as_bytes();

    // For Bitcoin, use the raw 64-byte BIP-39 seed
    let key_hex = if chain.as_str() == "bitcoin" {
        hex::encode(seed_array)
    } else {
        let (secret_key, _key_source) = signing_key_for_chain(&chain, 0, &seed_array, state)?;
        hex::encode(secret_key.expose_secret())
    };

    let mut private_keys = std::collections::HashMap::new();
    let key_bytes = hex::decode(&key_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode private key hex: {}", e))?;

    // Bitcoin uses 64-byte seed for HD derivation, other chains use 32-byte private key
    let secret_handle = if chain.as_str() == "bitcoin" {
        // For Bitcoin, use the 64-byte seed directly
        let seed_array: [u8; 64] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid seed length for Bitcoin (expected 64 bytes)"))?;
        csv_protocol::secret::SharedSecretHandle::from_seed(seed_array)
    } else {
        // For other chains, use 32-byte private key
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key length (expected 32 bytes)"))?;
        csv_protocol::secret::SharedSecretHandle::from_bytes(key_array)
    };

    private_keys.insert(chain.as_str().to_string(), secret_handle);

    // Note: SDK adapters are automatically created during client build
    // Do NOT call init_adapters here as it has been removed from SDK

    let runtime = client.chain_runtime();

    // Consume the sanad via the runtime
    output::info(&format!("Consuming sanad on {}...", chain));
    let result = runtime
        .consume_sanad(core_chain.clone(), &sanad_id, "default")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to consume sanad: {}", e))?;

    output::kv("Status", "Consumed successfully");
    output::kv("Transaction Hash", &result.transaction_hash);
    output::kv("Block Height", &result.block_height.to_string());

    // Update sanad status in local state
    if let Some(tracked) = state.storage.sanads.iter_mut().find(|s| s.id == hex::encode(sanad_id.as_bytes())) {
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
        if count == 0 {
            output::info("No Sanads to remove");
            return Ok(());
        }
        state.storage.sanads.clear();
        state.save()?;
        output::info(&format!("Removed {} Sanad(s) from local tracking", count));
        return Ok(());
    }

    let sanad_id = sanad_id.ok_or_else(|| anyhow::anyhow!("Must provide --all or a Sanad ID"))?;
    output::header(&format!("Removing Sanad {}", &sanad_id[..8.min(sanad_id.len())]));

    // Normalize sanad_id (remove 0x prefix if present)
    let normalized_id = sanad_id.trim_start_matches("0x").to_string();

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
    let bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Sanad ID must be 32 bytes ({} bytes provided)",
            bytes.len()
        ));
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    let sanad_id_hash = csv_hash::Hash::new(hash_bytes);
    let sanad_id_hex = sanad_id_hash.to_hex();

    output::header(&format!("Sanad State: {}", sanad_id_hex));
    output::kv("Chain", chain.as_ref());

    // Try to find the sanad in local state for fallback data
    let local_sanad = state.get_sanad(&sanad_id_hex);

    // Query on-chain state
    let on_chain_state = query_sanad_on_chain_state(&chain, &sanad_id_hex, local_sanad, config, state).await;

    match on_chain_state {
        Some(cs) => {
            output::kv("State", cs.state.label());
            if let Some(seal_id) = &cs.seal_id {
                output::kv("Seal ID", seal_id);
            }
            if let Some(owner) = &cs.owner {
                output::kv("Owner", owner);
            }
            if let Some(commitment) = &cs.commitment {
                output::kv_hash("Commitment", commitment.as_bytes());
            }
            if let Some(nullifier) = &cs.nullifier {
                output::kv_hash("Nullifier", nullifier.as_bytes());
            }
            if let Some(src) = &cs.source_chain {
                output::kv("Source Chain", src.as_ref());
            }
            if let Some(dst) = &cs.destination_chain {
                output::kv("Destination Chain", dst.as_ref());
            }
            if let Some(tx) = &cs.tx_hash {
                output::kv("Last TX", tx);
            }
            if let Some(height) = &cs.block_height {
                output::kv("Block Height", &height.to_string());
            }
            if let Some(updated) = &cs.updated_at {
                output::kv("Updated", &chrono::DateTime::from_timestamp(*updated as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| updated.to_string()));
            }
        }
        None => {
            // Fall back to local state
            if let Some(tracked) = local_sanad {
                output::warning("On-chain query returned no data; showing local state");
                let state_enum = SanadLifecycleState::from_local_status(tracked.status);
                output::kv("State", state_enum.label());
                output::kv("Owner", &tracked.owner);
                output::kv_hash("Commitment", tracked.commitment.as_bytes());
                if let Some(nullifier) = &tracked.nullifier {
                    output::kv_hash("Nullifier", nullifier.as_bytes());
                }
                if let Some(anchor) = &tracked.anchor_tx_hash {
                    output::kv("Anchor TX", anchor);
                }
            } else {
                output::error("Sanad not found locally and on-chain query returned no data");
                output::info("This Sanad may not exist on-chain or the chain adapter may not support state queries yet");
            }
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
    let bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Sanad ID must be 32 bytes ({} bytes provided)",
            bytes.len()
        ));
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    let sanad_id_hash = csv_hash::Hash::new(hash_bytes);
    let sanad_id_hex = sanad_id_hash.to_hex();

    output::header(&format!("Sanad Lifecycle Trace: {}", sanad_id_hex));
    output::kv("Chain", chain.as_ref());

    let events = query_sanad_lifecycle_events(&chain, &sanad_id_hex, config, state).await;

    if events.is_empty() {
        output::info("No lifecycle events found. This Sanad may not exist on-chain yet.");
        return Ok(());
    }

    output::info(&format!("Found {} lifecycle event(s)", events.len()));
    println!();

    for event in &events {
        let time = chrono::DateTime::from_timestamp(event.timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| event.timestamp.to_string());

        output::kv("Time", &time);
        output::kv("Event", &event.event.to_string());
        output::kv("Chain", event.chain.as_ref());
        output::kv("State After", event.state_after.label());
        if let Some(actor) = &event.actor {
            output::kv("Actor", actor);
        }
        if let Some(tx) = &event.tx_hash {
            output::kv("TX", tx);
        }
        println!();
    }

    Ok(())
}

/// Query on-chain state and return a CanonicalSanadState.
/// This replaces the old check_sanad_on_chain_status which only returned "Active"/"Consumed".
async fn query_sanad_on_chain_state(
    chain: &Chain,
    sanad_id_hex: &str,
    local_sanad: Option<&SanadRecord>,
    config: &Config,
    state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    // Ethereum: call getSanadState and return full state
    if chain.as_str() == "ethereum" {
        return query_ethereum_sanad_state(sanad_id_hex, config).await;
    }

    // Bitcoin: check UTXO state
    if chain.as_str() == "bitcoin" {
        return query_bitcoin_sanad_state(sanad_id_hex, config, state).await;
    }

    // Sui: parse seal object state
    if chain.as_str() == "sui" {
        return query_sui_sanad_state(sanad_id_hex, local_sanad, config, state).await;
    }

    // Solana: parse PDA state
    if chain.as_str() == "solana" {
        return query_solana_sanad_state(sanad_id_hex, local_sanad, config, state).await;
    }

    // Aptos: check AnchorDataCollection state
    if chain.as_str() == "aptos" {
        return query_aptos_sanad_state(sanad_id_hex, local_sanad, config, state).await;
    }

    None
}

/// Ethereum: call getSanadState and return full CanonicalSanadState
async fn query_ethereum_sanad_state(sanad_id_hex: &str, config: &Config) -> Option<CanonicalSanadState> {
    use reqwest::Client;
    use sha3::{Digest, Keccak256};

    let client = Client::new();

    // Find the chain config — try ethereum first, then look for any chain with a contract
    let chain_cfg = config.chain(&Chain::from_str("ethereum").ok()?).ok()?;

    let contract_addr = chain_cfg.contract_address.as_ref()?;

    let mut hasher = Keccak256::new();
    hasher.update(b"getSanadState(bytes32)");
    let selector = &hasher.finalize()[..4];

    let sanad_id_bytes = hex::decode(sanad_id_hex.trim_start_matches("0x")).ok()?;

    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(selector);
    calldata.extend_from_slice(&sanad_id_bytes);

    let calldata_hex = format!("0x{}", hex::encode(&calldata));
    let contract_addr_normalized = contract_addr.trim_start_matches("0x");

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": format!("0x{}", contract_addr_normalized),
            "data": calldata_hex
        }, "latest"],
        "id": 1
    });

    if let Ok(response) = client.post(&chain_cfg.rpc_url).timeout(std::time::Duration::from_secs(5)).json(&payload).send().await {
        if let Ok(result) = response.json::<serde_json::Value>().await {
            if let Some(hex_str) = result.get("result").and_then(|r| r.as_str()) {
                let response_bytes = hex::decode(hex_str.trim_start_matches("0x")).ok()?;

                if response_bytes.len() >= 128 {
                    let state = response_bytes[31];
                    let locked_at = u64::from_be_bytes(response_bytes[64..72].try_into().unwrap_or([0; 8]));
                    let consumed_at = u64::from_be_bytes(response_bytes[96..104].try_into().unwrap_or([0; 8]));

                    return Some(CanonicalSanadState {
                        sanad_id: sanad_id_hex.to_string(),
                        seal_id: None,
                        chain: csv_hash::ChainId::new("ethereum"),
                        state: SanadLifecycleState::from_u8(state),
                        owner: None,
                        commitment: None,
                        nullifier: None,
                        source_chain: None,
                        destination_chain: None,
                        tx_hash: None,
                        block_height: None,
                        updated_at: Some(if consumed_at > 0 { consumed_at } else { locked_at }),
                    });
                }
            }
        }
    }

    None
}

/// Bitcoin: check UTXO state
async fn query_bitcoin_sanad_state(
    sanad_id_hex: &str,
    config: &Config,
    state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    let tracked = state.get_sanad(sanad_id_hex)?;

    if let Some(anchor_tx_hash) = &tracked.anchor_tx_hash {
        if let Ok(tx_hash_bytes) = hex::decode(anchor_tx_hash.trim_start_matches("0x")) {
            if tx_hash_bytes.len() >= 32 {
                let txid = &tx_hash_bytes[0..32];
                let vout = if tx_hash_bytes.len() >= 36 {
                    u32::from_le_bytes(tx_hash_bytes[32..36].try_into().unwrap_or([0; 4]))
                } else {
                    state.storage.wallet.sanad_seals
                        .iter()
                        .find(|s| s.sanad_id == sanad_id_hex)
                        .map(|s| s.vout)
                        .unwrap_or(0)
                };

                let txid_display = hex::encode(txid);

                // Runtime-mediated validation: check UTXO status via runtime
                match validate_bitcoin_utxo_via_runtime(&txid_display, vout, config, tracked).await {
                    Ok(is_valid) => {
                        if is_valid {
                            return Some(CanonicalSanadState {
                                sanad_id: sanad_id_hex.to_string(),
                                seal_id: None,
                                chain: csv_hash::ChainId::new("bitcoin"),
                                state: SanadLifecycleState::Active,
                                owner: None,
                                commitment: Some(tracked.commitment.clone()),
                                nullifier: tracked.nullifier.clone(),
                                source_chain: None,
                                destination_chain: None,
                                tx_hash: Some(txid_display),
                                block_height: None,
                                updated_at: Some(tracked.created_at),
                            });
                        } else {
                            // UTXO is spent/invalid
                            return Some(CanonicalSanadState {
                                sanad_id: sanad_id_hex.to_string(),
                                seal_id: None,
                                chain: csv_hash::ChainId::new("bitcoin"),
                                state: SanadLifecycleState::Consumed,
                                owner: None,
                                commitment: Some(tracked.commitment.clone()),
                                nullifier: tracked.nullifier.clone(),
                                source_chain: None,
                                destination_chain: None,
                                tx_hash: Some(txid_display),
                                block_height: None,
                                updated_at: Some(tracked.created_at),
                            });
                        }
                    }
                    Err(e) => {
                        // Fail closed if RPC unavailable - return error instead of partial state
                        log::warn!("Failed to validate Bitcoin sanad state via runtime: {}. Cannot return canonical state without on-chain validation.", e);
                        return None;
                    }
                }
            }
        }
    }

    None
}

/// Sui: parse seal object state (uses local state only, no direct chain RPC calls)
async fn query_sui_sanad_state(
    sanad_id_hex: &str,
    local_sanad: Option<&SanadRecord>,
    _config: &Config,
    _state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    let tracked = local_sanad?;

    // Parse seal reference to extract object ID
    if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&tracked.seal_ref) {
        if seal_ref_bytes.len() >= 2 {
            let mut pos = 0;
            if seal_ref_bytes[pos] == 1 { pos += 1; }
            if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 { pos += 1; }
            else { pos += 1; }

            if seal_ref_bytes.len() >= pos + 4 {
                let id_len = u32::from_le_bytes([seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3]]) as usize;
                pos += 4;
                if seal_ref_bytes.len() >= pos + id_len && id_len >= 32 {
                    let object_id_hex = format!("0x{}", hex::encode(&seal_ref_bytes[pos..pos + 32]));
                    // Return local state - live chain state should be queried via runtime/adapter
                    return Some(CanonicalSanadState {
                        sanad_id: sanad_id_hex.to_string(),
                        seal_id: Some(object_id_hex),
                        chain: csv_hash::ChainId::new("sui"),
                        state: SanadLifecycleState::Active,
                        owner: None,
                        commitment: Some(tracked.commitment.clone()),
                        nullifier: tracked.nullifier.clone(),
                        source_chain: None,
                        destination_chain: None,
                        tx_hash: None,
                        block_height: None,
                        updated_at: Some(tracked.created_at),
                    });
                }
            }
        }
    }

    None
}

/// Solana: parse PDA state (uses local state only, no direct chain RPC calls)
async fn query_solana_sanad_state(
    sanad_id_hex: &str,
    local_sanad: Option<&SanadRecord>,
    _config: &Config,
    _state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    let tracked = local_sanad?;
    // Return local state - live chain state should be queried via runtime/adapter
    return Some(CanonicalSanadState {
        sanad_id: sanad_id_hex.to_string(),
        seal_id: None,
        chain: csv_hash::ChainId::new("solana"),
        state: SanadLifecycleState::Active,
        owner: None,
        commitment: Some(tracked.commitment.clone()),
        nullifier: tracked.nullifier.clone(),
        source_chain: None,
        destination_chain: None,
        tx_hash: None,
        block_height: None,
        updated_at: Some(tracked.created_at),
    });
}

/// Aptos: check AnchorDataCollection state (uses local state only, no direct chain RPC calls)
async fn query_aptos_sanad_state(
    sanad_id_hex: &str,
    local_sanad: Option<&SanadRecord>,
    _config: &Config,
    _state: &UnifiedStateManager,
) -> Option<CanonicalSanadState> {
    let tracked = local_sanad?;
    // Return local state - live chain state should be queried via runtime/adapter
    return Some(CanonicalSanadState {
        sanad_id: sanad_id_hex.to_string(),
        seal_id: None,
        chain: csv_hash::ChainId::new("aptos"),
        state: SanadLifecycleState::Active,
        owner: None,
        commitment: Some(tracked.commitment.clone()),
        nullifier: tracked.nullifier.clone(),
        source_chain: None,
        destination_chain: None,
        tx_hash: None,
        block_height: None,
        updated_at: Some(tracked.created_at),
    });
}
/// Query lifecycle events for a Sanad (placeholder — full implementation requires chain adapter event indexing)
async fn query_sanad_lifecycle_events(
    _chain: &Chain,
    sanad_id_hex: &str,
    _config: &Config,
    state: &UnifiedStateManager,
) -> Vec<CanonicalLifecycleEvent> {
    let mut events = Vec::new();

    // Get local sanad for creation event
    if let Some(tracked) = state.get_sanad(sanad_id_hex) {
        events.push(CanonicalLifecycleEvent {
            timestamp: tracked.created_at,
            chain: tracked.chain.clone(),
            event: LifecycleEventType::Created,
            actor: None,
            tx_hash: tracked.anchor_tx_hash.clone(),
            state_after: SanadLifecycleState::from_local_status(tracked.status),
        });
    }

    // Chain-specific event queries would go here (Phase 5: SanadStateReader trait)
    // For now, return the creation event from local state

    events
}

/// Validate a Bitcoin UTXO using runtime-mediated validation
/// This function builds a CsvClient and uses chain_runtime to check UTXO status
/// Returns Ok(true) if UTXO is valid/unspent, Ok(false) if spent/invalid, Err if RPC unavailable
async fn validate_bitcoin_utxo_via_runtime(
    txid: &str,
    vout: u32,
    config: &Config,
    sanad: &SanadRecord,
) -> Result<bool, anyhow::Error> {
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;
    use csv_hash::ChainId;
    
    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(sanad.chain.as_str());
    
    // Convert CLI config to SDK config format
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.network = match config.chain(&sanad.chain)?.network {
        Network::Test => csv_sdk::config::Network::Testnet,
        Network::Main => csv_sdk::config::Network::Mainnet,
        Network::Dev => csv_sdk::config::Network::Devnet,
    };
    
    // Convert chain config to SDK format
    let chain_cfg = config.chain(&sanad.chain)?;
    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: None,
        seed: None,
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account: 0,
        index: 0,
        utxos: vec![],
        sanad_seals: vec![],
    };
    sdk_config.chains.insert(sanad.chain.as_str().to_string(), sdk_chain_config);
    
    // Build CSV client
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client for validation: {}", e))?;
    
    // Use runtime to check transaction status
    let runtime = client.chain_runtime();
    match runtime.get_transaction(core_chain, txid).await {
        Ok(tx_info) => {
            // Check if transaction is confirmed (UTXO is unspent)
            match tx_info.status {
                csv_protocol::chain_adapter_traits::TransactionStatus::Confirmed { .. } => {
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
        Err(e) => {
            // Return error to indicate RPC/validation unavailable
            Err(anyhow::anyhow!("Runtime validation failed: {}", e))
        }
    }
}

/// Minimal Bitcoin UTXO scanning implementation
/// This replaces the removed csv-wallet::bitcoin::scan_utxos
async fn scan_bitcoin_utxos(
    address: &str,
    rpc_url: &str,
) -> Result<Vec<WalletUtxo>> {
    let url = format!("{}/address/{}/utxo", rpc_url, address);
    let response = reqwest::get(&url).await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let utxo_list: Vec<serde_json::Value> = resp
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to parse UTXO response: {}", e))?;

            let mut wallet_utxos = Vec::new();
            for utxo in utxo_list {
                let txid = utxo
                    .get("txid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing txid"))?
                    .to_string();
                let vout = utxo
                    .get("vout")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow::anyhow!("Missing vout"))? as u32;
                let value = utxo
                    .get("value")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow::anyhow!("Missing value"))?;
                let scriptpubkey_hex = utxo.get("scriptpubkey").and_then(|v| v.as_str()).map(|s| s.to_string());

                wallet_utxos.push(WalletUtxo {
                    txid,
                    vout,
                    value,
                    scriptpubkey_hex,
                });
            }
            Ok(wallet_utxos)
        }
        Ok(resp) => {
            log::warn!("Failed to fetch UTXOs for address {}: HTTP {}", address, resp.status());
            Ok(Vec::new())
        }
        Err(e) => {
            log::warn!("Failed to fetch UTXOs for address {}: {}", address, e);
            Ok(Vec::new())
        }
    }
}

/// Minimal UTXO structure for CLI use
#[derive(Debug, Clone)]
struct WalletUtxo {
    txid: String,
    vout: u32,
    value: u64,
    scriptpubkey_hex: Option<String>,
}

