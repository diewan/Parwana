//! Sanad lifecycle commands

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Subcommand;
use sha2::Digest;

use csv_hash::ChainId;
use csv_hash::Hash;

use crate::config::{Chain, Config, Network};
use crate::output;
use crate::state::{SanadRecord, SanadStatus, UnifiedStateManager};

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
}

pub async fn execute(
    action: SanadAction,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        SanadAction::Create { chain, value, account, index, skip_publish } => {
            cmd_create(chain, value, account, index, skip_publish, config, state).await
        }
        SanadAction::Show { sanad_id } => cmd_show(sanad_id, state),
        SanadAction::List { chain } => cmd_list(chain, config, state).await,
        SanadAction::Transfer { sanad_id, to } => cmd_transfer(sanad_id, to, state),
        SanadAction::Consume { chain, sanad_id } => cmd_consume(chain, sanad_id, config, state).await,
    }
}

async fn cmd_create(
    chain: Chain,
    value: Option<u64>,
    account: u32,
    index: u32,
    skip_publish: bool,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Creating Sanad on {}", chain));

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

            // Use csv-coordinator for wallet operations (architecture compliant)
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::bitcoin::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::bitcoin::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::bitcoin::Network::Dev,
            };
            let address = csv_coordinator::wallet::bitcoin::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

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

        // Use csv-coordinator for wallet operations (architecture compliant)
        let network = match config.chain(&chain)?.network {
            crate::config::Network::Main => csv_coordinator::wallet::bitcoin::Network::Main,
            crate::config::Network::Test => csv_coordinator::wallet::bitcoin::Network::Test,
            crate::config::Network::Dev => csv_coordinator::wallet::bitcoin::Network::Dev,
        };
        let expected_address = csv_coordinator::wallet::bitcoin::derive_funding_address(
            &seed_array,
            network,
            account,
            index,
        ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

        output::kv("Expected Address", &expected_address);
        output::info("Refreshing UTXOs from blockchain...");

        // Clear old UTXOs for this account before scanning
        state.storage.wallet.utxos.retain(|u| u.account != account);

        // Perform the scan
        let (_wallet, wallet_utxos) = csv_coordinator::wallet::bitcoin::scan_utxos_with_wallet(
            &seed_array,
            network,
            account,
            20, // gap_limit
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

            // Validate UTXO is still unspent on-chain BEFORE adding to state
            match csv_coordinator::wallet::bitcoin::validate_utxo_onchain(&utxo.txid, utxo.vout, &rpc_url).await {
                Ok((tx_exists, is_confirmed, is_unspent, _)) => {
                    if !tx_exists {
                        output::warning(&format!("    Skipping UTXO - transaction not found on-chain"));
                        continue;
                    }
                    if !is_confirmed {
                        output::warning(&format!("    Skipping UTXO - transaction not confirmed"));
                        continue;
                    }
                    if !is_unspent {
                        output::warning(&format!("    Skipping UTXO - already spent"));
                        continue;
                    }
                    output::info(&format!("    UTXO validated - adding to wallet state"));
                }
                Err(e) => {
                    output::warning(&format!("    Skipping UTXO - validation failed: {}", e));
                    continue;
                }
            }

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
        let pk_hex = hex::encode(secret_key.as_bytes());
        log::info!("CLI LAYER: Private key (first 8 bytes): 0x{}", &pk_hex[..16]);

        // Derive and log the address for this key
        let core_chain = csv_hash::ChainId::new(chain.as_str());
        if let Ok(address) = csv_keys::bip44::derive_address_from_key(secret_key.as_bytes(), &core_chain) {
            log::info!("CLI LAYER: Derived address for {}: {}", chain.as_str().to_uppercase(), address);
            eprintln!("CLI LAYER: Derived address for {}: {}", chain.as_str().to_uppercase(), address);
        }

        pk_hex
    };

    let mut private_keys = std::collections::HashMap::new();
    private_keys.insert(chain.as_str().to_string(), Some(key_hex));

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

    // Create the sanad through the runtime
    match client.sanads().create(commitment, core_chain.clone()) {
        Ok(sanad) => {
            let sanad_id_hex = hex::encode(sanad.id.as_bytes());

            // Convert seal to base64 for storage
            let seal_ref_encoded = STANDARD.encode(seal.to_vec());

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

async fn cmd_list(chain: Option<Chain>, config: &Config, state: &UnifiedStateManager) -> Result<()> {
    output::header("Tracked Sanads");

    let headers = vec!["Sanad ID", "Chain", "Status"];
    let mut rows = Vec::new();

    for sanad in &state.storage.sanads {
        if let Some(ref filter_chain) = chain
            && sanad.chain != *filter_chain
        {
            continue;
        }

        // Check if seal is consumed in registry even if flag not set
        let seal_consumed = state.is_seal_consumed(&sanad.id);
        
        // Check if sanad has a valid seal_ref (required for non-Bitcoin chains)
        let has_valid_seal = if sanad.chain.as_str() != "bitcoin" {
            // For non-Bitcoin chains, check if seal_ref is valid
            base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref).is_ok()
        } else {
            // Bitcoin sanads might not have seal_ref in the same format
            true
        };
        
        // Check on-chain status for accurate detection
        let on_chain_status = check_sanad_on_chain_status(sanad, config, state).await;
        
        let status = if sanad.status == SanadStatus::Consumed || seal_consumed {
            "Consumed".to_string()
        } else if !has_valid_seal {
            // Mark as Inaccessible if seal_ref is invalid (for non-Bitcoin chains)
            "Inaccessible".to_string()
        } else if on_chain_status == "Inaccessible" {
            "Inaccessible".to_string()
        } else if on_chain_status == "Consumed" {
            "Consumed".to_string()
        } else {
            "Active".to_string()
        };

        rows.push(vec![sanad.id.clone(), sanad.chain.to_string(), status]);
    }

    if rows.is_empty() {
        output::info("No Sanads tracked. Use 'csv sanad create' to create one.");
    } else {
        output::table(&headers, &rows);
    }

    Ok(())
}

/// Check on-chain status of a sanad to detect if it's consumed or inaccessible
async fn check_sanad_on_chain_status(sanad: &SanadRecord, config: &Config, state: &UnifiedStateManager) -> &'static str {
    // For Bitcoin, check if the UTXO is still unspent
    if sanad.chain.as_str() == "bitcoin" {
        if let Some(anchor_tx_hash) = &sanad.anchor_tx_hash {
            log::debug!("Bitcoin sanad {}: checking anchor_tx_hash: {}", sanad.id, anchor_tx_hash);
            // Parse the anchor_tx_hash to get txid and vout
            // The anchor_tx_hash format is: txid (32 bytes) + vout (4 bytes) in hex
            if let Ok(tx_hash_bytes) = hex::decode(anchor_tx_hash.trim_start_matches("0x")) {
                log::debug!("Bitcoin sanad {}: decoded {} bytes from anchor_tx_hash", sanad.id, tx_hash_bytes.len());
                
                // Handle both formats: 32 bytes (txid only) or 36 bytes (txid + vout)
                let (txid, vout) = if tx_hash_bytes.len() >= 36 {
                    let txid = &tx_hash_bytes[0..32];
                    let vout_bytes = &tx_hash_bytes[32..36];
                    let vout = u32::from_le_bytes(vout_bytes.try_into().unwrap_or([0u8; 4]));
                    (txid, vout)
                } else if tx_hash_bytes.len() == 32 {
                    // Only txid, need to look up vout from sanad_seals
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
                    return "Active";
                };
                
                // Convert txid to display format (reverse byte order for Bitcoin)
                let mut txid_display = [0u8; 32];
                txid_display.copy_from_slice(txid);
                txid_display.reverse();
                let txid_hex = hex::encode(txid_display);
                
                log::debug!("Bitcoin sanad {}: checking UTXO {}:{} on-chain", sanad.id, &txid_hex[..16], vout);
                
                // Check if UTXO is still unspent on-chain
                if let Ok(chain_cfg) = config.chain(&sanad.chain) {
                    match csv_coordinator::wallet::bitcoin::validate_utxo_onchain(&txid_hex, vout, &chain_cfg.rpc_url).await {
                        Ok((tx_exists, is_confirmed, is_unspent, _)) => {
                            log::debug!("Bitcoin sanad {}: UTXO status - exists={}, confirmed={}, unspent={}", 
                                sanad.id, tx_exists, is_confirmed, is_unspent);
                            if !tx_exists || !is_confirmed {
                                return "Inaccessible";
                            }
                            if !is_unspent {
                                return "Consumed";
                            }
                        }
                        Err(e) => {
                            log::warn!("Bitcoin sanad {}: failed to validate UTXO on-chain: {}", sanad.id, e);
                        }
                    }
                }
            } else {
                log::warn!("Bitcoin sanad {}: failed to decode anchor_tx_hash", sanad.id);
            }
        } else {
            log::warn!("Bitcoin sanad {}: no anchor_tx_hash found", sanad.id);
        }
    }
    
    // For Aptos, check if seal resource is still available
    if sanad.chain.as_str() == "aptos" {
        log::debug!("Aptos sanad {}: checking seal status", sanad.id);
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            // Check if the seal resource exists on-chain by querying the account
            // Parse the seal_ref to get the account address
            // The seal_ref is a core SealPoint serialized with format:
            // [nonce_flag(1) | nonce_bytes(8 if flag=1) | version_flag(1) | version_bytes(8 if flag=1) | id_len(4) | id]
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                log::debug!("Aptos sanad {}: decoded {} bytes from seal_ref", sanad.id, seal_ref_bytes.len());
                
                // Parse the SealPoint format to extract the account address (id field)
                let account_address = if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    
                    // Parse nonce
                    let _nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            log::warn!("Aptos sanad {}: insufficient bytes for nonce", sanad.id);
                            return "Active"; // Default to active if we can't parse
                        }
                        let nonce_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(nonce_bytes))
                    } else {
                        pos += 1;
                        None
                    };
                    
                    log::debug!("Aptos sanad {}: parsed nonce: {:?}", sanad.id, _nonce);
                    
                    // Parse version
                    let _version = if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            log::warn!("Aptos sanad {}: insufficient bytes for version", sanad.id);
                            return "Active"; // Default to active if we can't parse
                        }
                        let version_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(version_bytes))
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                        None
                    } else {
                        None
                    };
                    
                    log::debug!("Aptos sanad {}: parsed version: {:?}", sanad.id, _version);
                    
                    // Parse id length
                    if seal_ref_bytes.len() < pos + 4 {
                        log::warn!("Aptos sanad {}: insufficient bytes for id length", sanad.id);
                        return "Active"; // Default to active if we can't parse
                    }
                    let id_len = u32::from_le_bytes([
                        seal_ref_bytes[pos], seal_ref_bytes[pos + 1],
                        seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    
                    log::debug!("Aptos sanad {}: parsed id length: {}", sanad.id, id_len);
                    
                    // Parse id (account address for Aptos)
                    if seal_ref_bytes.len() < pos + id_len {
                        log::warn!("Aptos sanad {}: insufficient bytes for id (expected {}, have {})", 
                            sanad.id, id_len, seal_ref_bytes.len() - pos);
                        return "Active"; // Default to active if we can't parse
                    }
                    
                    let account_address = &seal_ref_bytes[pos..pos + id_len];
                    log::debug!("Aptos sanad {}: extracted account address ({} bytes)", sanad.id, account_address.len());
                    
                    Some(account_address)
                } else {
                    log::warn!("Aptos sanad {}: seal_ref is too short ({} bytes, expected >= 2)", 
                        sanad.id, seal_ref_bytes.len());
                    return "Active"; // Default to active if we can't parse
                };
                
                if let Some(account_address) = account_address {
                    if account_address.len() != 32 {
                        log::warn!("Aptos sanad {}: account address is not 32 bytes (got {})", 
                            sanad.id, account_address.len());
                        return "Active"; // Default to active if address is invalid
                    }
                    
                    // Use Aptos RPC to check if the seal resource exists
                    use reqwest::Client;
                    let client = Client::new();
                    
                    // Build the resource type for the seal
                    let resource_type = if let Some(contract_addr) = &chain_cfg.contract_address {
                        format!("{}::CSVSeal::Seal", contract_addr)
                    } else {
                        // Default contract address for testnet
                        "0x9d4c8ad9b8f58c73c73327833a4bda650c590091f130b2ec1293f086cf02ed50::CSVSeal::Seal".to_string()
                    };
                    
                    let addr_hex = format!("0x{}", hex::encode(account_address));
                    let url = format!("{}/v1/accounts/{}/resources", chain_cfg.rpc_url.trim_end_matches('/'), addr_hex);
                    
                    log::info!("Aptos sanad {}: checking account {} for resource {}", sanad.id, addr_hex, resource_type);
                    
                    if let Ok(response) = client.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
                        let status = response.status();
                        log::debug!("Aptos sanad {}: API response status: {}", sanad.id, status);
                        
                        if let Ok(resources) = response.json::<serde_json::Value>().await {
                            log::debug!("Aptos sanad {}: resources response: {}", sanad.id, serde_json::to_string(&resources).unwrap_or_else(|_| "failed".to_string()));
                            // Check if the seal resource exists in the resources array
                            if let Some(resource_array) = resources.as_array() {
                                let seal_exists = resource_array.iter().any(|r| {
                                    r.get("type").and_then(|t| t.as_str()) == Some(&resource_type)
                                });
                                
                                log::debug!("Aptos sanad {}: seal resource exists = {}", sanad.id, seal_exists);
                                
                                if !seal_exists {
                                    return "Inaccessible";
                                }
                            } else {
                                // Response might be an error object - check for various error fields
                                if let Some(error_code) = resources.get("error_code") {
                                    log::warn!("Aptos sanad {}: API returned error_code: {:?}", sanad.id, error_code);
                                }
                                if let Some(message) = resources.get("message") {
                                    log::warn!("Aptos sanad {}: API returned message: {:?}", sanad.id, message);
                                }
                                if let Some(error_str) = resources.as_str() {
                                    log::warn!("Aptos sanad {}: API returned error string: {}", sanad.id, error_str);
                                }
                                log::warn!("Aptos sanad {}: resources response is not an array, full response: {}", sanad.id, serde_json::to_string(&resources).unwrap_or_else(|_| "failed".to_string()));
                                // For Aptos, seals are consumed during commitment publishing (consume_seal)
                                // If the resource doesn't exist, it likely means the seal was consumed, not inaccessible
                                // Default to "Active" since we can't determine the actual status from the API
                                log::info!("Aptos sanad {}: seal resource not found, defaulting to Active status (likely consumed during commitment)", sanad.id);
                                return "Active";
                            }
                        } else {
                            log::warn!("Aptos sanad {}: failed to parse resources response", sanad.id);
                        }
                    } else {
                        log::warn!("Aptos sanad {}: failed to query account resources", sanad.id);
                    }
                }
            } else {
                log::warn!("Aptos sanad {}: failed to decode seal_ref", sanad.id);
            }
        } else {
            log::warn!("Aptos sanad {}: failed to get chain config", sanad.id);
        }
    }
    
    // For Ethereum, check if seal/contract is still valid
    if sanad.chain.as_str() == "ethereum" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            // Use Ethereum RPC to check if the seal exists
            use reqwest::Client;
            let client = Client::new();
            
            // Parse seal_ref using SealPoint format to extract the id field
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                let contract_address = if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    
                    // Parse nonce
                    let _nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let nonce_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(nonce_bytes))
                    } else {
                        pos += 1;
                        None
                    };
                    
                    // Parse version
                    let _version = if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let version_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(version_bytes))
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                        None
                    } else {
                        None
                    };
                    
                    // Parse id length
                    if seal_ref_bytes.len() < pos + 4 {
                        return "Active";
                    }
                    let id_len = u32::from_le_bytes([
                        seal_ref_bytes[pos], seal_ref_bytes[pos + 1],
                        seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    
                    // Parse id (contract address for Ethereum)
                    if seal_ref_bytes.len() < pos + id_len {
                        return "Active";
                    }
                    
                    let contract_address = &seal_ref_bytes[pos..pos + id_len];
                    Some(contract_address)
                } else {
                    return "Active";
                };
                
                if let Some(contract_address) = contract_address {
                    if contract_address.len() < 20 {
                        return "Active";
                    }
                    
                    let contract_address = &contract_address[0..20]; // Ethereum addresses are 20 bytes
                    
                    let addr_hex = format!("0x{}", hex::encode(contract_address));
                    let url = format!("{}", chain_cfg.rpc_url.trim_end_matches('/'));
                    
                    // Build JSON-RPC request to check if the seal exists
                    let payload = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "eth_getCode",
                        "params": [addr_hex, "latest"],
                        "id": 1
                    });
                    
                    if let Ok(response) = client.post(&url).timeout(std::time::Duration::from_secs(5)).json(&payload).send().await {
                        if let Ok(result) = response.json::<serde_json::Value>().await {
                            // If result is "0x" or null, the contract doesn't exist
                            if let Some(code) = result.get("result") {
                                if code.as_str() == Some("0x") || code.is_null() {
                                    return "Inaccessible";
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // For Sui, check if seal object is still available
    if sanad.chain.as_str() == "sui" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            // Use Sui RPC to check if the seal object exists
            use reqwest::Client;
            let client = Client::new();
            
            // Parse seal_ref using SealPoint format to extract the id field
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                let object_id = if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    
                    // Parse nonce
                    let _nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let nonce_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(nonce_bytes))
                    } else {
                        pos += 1;
                        None
                    };
                    
                    // Parse version
                    let _version = if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let version_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(version_bytes))
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                        None
                    } else {
                        None
                    };
                    
                    // Parse id length
                    if seal_ref_bytes.len() < pos + 4 {
                        return "Active";
                    }
                    let id_len = u32::from_le_bytes([
                        seal_ref_bytes[pos], seal_ref_bytes[pos + 1],
                        seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    
                    // Parse id (object ID for Sui)
                    if seal_ref_bytes.len() < pos + id_len {
                        return "Active";
                    }
                    
                    let object_id = &seal_ref_bytes[pos..pos + id_len];
                    Some(object_id)
                } else {
                    return "Active";
                };
                
                if let Some(object_id) = object_id {
                    if object_id.len() < 32 {
                        return "Active";
                    }
                    
                    let object_id = &object_id[0..32]; // Sui object IDs are 32 bytes
                    
                    let object_id_hex = format!("0x{}", hex::encode(object_id));
                    let url = format!("{}/sui/object/{}", chain_cfg.rpc_url.trim_end_matches('/'), object_id_hex);
                    
                    if let Ok(response) = client.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
                        if let Ok(result) = response.json::<serde_json::Value>().await {
                            // Check if object exists and is not deleted
                            if let Some(status) = result.get("status") {
                                if status.as_str() == Some("Deleted") || status.as_str() == Some("NotFound") {
                                    return "Inaccessible";
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // For Solana, check if seal account is still valid
    if sanad.chain.as_str() == "solana" {
        if let Ok(chain_cfg) = config.chain(&sanad.chain) {
            // Use Solana RPC to check if the account exists
            use reqwest::Client;
            let client = Client::new();
            
            // Parse seal_ref using SealPoint format to extract the id field
            if let Ok(seal_ref_bytes) = base64::engine::general_purpose::STANDARD.decode(&sanad.seal_ref) {
                let account_address = if seal_ref_bytes.len() >= 2 {
                    let mut pos = 0;
                    
                    // Parse nonce
                    let _nonce = if seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let nonce_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(nonce_bytes))
                    } else {
                        pos += 1;
                        None
                    };
                    
                    // Parse version
                    let _version = if seal_ref_bytes.len() > pos && seal_ref_bytes[pos] == 1 {
                        pos += 1;
                        if seal_ref_bytes.len() < pos + 8 {
                            return "Active";
                        }
                        let version_bytes = [
                            seal_ref_bytes[pos], seal_ref_bytes[pos + 1], seal_ref_bytes[pos + 2],
                            seal_ref_bytes[pos + 3], seal_ref_bytes[pos + 4], seal_ref_bytes[pos + 5],
                            seal_ref_bytes[pos + 6], seal_ref_bytes[pos + 7],
                        ];
                        pos += 8;
                        Some(u64::from_le_bytes(version_bytes))
                    } else if seal_ref_bytes.len() > pos {
                        pos += 1;
                        None
                    } else {
                        None
                    };
                    
                    // Parse id length
                    if seal_ref_bytes.len() < pos + 4 {
                        return "Active";
                    }
                    let id_len = u32::from_le_bytes([
                        seal_ref_bytes[pos], seal_ref_bytes[pos + 1],
                        seal_ref_bytes[pos + 2], seal_ref_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    
                    // Parse id (account address for Solana)
                    if seal_ref_bytes.len() < pos + id_len {
                        return "Active";
                    }
                    
                    let account_address = &seal_ref_bytes[pos..pos + id_len];
                    Some(account_address)
                } else {
                    return "Active";
                };
                
                if let Some(account_address) = account_address {
                    if account_address.len() < 32 {
                        return "Active";
                    }
                    
                    let account_address = &account_address[0..32]; // Solana addresses are 32 bytes
                    
                    let account_hex = hex::encode(account_address);
                    let url = format!("{}", chain_cfg.rpc_url.trim_end_matches('/'));
                    
                    // Build JSON-RPC request to check account info
                    let payload = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "getAccountInfo",
                        "params": [account_hex],
                        "id": 1
                    });
                    
                    if let Ok(response) = client.post(&url).timeout(std::time::Duration::from_secs(5)).json(&payload).send().await {
                        if let Ok(result) = response.json::<serde_json::Value>().await {
                            // If result.value is null, the account doesn't exist
                            if let Some(value) = result.get("result").and_then(|r| r.get("value")) {
                                if value.is_null() {
                                    return "Inaccessible";
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Return "Active" if we can't determine status or chain is not supported for verification
    "Active"
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
        hex::encode(secret_key.as_bytes())
    };

    let mut private_keys = std::collections::HashMap::new();
    private_keys.insert(chain.as_str().to_string(), Some(key_hex));

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
