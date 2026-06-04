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
        SanadAction::Create { chain, value, account, index } => {
            cmd_create(chain, value, account, index, config, state).await
        }
        SanadAction::Show { sanad_id } => cmd_show(sanad_id, state),
        SanadAction::List { chain } => cmd_list(chain, state),
        SanadAction::Transfer { sanad_id, to } => cmd_transfer(sanad_id, to, state),
        SanadAction::Consume { chain, sanad_id } => cmd_consume(chain, sanad_id, config, state).await,
    }
}

async fn cmd_create(
    chain: Chain,
    value: Option<u64>,
    account: u32,
    index: u32,
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
            // Convert display format txid to internal byte order for Bitcoin adapter
            // mempool.space returns display format (reversed bytes), but adapter expects internal order
            let txid_bytes = hex::decode(&txid).unwrap_or_default();
            let mut internal_txid = [0u8; 32];
            if txid_bytes.len() == 32 {
                internal_txid.copy_from_slice(&txid_bytes);
                internal_txid.reverse(); // Convert display to internal byte order
            }
            csv_sdk::config::UtxoConfig {
                txid: hex::encode(internal_txid),
                vout,
                value,
                account,
                index,
                script_pubkey: scriptpubkey_hex,
            }
        }).collect(),
    };
    sdk_config.chains.insert(chain.as_str().to_string(), sdk_chain_config);

    // Build CSV client with the requested chain enabled
    eprintln!("CLI LAYER: Building client with SDK config RPC URL: {}", sdk_config.chains.get(chain.as_str()).map(|c| &c.rpc.url).unwrap_or(&"N/A".to_string()));
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    // Initialize chain adapters for the configured network
    let network_type = match config.chain(&chain)?.network {
        Network::Test => csv_sdk::client::NetworkType::Testnet,
        Network::Main => csv_sdk::client::NetworkType::Mainnet,
        Network::Dev => csv_sdk::client::NetworkType::Testnet, // Dev uses testnet
    };

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

    eprintln!("CLI LAYER: Initializing adapters with network type: {:?}", network_type);
    client.init_adapters(network_type, private_keys).await
        .map_err(|e| anyhow::anyhow!("Failed to initialize chain adapters: {}", e))?;

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
        
        // Sort UTXOs by value descending to try largest first
        let mut sorted_utxos: Vec<_> = bitcoin_utxos.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UTXOs available. Run 'csv wallet scan --chain bitcoin' first."))?
            .iter()
            .collect();
        sorted_utxos.sort_by_key(|u| std::cmp::Reverse(u.2)); // Sort by value (index 2) descending

        let mut last_error = None;
        let mut successful_seal = None;
        let mut successful_utxo_ref = None;
        let mut successful_anchor = None;

        // Try UTXOs in order until one succeeds
        for (attempt, selected_utxo) in sorted_utxos.iter().enumerate() {
            output::info(&format!("Attempt {}/{}: Using UTXO {}:{} ({} sats) for seal",
                attempt + 1, sorted_utxos.len(), &selected_utxo.0[..16], selected_utxo.1, selected_utxo.2));

            // Convert txid from display format to internal byte order
            // mempool.space returns display format (reversed bytes), but seal protocol expects internal order
            let txid_bytes = hex::decode(&selected_utxo.0)
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
            id_bytes.extend_from_slice(&selected_utxo.1.to_le_bytes());

            let seal = csv_hash::seal::SealPoint {
                id: id_bytes,
                nonce: Some(selected_utxo.2),
                version: None,
            };

            // Try to publish with this UTXO
            match runtime.publish_seal(core_chain.clone(), seal.clone(), commitment).await {
                Ok(anchor) => {
                    output::info(&format!("Successfully published using UTXO {}:{} ({} sats)", 
                        &selected_utxo.0[..16], selected_utxo.1, selected_utxo.2));
                    successful_seal = Some(seal);
                    successful_utxo_ref = Some((selected_utxo.0.clone(), selected_utxo.1));
                    successful_anchor = Some(anchor);
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    output::warning(&format!("Failed to publish with UTXO {}:{}: {}", 
                        &selected_utxo.0[..16], selected_utxo.1, error_str));
                    
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
    let anchor = if anchor.is_some() {
        // Bitcoin: already published during UTXO selection
        log::info!("{}: Commitment already published during UTXO selection (anchor_id: 0x{})", 
            chain.as_str().to_uppercase(), hex::encode(&anchor.as_ref().unwrap().anchor_id[..8]));
        output::info(&format!("Commitment published to {}", chain.as_str()));
        anchor.unwrap()
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
        anchor
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
                anchor_tx_hash: Some(hex::encode(&anchor.anchor_id)),
            };

            state.storage.sanads.push(tracked);

            output::kv("Chain", chain.as_ref());
            output::kv_hash("Sanad ID", sanad.id.as_bytes());
            output::kv_hash("Commitment", commitment.as_bytes());
            output::kv(
                "Value",
                &value
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "default".to_string()),
            );
            output::kv("Anchor TX Hash", &hex::encode(&anchor.anchor_id));
            output::kv("Block Height", &anchor.block_height.to_string());
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

fn cmd_list(chain: Option<Chain>, state: &UnifiedStateManager) -> Result<()> {
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
        let status = if sanad.status == SanadStatus::Consumed || seal_consumed {
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
    };
    sdk_config.chains.insert(chain.as_str().to_string(), sdk_chain_config);

    // Build CSV client with the requested chain enabled
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    // Initialize chain adapters for the configured network
    let network_type = match config.chain(&chain)?.network {
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

    client.init_adapters(network_type, private_keys).await
        .map_err(|e| anyhow::anyhow!("Failed to initialize chain adapters: {}", e))?;

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
