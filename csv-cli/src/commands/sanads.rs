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
        SanadAction::Consume { sanad_id } => cmd_consume(sanad_id, state),
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

    // For Bitcoin, load UTXOs from unified state and validate they're still unspent
    let bitcoin_utxos: Option<Vec<(String, u32, u64, Option<String>)>> = if chain.as_str() == "bitcoin" {
        output::info("Loading UTXOs from wallet state...");

        // Derive the expected address for this account/index to validate UTXOs belong to it
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
        output::info("Validating UTXOs belong to this address...");

        // Load UTXOs from unified state that match the account/index
        let matching_utxos: Vec<_> = state.storage.wallet.utxos.iter()
            .filter(|u| u.account == account && u.index == index)
            .collect();

        // Check if we need to auto-scan (no UTXOs or stale UTXOs without script_pubkey)
        let needs_scan = matching_utxos.is_empty() ||
            matching_utxos.iter().any(|u| u.script_pubkey.is_none());

        if needs_scan {
            output::info("No UTXOs found or UTXOs missing script_pubkey - auto-scanning wallet...");

            // Perform the scan
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::bitcoin::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::bitcoin::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::bitcoin::Network::Dev,
            };
            let (_wallet, wallet_utxos) = csv_coordinator::wallet::bitcoin::scan_utxos_with_wallet(
                &seed_array,
                network,
                account,
                20, // gap_limit
                &config.chain(&chain)?.rpc_url,
            ).await.map_err(|e| anyhow::anyhow!("Failed to scan UTXOs: {}", e))?;

            // Clear old UTXOs for this account before adding new ones
            state.storage.wallet.utxos.retain(|u| u.account != account);

            let mut total_utxos = 0;
            let mut total_value = 0u64;

            for utxo in wallet_utxos {
                output::info(&format!("  Discovered UTXO {}:{} ({} sats)", &utxo.txid[..16], utxo.vout, utxo.value));

                // Add UTXO to unified state for persistence with script_pubkey
                let utxo_record = csv_store::state::wallet::UtxoRecord {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                    value: utxo.value,
                    account,
                    index: 0, // TODO: track actual index from derivation_path
                    derivation_path: format!("m/86'/1'/{}'/0/0", account),
                    script_pubkey: utxo.scriptpubkey_hex,
                };
                state.storage.wallet.utxos.push(utxo_record);

                total_utxos += 1;
                total_value += utxo.value;
            }

            state.save()?;

            output::kv("Total UTXOs discovered", &total_utxos.to_string());
            output::kv("Total value", &format!("{} sats", total_value));

            if total_utxos == 0 {
                return Err(anyhow::anyhow!("No UTXOs found on-chain. Send Bitcoin to the funding address first."));
            }
        }

        // Reload matching UTXOs after potential scan
        let matching_utxos: Vec<_> = state.storage.wallet.utxos.iter()
            .filter(|u| u.account == account && u.index == index)
            .collect();

        if !matching_utxos.is_empty() {
            output::info(&format!("Found {} UTXO(s) in wallet state for account {}, index {}", matching_utxos.len(), account, index));

            let mut utxos_to_add = Vec::new();

            for utxo in matching_utxos {
                // Skip UTXOs below minimum threshold (10,000 sats)
                if utxo.value < 10_000 {
                    output::warning(&format!("  UTXO {}:{} ({} sats) is below minimum threshold (10,000 sats), skipping", &utxo.txid[..16], utxo.vout, utxo.value));
                    continue;
                }

                output::info(&format!("  Loaded UTXO {}:{} ({} sats)", &utxo.txid[..16], utxo.vout, utxo.value));

                log::info!(
                    "UTXO {}:{} script_pubkey from state: {:?}",
                    utxo.txid, utxo.vout, utxo.script_pubkey
                );

                // Validate UTXO is still unspent on-chain before attempting to use it
                let rpc_url = config.chain(&chain)?.rpc_url.clone();
                match csv_coordinator::wallet::bitcoin::validate_utxo_onchain(&utxo.txid, utxo.vout, &rpc_url).await {
                    Ok((tx_exists, is_confirmed, is_unspent, _)) => {
                        if !tx_exists {
                            output::warning(&format!("  UTXO {}:{} transaction not found on-chain, skipping", &utxo.txid[..16], utxo.vout));
                            continue;
                        }
                        if !is_confirmed {
                            output::warning(&format!("  UTXO {}:{} transaction not confirmed yet, skipping", &utxo.txid[..16], utxo.vout));
                            continue;
                        }
                        if !is_unspent {
                            output::warning(&format!("  UTXO {}:{} already spent on-chain, removing from state and skipping", &utxo.txid[..16], utxo.vout));
                            continue;
                        }
                    }
                    Err(e) => {
                        output::warning(&format!("  Failed to validate UTXO {}:{} on-chain: {}, skipping", &utxo.txid[..16], utxo.vout, e));
                        continue;
                    }
                }

                // SDK/adapter will handle on-chain validation
                // Pass script_pubkey if available for correct sighash calculation
                utxos_to_add.push((utxo.txid.clone(), utxo.vout, utxo.value, utxo.script_pubkey.clone()));
            }

            if utxos_to_add.is_empty() {
                output::warning(&format!("No valid unspent UTXOs found. Run 'csv wallet scan --chain bitcoin --account {}' to refresh UTXOs.", account));
                None
            } else {
                Some(utxos_to_add)
            }
        } else {
            output::warning(&format!("No UTXOs found in wallet state for account {}, index {}. Run 'csv wallet scan --chain bitcoin --account {}' to discover UTXOs.", account, index, account));
            None
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
            // Debug: print the txid being passed to SDK
            eprintln!("DEBUG: Passing UTXO to SDK: txid={}, vout={}", txid, vout);
            csv_sdk::config::UtxoConfig {
                txid: txid.clone(),
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

    // Derive chain-specific private key using BIP-44
    let keys = csv_keys::bip44::derive_all_chain_keys(&seed_array, account);
    let core_chain = ChainId::new(chain.as_str());
    let secret_key = keys
        .get(&core_chain)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive key for chain: {}", chain))?;

    // Use the chain-specific private key (32 bytes) instead of the raw seed (64 bytes)
    let private_key_hex = hex::encode(secret_key.as_bytes());

    let mut private_keys = std::collections::HashMap::new();
    private_keys.insert(chain.as_str().to_string(), Some(private_key_hex));

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
    let (seal, selected_utxo_ref) = if chain.as_str() == "bitcoin" {
        // Select the largest UTXO from the loaded state to avoid dust/tiny amounts
        let selected_utxo = bitcoin_utxos.as_ref()
            .and_then(|utxos: &Vec<(String, u32, u64, Option<String>)>| {
                // Sort by value descending and pick the largest
                let mut sorted: Vec<_> = utxos.iter().collect();
                sorted.sort_by_key(|u| std::cmp::Reverse(u.2)); // Sort by value (index 2) descending
                sorted.first().copied()
            })
            .ok_or_else(|| anyhow::anyhow!("No UTXOs available. Run 'csv wallet scan --chain bitcoin' first."))?;

        output::info(&format!("Using UTXO {}:{} ({} sats) for seal", &selected_utxo.0[..16], selected_utxo.1, selected_utxo.2));

        // Convert txid to bytes
        let txid_bytes = hex::decode(&selected_utxo.0)
            .map_err(|e| anyhow::anyhow!("Invalid txid: {}", e))?;
        if txid_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid txid length"));
        }
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid_bytes);

        // Create a seal from the UTXO
        let mut id_bytes = Vec::with_capacity(36);
        id_bytes.extend_from_slice(&txid_array);
        id_bytes.extend_from_slice(&selected_utxo.1.to_le_bytes());

        let seal = csv_hash::seal::SealPoint {
            id: id_bytes,
            nonce: Some(selected_utxo.2),
        };

        (seal, Some((selected_utxo.0.clone(), selected_utxo.1)))
    } else {
        // For other chains, use the normal create_seal flow
        let seal = runtime
            .create_seal(core_chain.clone(), value)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create seal: {}", e))?;
        (seal, None)
    };

    // Step 2: Publish the commitment under the seal
    let anchor = runtime
        .publish_seal(core_chain.clone(), seal.clone(), commitment)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to publish seal: {}", e))?;

    // For Bitcoin, mark the used UTXO as spent in wallet state to prevent reuse
    if chain.as_str() == "bitcoin" {
        if let Some((used_txid, used_vout)) = selected_utxo_ref {
            // Remove the spent UTXO from wallet state
            state.storage.wallet.utxos.retain(|u| !(u.txid == used_txid && u.vout == used_vout));
            state.save()?;
            output::info(&format!("Marked UTXO {}:{} as spent", &used_txid[..16], used_vout));
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

fn cmd_consume(sanad_id: String, _state: &UnifiedStateManager) -> Result<()> {
    output::header("Consuming Sanad");
    output::kv("Sanad ID", &sanad_id);
    output::info("This will consume the seal and make the Sanad unusable");
    Ok(())
}
