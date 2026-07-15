//! Wallet balance checking commands (Phase 5 Compliant).
//!
//! Uses csv-sdk runtime APIs only - no direct chain adapter dependencies.
//! Uses centralized wallet identity resolver from csv-runtime.

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;
use anyhow::Result;

use crate::wallet_identity::WalletIdentity;
use csv_hash::ChainId;
use csv_keys::Mnemonic;
use csv_sdk::CsvClient;
use csv_sdk::StoreBackend;

/// Check balance for a specific chain.
pub async fn cmd_balance(
    chain: Chain,
    address: Option<String>,
    account: u32,
    index: u32,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    // Use centralized wallet identity resolver for address derivation
    let address = if address.is_none() {
        if state.storage.wallet.mnemonic.is_some() {
            Some(WalletIdentity::from_state(state)?.address(&chain, account, index)?)
        } else {
            state.get_address(&chain).map(|s| s.to_string())
        }
    } else {
        address
    };

    if let Some(addr) = address {
        output::header(&format!("{} Balance", chain));
        output::kv("Address", &addr);

        // Query balance from chain using csv-sdk runtime
        match query_balance(&chain, &addr, config, state).await {
            Ok(balance) => {
                output::kv("Balance", &format!("{} {}", balance, chain_symbol(&chain)));
            }
            Err(e) => {
                output::error(&format!("Failed to query balance: {}", e));
            }
        }
    } else {
        output::warning(&format!("No {} address found in wallet", chain));
        output::info(&format!(
            "Generate one with: csv wallet generate --chain {}",
            chain
        ));
    }

    Ok(())
}

/// List all wallets.
pub fn cmd_list(
    chain_filter: Option<Chain>,
    account: u32,
    index: u32,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Wallet Addresses");

    let chains = if let Some(ref chain) = chain_filter {
        vec![chain.clone()]
    } else {
        vec![
            Chain::new("bitcoin"),
            Chain::new("ethereum"),
            Chain::new("sui"),
            Chain::new("aptos"),
            Chain::new("solana"),
        ]
    };

    let mut found_any = false;
    for chain in chains {
        // Use csv-keys bip44 derivation for all chains (consistent with wallet init)
        if state.storage.wallet.mnemonic.is_some() {
            let derived_address =
                WalletIdentity::from_state(state)?.address(&chain, account, index)?;

            output::kv(
                &format!("{} (account {}, index {})", chain, account, index),
                &derived_address,
            );
            found_any = true;
        } else {
            // Fallback to stored address if no mnemonic
            if let Some(address) = state.get_address(&chain) {
                output::kv(&format!("{}", chain), address);
                found_any = true;
            }
        }
    }

    if !found_any {
        output::warning("No wallets found");
        output::info("Generate wallets with: csv wallet generate --chain <chain>");
        output::info("Or use one-command setup: csv wallet init");
    }

    Ok(())
}

/// Query balance from chain using csv-sdk runtime APIs.
///
/// This function uses only the unified CsvClient runtime, avoiding direct
/// chain adapter dependencies per Phase 5 of the Production Guarantee Plan.
async fn query_balance(
    chain: &Chain,
    address: &str,
    config: &Config,
    state: &UnifiedStateManager,
) -> Result<f64> {
    use csv_sdk::config::{ChainConfig, StoreConfig};
    use csv_sdk::prelude::NetworkType;
    use std::collections::HashMap;

    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(chain.as_str());

    // Build SDK config from CLI config, passing through seed for Bitcoin
    let sdk_chain = config.chains.get(&core_chain.clone()).cloned();
    let wallet_xpub = config
        .wallets
        .get(&core_chain.clone())
        .and_then(|w| w.xpub.clone());

    // For Bitcoin, derive seed from mnemonic if available
    let wallet_seed = if chain.as_str() == "bitcoin" {
        if let Some(mnemonic_phrase) = &state.storage.wallet.mnemonic {
            let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)
                .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
            let seed = mnemonic.to_seed(None);
            Some(hex::encode(seed.as_bytes()))
        } else {
            None
        }
    } else {
        None
    };

    let mut sdk_chains = HashMap::new();
    if let Some(cc) = &sdk_chain {
        let rpc = crate::config::sdk_rpc_config(core_chain.as_str(), cc);
        sdk_chains.insert(
            core_chain.to_string(),
            ChainConfig {
                rpc,
                finality_depth: cc.finality_depth as u32,
                enabled: true,
                xpub: wallet_xpub,
                seed: wallet_seed,
                contract_address: cc.contract_address.clone(),
                program_id: cc.program_id.clone(),
                account: 0,
                index: 0,
                utxos: Vec::new(),
                sanad_seals: Vec::new(),
            },
        );
    } else {
        // No per-chain config: use the reviewed built-in policy for the chain
        // and network (RFC-0013), with seed/xpub from wallet config below.
        let sdk_net = if config.network().is_testnet() {
            csv_sdk::config::Network::Testnet
        } else {
            csv_sdk::config::Network::Mainnet
        };
        let rpc = csv_sdk::config::Config::builtin_rpc(core_chain.as_str(), sdk_net, None, None)
            .unwrap_or_default();
        sdk_chains.insert(
            core_chain.to_string(),
            ChainConfig {
                rpc,
                finality_depth: 6,
                enabled: true,
                xpub: wallet_xpub,
                seed: wallet_seed,
                contract_address: None,
                program_id: config
                    .chain(&core_chain)
                    .ok()
                    .and_then(|c| c.program_id.clone()),
                account: 0,
                index: 0,
                utxos: Vec::new(),
                sanad_seals: Vec::new(),
            },
        );
    }

    let sdk_config = csv_sdk::config::Config {
        network: if config.network().is_testnet() {
            csv_sdk::config::Network::Testnet
        } else {
            csv_sdk::config::Network::Mainnet
        },
        chains: sdk_chains,
        store: StoreConfig::default(),
        log_level: None,
        data_dir: None,
        remote: None,
    };

    // Build CSV client with the requested chain enabled and config
    let client_builder = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_store_backend(StoreBackend::InMemory)
        .with_config(sdk_config);

    let client = client_builder
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    // Get chain runtime and query balance through the unified runtime
    let clean_address = address.strip_prefix("0x").unwrap_or(address);

    // Initialize adapters with the correct network (testnet by default for CLI)
    let _network = if config.network().is_testnet() {
        NetworkType::Testnet
    } else {
        NetworkType::Mainnet
    };

    // Execute async operations using the existing tokio runtime
    let balance_info = async {
        client
            .chain_runtime()
            .get_balance(core_chain.clone(), clean_address)
            .await
    }
    .await;

    match balance_info {
        Ok(balance_info) => Ok(balance_info.available as f64 / chain_decimals(chain)),
        Err(e) => {
            // Check if it's a configuration error
            if matches!(e, csv_sdk::CsvError::ChainNotEnabled(_)) {
                Err(anyhow::anyhow!(
                    "Balance query via runtime requires RPC configuration. \
                     Please configure the appropriate RPC_URL environment variable for {:?}.",
                    chain
                ))
            } else {
                Err(anyhow::anyhow!("Failed to query balance: {}", e))
            }
        }
    }
}

/// Get symbol for chain.
fn chain_symbol(chain: &Chain) -> &'static str {
    match chain.as_str() {
        "bitcoin" => "BTC",
        "ethereum" => "ETH",
        "sui" => "SUI",
        "aptos" => "APT",
        "solana" => "SOL",
        _ => "???",
    }
}

/// Get decimal places for chain (smallest unit to base unit conversion).
fn chain_decimals(chain: &Chain) -> f64 {
    match chain.as_str() {
        "bitcoin" => 1e8,   // satoshis to BTC
        "ethereum" => 1e18, // wei to ETH
        "sui" => 1e9,       // MIST to SUI
        "aptos" => 1e8,     // octas to APT
        "solana" => 1e9,    // lamports to SOL
        _ => 1e8,           // default to 8 decimals
    }
}
