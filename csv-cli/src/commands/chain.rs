//! Chain management commands

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;

use crate::config::{Chain, Config, Network};
use crate::output;

#[derive(Subcommand)]
pub enum ChainAction {
    /// List all supported chains
    List,
    /// Show chain status and configuration
    Status {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
    },
    /// Show chain RPC endpoint info
    Info {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
    },
    /// Set chain RPC URL
    SetRpc {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// New RPC URL
        url: String,
    },
    /// Set chain network (dev/test/main)
    SetNetwork {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Network
        #[arg(value_enum)]
        network: Network,
    },
    /// Set chain contract address
    SetContract {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Contract/package address
        address: String,
    },
}

pub fn execute(action: ChainAction, config: &Config) -> Result<()> {
    match action {
        ChainAction::List => cmd_list(config),
        ChainAction::Status { chain } => cmd_status(&chain, config),
        ChainAction::Info { chain } => cmd_info(&chain, config),
        ChainAction::SetRpc { chain, url } => cmd_set_rpc(chain, url, config),
        ChainAction::SetNetwork { chain, network } => cmd_set_network(chain, network, config),
        ChainAction::SetContract { chain, address } => cmd_set_contract(chain, address, config),
    }
}

fn cmd_list(config: &Config) -> Result<()> {
    output::header("Supported Chains");

    let headers = vec!["Chain", "Network", "RPC URL", "Finality", "Contract"];
    let mut rows = Vec::new();

    for (chain, chain_config) in &config.chains {
        rows.push(vec![
            format!("{}", chain).to_string(),
            chain_config.network.to_string(),
            chain_config.rpc_url.chars().take(40).collect::<String>(),
            chain_config.finality_depth.to_string(),
            chain_config
                .contract_address
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ]);
    }

    output::table(&headers, &rows);
    println!();
    output::info("Use 'csv chain status <chain>' for details");
    Ok(())
}

fn cmd_status(chain: &Chain, config: &Config) -> Result<()> {
    let chain_config = config.chain(chain)?;

    output::header(&format!("Chain: {}", chain));

    output::kv("Network", &chain_config.network.to_string());
    output::kv("RPC URL", &chain_config.rpc_url);
    output::kv(
        "Chain ID",
        &chain_config
            .chain_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
    );
    output::kv("Finality Depth", &chain_config.finality_depth.to_string());
    output::kv(
        "Contract",
        &chain_config
            .contract_address
            .clone()
            .unwrap_or_else(|| "Not deployed".to_string()),
    );

    if let Some(fee) = chain_config.default_fee {
        output::kv("Default Fee", &fee.to_string());
    }

    // Check RPC connectivity
    print!("\n  Checking RPC connectivity... ");
    match reqwest::blocking::get(&chain_config.rpc_url) {
        Ok(resp) => {
            if resp.status().is_success() || resp.status().is_server_error() {
                println!("{}", "Connected ✓".green());
            } else {
                println!("{} ({})", "Partial".yellow(), resp.status());
            }
        }
        Err(e) => {
            println!("{} ({})", "Failed ✗".red(), e);
        }
    }

    Ok(())
}

fn cmd_info(chain: &Chain, config: &Config) -> Result<()> {
    let chain_config = config.chain(chain)?;

    output::header(&format!("RPC Info: {}", chain));

    // Try to fetch chain info from RPC
    match chain.as_str() {
        "bitcoin" => {
            let url = format!(
                "{}/blocks/tip/height",
                chain_config.rpc_url.trim_end_matches('/')
            );
            match reqwest::blocking::get(&url)?.text() {
                Ok(height) => {
                    output::kv("Current Height", height.trim());
                }
                Err(e) => output::warning(&format!("Could not fetch height: {}", e)),
            }
        }
        "ethereum" => {
            output::info("Ethereum RPC info requires JSON-RPC call (eth_blockNumber)");
            output::kv("Endpoint", &chain_config.rpc_url);
        }
        "sui" => {
            output::info(
                "Sui RPC info requires JSON-RPC call (sui_getLatestCheckpointSequenceNumber)",
            );
            output::kv("Endpoint", &chain_config.rpc_url);
        }
        "aptos" => {
            let url = format!("{}/ledger_info", chain_config.rpc_url.trim_end_matches('/'));
            match reqwest::blocking::get(&url)?.json::<serde_json::Value>() {
                Ok(info) => {
                    if let Some(ledger) = info.get("ledger_info") {
                        if let Some(version) = ledger.get("ledger_version") {
                            output::kv("Ledger Version", version.as_str().unwrap_or("unknown"));
                        }
                        if let Some(epoch) = ledger.get("epoch") {
                            output::kv("Epoch", epoch.as_str().unwrap_or("unknown"));
                        }
                    }
                }
                Err(e) => output::warning(&format!("Could not fetch ledger info: {}", e)),
            }
        }
        "solana" => {
            output::info("Solana RPC info requires JSON-RPC call (getEpochInfo)");
            output::kv("Endpoint", &chain_config.rpc_url);
        }
        _ => {
            output::warning(&format!("Unknown chain: {}", chain));
        }
    }

    Ok(())
}

fn cmd_set_rpc(chain: Chain, url: String, config: &Config) -> Result<()> {
    let mut config_clone = config.clone();
    if let Some(chain_config) = config_clone.chains.get_mut(&chain) {
        chain_config.rpc_url = url.clone();
    }

    // Save updated config
    let path = expand_path("~/.csv/config.toml");
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(&config_clone)?;
    std::fs::write(&path, content)?;

    output::success(&format!("Set {} RPC URL to: {}", chain, url));
    Ok(())
}

fn cmd_set_network(chain: Chain, network: Network, config: &Config) -> Result<()> {
    let mut config_clone = config.clone();
    if let Some(chain_config) = config_clone.chains.get_mut(&chain) {
        chain_config.network = network;
    }

    let path = expand_path("~/.csv/config.toml");
    let content = toml::to_string_pretty(&config_clone)?;
    std::fs::write(&path, content)?;

    output::success(&format!("Set {} network to: {}", chain, network));
    Ok(())
}

fn cmd_set_contract(chain: Chain, address: String, config: &Config) -> Result<()> {
    let mut config_clone = config.clone();
    if let Some(chain_config) = config_clone.chains.get_mut(&chain) {
        chain_config.contract_address = Some(address.clone());
    }

    let path = expand_path("~/.csv/config.toml");
    let content = toml::to_string_pretty(&config_clone)?;
    std::fs::write(&path, content)?;

    output::success(&format!("Set {} contract address to: {}", chain, address));
    Ok(())
}

fn expand_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped).to_string_lossy().to_string();
    }
    path.to_string()
}
