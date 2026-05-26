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

    // Check RPC connectivity using csv-sdk runtime APIs
    print!("\n  Checking RPC connectivity... ");
    use csv_hash::ChainId;
    use csv_sdk::CsvClient;

    let protocol_chain = ChainId::new(chain.as_str());
    match CsvClient::builder()
        .with_chain(protocol_chain.clone())
        .build()
    {
        Ok(client) => {
            // Try to initialize the adapter to verify connectivity
            match tokio::runtime::Runtime::new()
                .map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))
                .and_then(|rt| {
                    rt.block_on(async {
                        client
                            .init_adapters(csv_sdk::prelude::NetworkType::Testnet)
                            .await
                            .map_err(|e| anyhow::anyhow!("Failed to initialize adapters: {}", e))
                    })
                }) {
                Ok(_) => println!("{}", "Connected ✓".green()),
                Err(e) => println!("{} ({})", "Failed ✗".red(), e),
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

    // Use csv-sdk runtime APIs to fetch chain info
    use csv_hash::ChainId;
    use csv_sdk::CsvClient;

    let protocol_chain = ChainId::new(chain.as_str());
    match CsvClient::builder()
        .with_chain(protocol_chain.clone())
        .build()
    {
        Ok(client) => {
            // Try to get chain info through runtime
            match tokio::runtime::Runtime::new()
                .map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))
                .and_then(|rt| {
                    rt.block_on(async {
                        client
                            .init_adapters(csv_sdk::prelude::NetworkType::Testnet)
                            .await
                            .map_err(|e| anyhow::anyhow!("Failed to initialize adapters: {}", e))
                    })
                }) {
                Ok(_) => {
                    output::kv("Endpoint", &chain_config.rpc_url);
                    output::kv("Status", "Connected");
                }
                Err(e) => {
                    output::kv("Endpoint", &chain_config.rpc_url);
                    output::warning(&format!("Could not fetch chain info: {}", e));
                }
            }
        }
        Err(e) => {
            output::kv("Endpoint", &chain_config.rpc_url);
            output::warning(&format!("Failed to initialize client: {}", e));
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
