//! Chain management commands

use anyhow::Result;
use clap::Subcommand;

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
    /// Check chain readiness (signer configuration, contract deployment)
    Readiness {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Account index for HD wallet derivation (default: 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Address index for HD wallet derivation (default: 0)
        #[arg(long, default_value = "0")]
        index: u32,
    },
}

pub async fn execute(action: ChainAction, config: &Config) -> Result<()> {
    match action {
        ChainAction::List => cmd_list(config),
        ChainAction::Status { chain } => cmd_status(&chain, config).await,
        ChainAction::Info { chain } => cmd_info(&chain, config).await,
        ChainAction::SetRpc { chain, url } => cmd_set_rpc(chain, url, config),
        ChainAction::SetNetwork { chain, network } => cmd_set_network(chain, network, config),
        ChainAction::SetContract { chain, address } => cmd_set_contract(chain, address, config),
        ChainAction::Readiness { chain, account, index } => cmd_readiness(&chain, account, index, config).await,
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

async fn cmd_status(chain: &Chain, config: &Config) -> Result<()> {
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

    // Note: RPC connectivity check via SDK requires full adapter configuration
    // including contract addresses. Use 'csv runtime health' for full connectivity checks.
    println!();

    Ok(())
}

async fn cmd_info(chain: &Chain, config: &Config) -> Result<()> {
    let chain_config = config.chain(chain)?;

    output::header(&format!("RPC Info: {}", chain));

    output::kv("Endpoint", &chain_config.rpc_url);
    output::kv("Network", &chain_config.network.to_string());

    // Note: For full chain connectivity checks, use 'csv runtime health'
    output::info("Use 'csv runtime health' for connectivity checks");

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

async fn cmd_readiness(chain: &Chain, account: u32, index: u32, config: &Config) -> Result<()> {
    let chain_config = config.chain(chain)?;

    output::header(&format!("Chain Readiness: {}", chain));

    output::kv("Account", &account.to_string());
    output::kv("Index", &index.to_string());

    // Use the runtime to check readiness
    use csv_sdk::CsvClient;
    use csv_sdk::StoreBackend;
    use csv_hash::ChainId;

    // Map CLI Chain to protocol ChainId
    let core_chain = ChainId::new(chain.as_str());

    // Convert CLI config to SDK config format
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.network = match config.chain(chain)?.network {
        crate::config::Network::Test => csv_sdk::config::Network::Testnet,
        crate::config::Network::Main => csv_sdk::config::Network::Mainnet,
        crate::config::Network::Dev => csv_sdk::config::Network::Devnet,
    };

    // Convert chain config to SDK format
    let chain_cfg = config.chain(chain)?;
    let sdk_chain_config = csv_sdk::config::ChainConfig {
        rpc: csv_sdk::config::RpcConfig {
            url: chain_cfg.rpc_url.clone(),
            api_key: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        finality_depth: chain_cfg.finality_depth as u32,
        enabled: true,
        xpub: config.wallets.get(chain).and_then(|w| w.xpub.clone()),
        seed: None,
        contract_address: chain_cfg.contract_address.clone(),
        program_id: chain_cfg.program_id.clone(),
        account,
        index,
        utxos: vec![],
        sanad_seals: vec![],
    };
    sdk_config.chains.insert(chain.as_str().to_string(), sdk_chain_config);

    // Build CSV client without private keys (readiness check doesn't need signing)
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .with_config(sdk_config)
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    let runtime = client.chain_runtime();

    // Check readiness via the chain backend
    match runtime.check_readiness(core_chain.clone(), account, index).await {
        Ok(readiness) => {
            output::kv("Derived Signer Address", readiness.signer_address.as_deref().unwrap_or("N/A"));
            output::kv("Balance Address", readiness.balance_address.as_deref().unwrap_or("N/A"));
            output::kv("Signer Configured", if readiness.signer_configured { "Yes" } else { "No" });
            output::kv("Write Capable", if readiness.write_capable { "Yes" } else { "No" });
            output::kv("Contract/Program Configured", if readiness.contract_configured { "Yes" } else { "No" });
            output::kv("Account Exists", if readiness.account_exists { "Yes" } else { "No" });
            
            if let Some(balance) = readiness.native_balance {
                output::kv("Native Balance", &balance.to_string());
            } else {
                output::kv("Native Balance", "N/A");
            }
            
            if let Some(fee) = readiness.estimated_fee {
                output::kv("Estimated Minimum Fee", &fee.to_string());
            } else {
                output::kv("Estimated Minimum Fee", "N/A");
            }
            
            output::kv("Sanad Create Supported", if readiness.sanad_create_supported { "Yes" } else { "No" });
            output::kv("Proof Generation Supported", if readiness.proof_generation_supported { "Yes" } else { "No" });
            output::kv("Cross-Chain Source Supported", if readiness.cross_chain_source_supported { "Yes" } else { "No" });
            output::kv("Cross-Chain Destination Supported", if readiness.cross_chain_destination_supported { "Yes" } else { "No" });

            // Overall readiness assessment
            let ready_for_writes = readiness.signer_configured && readiness.write_capable;
            if ready_for_writes {
                output::success("Chain is ready for write operations");
            } else {
                output::warn("Chain is NOT ready for write operations");
                if !readiness.signer_configured {
                    output::info("  - Signer not configured (use 'csv wallet init' or 'csv wallet import')");
                }
                if !readiness.write_capable {
                    output::info("  - Write capability not available");
                }
            }
        }
        Err(e) => {
            output::error(&format!("Failed to check readiness: {}", e));
            output::info("This may indicate the chain adapter is not properly configured or RPC is unavailable");
        }
    }

    println!();
    Ok(())
}
