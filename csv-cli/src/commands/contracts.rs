//! Contract management commands

use anyhow::Result;
use clap::Subcommand;

use crate::config::Chain;
use crate::output;
use crate::state::UnifiedStateManager;

#[derive(Subcommand)]
pub enum ContractAction {
    /// List all deployed contracts
    List,
    /// Show contract status for a chain
    Status {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
    },
    /// Show contract info for a chain
    Info {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
    },
    /// Set contract address for a chain
    Set {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Contract address
        address: String,
    },
}

pub fn execute(
    action: ContractAction,
    config: &crate::config::Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        ContractAction::List => cmd_list(config, state),
        ContractAction::Status { chain } => cmd_status(&chain, config, state),
        ContractAction::Info { chain } => cmd_info(&chain, config, state),
        ContractAction::Set { chain, address } => cmd_set(&chain, address, config, state),
    }
}

fn cmd_list(config: &crate::config::Config, state: &UnifiedStateManager) -> Result<()> {
    output::header("Deployed Contracts");

    let headers = vec!["Chain", "Network", "Contract Address", "Tx Hash"];
    let mut rows = Vec::new();

    for chain in config.chains.keys() {
        if let Some(contract) = state.get_contract(chain) {
            let network = config
                .chains
                .get(chain)
                .map(|c| c.network.to_string())
                .unwrap_or_default();
            rows.push(vec![
                format!("{}", chain),
                network,
                contract.address.clone(),
                contract.tx_hash.clone(),
            ]);
        }
    }

    if rows.is_empty() {
        output::warning(
            "No contracts deployed. Deploy contracts manually using Foundry/forge and set the address with `csv contracts set`.",
        );
    } else {
        output::table(&headers, &rows);
    }

    Ok(())
}

fn cmd_status(
    chain: &Chain,
    config: &crate::config::Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    if let Some(contract) = state.get_contract(chain) {
        let chain_config = config.chain(chain)?;

        output::header(&format!("Contract Status: {}", chain));
        output::kv("Chain", &format!("{}", chain));
        output::kv("Network", &chain_config.network.to_string());
        output::kv("Contract Address", &contract.address);
        output::kv("Tx Hash", &contract.tx_hash);
        output::kv("Deployed At", &contract.deployed_at.to_string());
    } else {
        output::warning(&format!(
            "No contract deployed for {}. Deploy manually and set with `csv contracts set {} <address>`",
            chain, chain
        ));
    }

    Ok(())
}

fn cmd_info(
    chain: &Chain,
    config: &crate::config::Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    cmd_status(chain, config, state)
}

fn cmd_set(
    chain: &Chain,
    address: String,
    config: &crate::config::Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    if !config.chains.contains_key(chain) {
        anyhow::bail!(
            "Chain '{}' not found in config. Add it with `csv chain set-rpc` first.",
            chain
        );
    }

    let chain_config = config.chain(chain)?;

    // Update config file
    let mut config_clone = config.clone();
    if let Some(c) = config_clone.chains.get_mut(chain) {
        c.contract_address = Some(address.clone());
    }

    let path = expand_path("~/.csv/config.toml");
    let content = toml::to_string_pretty(&config_clone)?;
    std::fs::write(&path, content)?;

    // Store contract record
    let contract = csv_store::ContractRecord {
        chain: chain.clone(),
        address: address.clone(),
        tx_hash: "manual".to_string(),
        deployed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state.store_contract(contract);

    output::success(&format!(
        "Contract set for {}: {} (network: {})",
        chain, address, chain_config.network
    ));

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
