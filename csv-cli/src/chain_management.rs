//! CLI commands for chain management and validation.

use clap::{Args, Subcommand};
use std::path::Path;
use csv_core::chain_discovery::ChainDiscovery;

/// Chain management commands
#[derive(Debug, Subcommand)]
pub enum ChainCommands {
    /// List all supported chains
    List,
    /// Show details for a specific chain
    Show {
        /// Chain ID to show details for
        chain_id: String,
    },
    /// Discover and load chains from configuration directory
    Discover {
        /// Directory containing chain configuration files
        #[arg(short, long, default_value = "chains")]
        directory: String,
    },
    /// Validate chain configuration files
    Validate {
        /// Directory containing chain configuration files
        #[arg(short, long, default_value = "chains")]
        directory: String,
    },
    /// Create a new chain configuration template
    CreateTemplate {
        /// Chain ID for the new template
        chain_id: String,
        /// Chain name for the new template
        chain_name: String,
        /// Output directory for the template
        #[arg(short, long, default_value = "chains")]
        output_dir: String,
    },
}

impl ChainCommands {
    /// Execute the chain management command
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            ChainCommands::List => {
                self.list_chains().await
            }
            ChainCommands::Show { chain_id } => {
                self.show_chain(chain_id).await
            }
            ChainCommands::Discover { directory } => {
                self.discover_chains(directory).await
            }
            ChainCommands::Validate { directory } => {
                self.validate_chains(directory).await
            }
            ChainCommands::CreateTemplate { chain_id, chain_name, output_dir } => {
                self.create_template(chain_id, chain_name, output_dir).await
            }
        }
    }
    
    /// List all supported chains
    async fn list_chains(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut discovery = ChainDiscovery::new();
        discovery.load_default_chains()?;
        
        let chains = discovery.supported_chain_ids();
        
        if chains.is_empty() {
            println!("No chains discovered. Run 'csv-cli chain discover' to load chains from configuration.");
            return Ok(());
        }
        
        println!("Supported chains:");
        for chain_id in chains {
            let config = discovery.get_chain_config(&chain_id);
            if let Some(cfg) = config {
                let nft_support = if cfg.custom_settings.get("supports_nfts")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) { "NFT" } else { "" };
                let sc_support = if cfg.custom_settings.get("supports_smart_contracts")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) { "SC" } else { "" };
                
                println!("  {} ({}) - {}", chain_id, cfg.chain_name, 
                    if !nft_support.is_empty() || !sc_support.is_empty() {
                        format!("[{}{}]", nft_support, sc_support)
                    } else {
                        "".to_string()
                    });
            }
        }
        
        Ok(())
    }
    
    /// Show details for a specific chain
    async fn show_chain(&self, chain_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut discovery = ChainDiscovery::new();
        discovery.load_default_chains()?;
        
        let config = discovery.get_chain_config(chain_id);
        
        if let Some(cfg) = config {
            println!("Chain Details:");
            println!("  ID: {}", cfg.chain_id);
            println!("  Name: {}", cfg.chain_name);
            println!("  Default Network: {}", cfg.default_network);
            println!("  RPC Endpoints:");
            for endpoint in &cfg.rpc_endpoints {
                println!("    {}", endpoint);
            }
            println!("  Block Explorers:");
            for explorer in &cfg.block_explorer_urls {
                println!("    {}", explorer);
            }
            if let Some(program_id) = &cfg.program_id {
                println!("  Program ID: {}", program_id);
            }
            
            println!("  Capabilities:");
            if let Some(supports_nfts) = cfg.custom_settings.get("supports_nfts").and_then(|v| v.as_bool()) {
                println!("    NFTs: {}", if supports_nfts { "Yes" } else { "No" });
            }
            if let Some(supports_sc) = cfg.custom_settings.get("supports_smart_contracts").and_then(|v| v.as_bool()) {
                println!("    Smart Contracts: {}", if supports_sc { "Yes" } else { "No" });
            }
            if let Some(account_model) = cfg.custom_settings.get("account_model").and_then(|v| v.as_str()) {
                println!("    Account Model: {}", account_model);
            }
        } else {
            println!("Chain '{}' not found. Available chains:", chain_id);
            self.list_chains().await?;
        }
        
        Ok(())
    }
    
    /// Discover and load chains from configuration directory
    async fn discover_chains(&self, directory: &str) -> Result<(), Box<dyn std::error::Error>> {
        let chains_dir = Path::new(directory);
        
        if !chains_dir.exists() {
            return Err(format!("Chains directory '{}' does not exist", directory).into());
        }
        
        let mut discovery = ChainDiscovery::new();
        discovery.discover_chains(chains_dir)?;
        
        let chains = discovery.supported_chain_ids();
        println!("Discovered {} chains:", chains.len());
        for chain_id in chains {
            let config = discovery.get_chain_config(&chain_id);
            if let Some(cfg) = config {
                println!("  {} ({})", chain_id, cfg.chain_name);
            }
        }
        
        Ok(())
    }
    
    /// Validate chain configuration files
    async fn validate_chains(&self, directory: &str) -> Result<(), Box<dyn std::error::Error>> {
        let chains_dir = Path::new(directory);
        
        if !chains_dir.exists() {
            return Err(format!("Chains directory '{}' does not exist", directory).into());
        }
        
        let mut discovery = ChainDiscovery::new();
        let mut errors = Vec::new();
        
        // Try to load configurations
        match discovery.discover_chains(chains_dir) {
            Ok(_) => {
                let chains = discovery.supported_chain_ids();
                println!("Validated {} chain configurations:", chains.len());
                
                for chain_id in chains {
                    let config = discovery.get_chain_config(&chain_id);
                    if let Some(cfg) = config {
                        let mut chain_errors = Vec::new();
                        
                        // Validate required fields
                        if cfg.chain_id.is_empty() {
                            chain_errors.push("Missing chain_id");
                        }
                        if cfg.chain_name.is_empty() {
                            chain_errors.push("Missing chain_name");
                        }
                        if cfg.rpc_endpoints.is_empty() {
                            chain_errors.push("No RPC endpoints specified");
                        }
                        if cfg.block_explorer_urls.is_empty() {
                            chain_errors.push("No block explorer URLs specified");
                        }
                        
                        // Validate capabilities
                        if let Some(supports_nfts) = cfg.custom_settings.get("supports_nfts").and_then(|v| v.as_bool()) {
                            if supports_nfts {
                                println!("  {} ({}) - NFT support: OK", chain_id, cfg.chain_name);
                            }
                        }
                        
                        if chain_errors.is_empty() {
                            println!("  {} ({}) - OK", chain_id, cfg.chain_name);
                        } else {
                            println!("  {} ({}) - ERRORS:", chain_id, cfg.chain_name);
                            for error in chain_errors {
                                println!("    {}", error);
                                errors.push(format!("{}: {}", chain_id, error));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                errors.push(format!("Discovery failed: {}", e));
            }
        }
        
        if errors.is_empty() {
            println!("All chain configurations are valid!");
        } else {
            println!("Found {} validation errors:", errors.len());
            for error in errors {
                println!("  {}", error);
            }
        }
        
        Ok(())
    }
    
    /// Create a new chain configuration template
    async fn create_template(&self, chain_id: &str, chain_name: &str, output_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output_path = Path::new(output_dir);
        
        if !output_path.exists() {
            std::fs::create_dir_all(output_path)?;
        }
        
        let template = format!(r#"
# {} Chain Configuration

chain_id = "{}"
chain_name = "{}"
default_network = "mainnet"
rpc_endpoints = [
    "https://rpc.example.com"
]
program_id = null
block_explorer_urls = [
    "https://explorer.example.com"
]

[custom_settings]
supports_nfts = true
supports_smart_contracts = true
account_model = "Account"
confirmation_blocks = 6
max_batch_size = 100
supported_networks = ["mainnet", "testnet"]

# Chain-specific settings
[custom_settings.{}]
# Add chain-specific configuration here
"#, chain_name, chain_id, chain_name, chain_id.to_lowercase().replace("-", "_"));
        
        let config_file = output_path.join(format!("{}.toml", chain_id));
        std::fs::write(&config_file, template)?;
        
        println!("Created chain configuration template: {}", config_file.display());
        println!("Edit the file to add your chain-specific settings.");
        
        Ok(())
    }
}
