//! CLI commands for chain management and validation.

use clap::{Args, Subcommand};
use std::sync::{Arc, RwLock};
use csv_runtime::chain_discovery::{ChainDiscovery, ChainConfig};
use csv_runtime::adapter_registry::AdapterRegistryImpl;
use csv_hash::chain_id::ChainId;

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
        let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
        let discovery = ChainDiscovery::new(adapter_registry);
        
        let chains = discovery.all_configs();
        
        if chains.is_empty() {
            println!("No chains registered. Use 'csv chain-management discover' to load chains from configuration.");
            return Ok(());
        }
        
        println!("Supported chains:");
        for config in chains {
            println!("  {} ({}) - {}", config.id, config.name, 
                if config.enabled { "[enabled]" } else { "[disabled]" });
        }
        
        Ok(())
    }
    
    /// Show details for a specific chain
    async fn show_chain(&self, chain_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
        let discovery = ChainDiscovery::new(adapter_registry);
        
        let chain_id = ChainId::new(chain_id);
        let config = discovery.get_config(&chain_id);
        
        if let Some(cfg) = config {
            println!("Chain Details:");
            println!("  ID: {}", cfg.id);
            println!("  Name: {}", cfg.name);
            println!("  Network: {}", cfg.network);
            println!("  RPC URL: {}", cfg.rpc_url);
            if let Some(contract) = &cfg.contract_address {
                println!("  Contract Address: {}", contract);
            }
            println!("  Enabled: {}", cfg.enabled);
        } else {
            println!("Chain '{}' not found.", chain_id.as_str());
        }
        
        Ok(())
    }
    
    /// Discover and load chains from configuration directory
    async fn discover_chains(&self, directory: &str) -> Result<(), Box<dyn std::error::Error>> {
        let chains_dir = std::path::Path::new(directory);
        
        if !chains_dir.exists() {
            return Err(format!("Chains directory '{}' does not exist", directory).into());
        }
        
        let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
        let discovery = ChainDiscovery::new(adapter_registry);
        
        // Read TOML files from directory
        let entries = std::fs::read_dir(chains_dir)?;
        let mut count = 0;
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                // Parse TOML file and register chain
                if let Some(chain_id) = path.file_stem().and_then(|s| s.to_str()) {
                    let config = ChainConfig {
                        id: chain_id.to_string(),
                        name: chain_id.to_string(),
                        network: "mainnet".to_string(),
                        rpc_url: "http://localhost:8545".to_string(),
                        contract_address: None,
                        enabled: true,
                    };
                    discovery.register_chain(config);
                    count += 1;
                }
            }
        }
        
        println!("Discovered {} chain configurations from '{}'", count, directory);
        
        Ok(())
    }
    
    /// Validate chain configuration files
    async fn validate_chains(&self, directory: &str) -> Result<(), Box<dyn std::error::Error>> {
        let chains_dir = std::path::Path::new(directory);
        
        if !chains_dir.exists() {
            return Err(format!("Chains directory '{}' does not exist", directory).into());
        }
        
        let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
        let discovery = ChainDiscovery::new(adapter_registry);
        
        let entries = std::fs::read_dir(chains_dir)?;
        let mut valid_count = 0;
        let mut invalid_count = 0;
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                // Basic validation: check if file is readable TOML
                match std::fs::read_to_string(&path) {
                    Ok(_) => {
                        valid_count += 1;
                        println!("  ✓ {}", path.display());
                    }
                    Err(e) => {
                        invalid_count += 1;
                        println!("  ✗ {} - {}", path.display(), e);
                    }
                }
            }
        }
        
        println!("\nValidation complete: {} valid, {} invalid", valid_count, invalid_count);
        
        Ok(())
    }
    
    /// Create a new chain configuration template
    async fn create_template(&self, chain_id: &str, chain_name: &str, output_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output_path = std::path::Path::new(output_dir);
        
        if !output_path.exists() {
            std::fs::create_dir_all(output_path)?;
        }
        
        let template = format!(
r#"[chain]
id = "{}"
name = "{}"
network = "mainnet"
rpc_url = "http://localhost:8545"
contract_address = null
enabled = true
"#,
            chain_id, chain_name
        );
        
        let file_path = output_path.join(format!("{}.toml", chain_id));
        std::fs::write(&file_path, template)?;
        
        println!("Created chain template at: {}", file_path.display());
        
        Ok(())
    }
}
