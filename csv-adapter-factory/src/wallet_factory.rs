//! Wallet factory for chain-specific wallet operations
//!
//! This module provides a factory that registers chain-specific wallet operations
//! from chain adapters and provides a unified interface for wallet operations.

use csv_hash::chain_id::ChainId;
use csv_wallet::wallet_traits::{WalletFactory, WalletOperations};
use std::sync::{Arc, OnceLock};

/// Global wallet factory instance
static WALLET_FACTORY: OnceLock<Arc<WalletFactory>> = OnceLock::new();

/// Initialize the wallet factory with chain-specific operations
///
/// This should be called during application initialization to register
/// wallet operations for each supported chain.
pub fn init_wallet_factory() -> Arc<WalletFactory> {
    Arc::clone(WALLET_FACTORY.get_or_init(|| {
        let mut factory = WalletFactory::new();

        // Register Bitcoin operations if available
        #[cfg(feature = "bitcoin")]
        {
            use csv_bitcoin::wallet_operations::{BitcoinWalletOperations, Network};
            let bitcoin_ops = Box::new(BitcoinWalletOperations::new(Network::Test));
            factory.register(bitcoin_ops);
        }

        // Register Ethereum operations if available
        #[cfg(feature = "ethereum")]
        {
            use csv_ethereum::wallet_operations::{
                EthereumWalletOperations, Network as EthNetwork,
            };
            let ethereum_ops = Box::new(EthereumWalletOperations::new(EthNetwork::Test));
            factory.register(ethereum_ops);
        }

        // Register Sui operations if available
        #[cfg(feature = "sui")]
        {
            use csv_sui::wallet_operations::{Network as SuiNetwork, SuiWalletOperations};
            let sui_ops = Box::new(SuiWalletOperations::new(SuiNetwork::Test));
            factory.register(sui_ops);
        }

        // Register Aptos operations if available
        #[cfg(feature = "aptos")]
        {
            use csv_aptos::wallet_operations::{AptosWalletOperations, Network as AptosNetwork};
            let aptos_ops = Box::new(AptosWalletOperations::new(AptosNetwork::Test));
            factory.register(aptos_ops);
        }

        // Register Solana operations if available
        #[cfg(feature = "solana")]
        {
            use csv_solana::wallet_operations::{Network as SolNetwork, SolanaWalletOperations};
            let solana_ops = Box::new(SolanaWalletOperations::new(SolNetwork::Test));
            factory.register(solana_ops);
        }

        Arc::new(factory)
    }))
}

/// Get the global wallet factory instance
///
/// Returns None if the factory has not been initialized.
pub fn get_wallet_factory() -> Option<Arc<WalletFactory>> {
    WALLET_FACTORY.get().map(Arc::clone)
}

/// Get wallet operations for a specific chain
///
/// Returns None if the factory has not been initialized or the chain is not registered.
pub fn get_wallet_operations(chain_id: &ChainId) -> Option<Arc<dyn WalletOperations>> {
    get_wallet_factory().and_then(|factory| factory.get(chain_id))
}

/// Check if a chain is registered in the wallet factory
pub fn is_chain_registered(chain_id: &ChainId) -> bool {
    get_wallet_factory()
        .map(|factory| factory.is_registered(chain_id))
        .unwrap_or(false)
}

/// Get all registered chain IDs
pub fn registered_chains() -> Vec<ChainId> {
    get_wallet_factory()
        .map(|factory| factory.registered_chains().cloned().collect())
        .unwrap_or_default()
}
