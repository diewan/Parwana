//! Wallet management commands — encrypted mnemonic management only.

pub mod balance;
pub mod export;
pub mod generate;
pub mod import;
pub mod private_key;
pub mod types;

pub use types::WalletAction;

use crate::config::Config;
use crate::state::UnifiedStateManager;
use anyhow::Result;

/// Execute wallet command.
pub async fn execute(
    action: WalletAction,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        WalletAction::Init {
            network,
            words,
            account,
        } => generate::cmd_init(network, words, account, config, state),
        WalletAction::Import {
            phrase,
            network,
            account,
        } => import::cmd_import(&phrase, network, account, config, state),
        WalletAction::Export => export::cmd_export(config, state),
        WalletAction::Generate { chain, network } => {
            generate::cmd_generate(chain, network, config, state)
        }
        WalletAction::Balance { chain, address } => {
            balance::cmd_balance(chain, address, config, state).await
        }
        WalletAction::List => balance::cmd_list(config, state),
        WalletAction::PrivateKey { chain } => private_key::cmd_private_key(chain, config, state),
    }
}
