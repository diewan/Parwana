//! Cross-chain transfer commands (Phase 5 Compliant)
//!
//! This module uses only the csv-sdk runtime API.
//! All chain operations are delegated through `CsvClient::transfers()`.

use anyhow::Result;
use clap::Subcommand;

use csv_protocol::ChainId;

use crate::config::{Chain, Config};
use crate::state::UnifiedStateManager;

pub mod status;
pub mod transfer;

#[derive(Subcommand)]
pub enum CrossChainAction {
    /// Execute a cross-chain Sanad transfer (via runtime)
    Transfer {
        /// Source chain
        #[arg(long)]
        from: Chain,
        /// Destination chain
        #[arg(long)]
        to: Chain,
        /// Sanad ID to transfer (hex)
        #[arg(long)]
        sanad_id: String,
        /// Destination owner address (hex)
        #[arg(long)]
        dest_owner: Option<String>,
    },
    /// Check transfer status
    Status {
        /// Transfer ID (hex)
        transfer_id: String,
    },
    /// List all transfers
    List {
        /// Filter by source chain
        #[arg(long, value_enum)]
        from: Option<Chain>,
        /// Filter by destination chain
        #[arg(long, value_enum)]
        to: Option<Chain>,
    },
    /// Retry a failed transfer
    Retry {
        /// Transfer ID (hex)
        transfer_id: String,
    },
}

pub async fn execute(
    action: CrossChainAction,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        CrossChainAction::Transfer {
            from,
            to,
            sanad_id,
            dest_owner,
        } => {
            transfer::cmd_transfer(from, to, sanad_id, dest_owner, config, state).await
        }
        CrossChainAction::Status { transfer_id } => status::cmd_status(transfer_id, state),
        CrossChainAction::List { from, to } => status::cmd_list(from, to, state),
        CrossChainAction::Retry { transfer_id } => status::cmd_retry(transfer_id, config, state),
    }
}

/// Convert CLI Chain enum to protocol ChainId
pub fn to_protocol_chain(chain: Chain) -> ChainId {
    ChainId::new(chain.as_str())
}
