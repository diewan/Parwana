//! Cross-chain transfer commands (Phase 5 Compliant)
//!
//! This module uses only the csv-adapter runtime API.
//! All chain operations are delegated through `CsvClient::transfers()`.

use anyhow::Result;
use clap::Subcommand;

use crate::config::{Chain, Config};
use crate::state::UnifiedStateManager;

pub mod lease;
pub mod status;
pub mod transfer;

#[derive(Subcommand)]
pub enum CrossChainAction {
    /// Acquire a lease for a sanad (required before transfer)
    AcquireLease {
        /// Sanad ID to lease (hex)
        #[arg(long)]
        sanad_id: String,
        /// Time-to-live in seconds (default: 300)
        #[arg(long, default_value = "300")]
        ttl: u64,
        /// Source chain
        #[arg(long)]
        from: Chain,
    },
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
        /// Lease token (hex) - acquired via acquire-lease command
        #[arg(long)]
        lease_token: Option<String>,
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
        CrossChainAction::AcquireLease {
            sanad_id,
            ttl,
            from,
        } => lease::cmd_acquire_lease(sanad_id, ttl, from, config, state),
        CrossChainAction::Transfer {
            from,
            to,
            sanad_id,
            dest_owner,
            lease_token,
        } => {
            transfer::cmd_transfer(from, to, sanad_id, dest_owner, lease_token, config, state).await
        }
        CrossChainAction::Status { transfer_id } => status::cmd_status(transfer_id, state),
        CrossChainAction::List { from, to } => status::cmd_list(from, to, state),
        CrossChainAction::Retry { transfer_id } => status::cmd_retry(transfer_id, config, state),
    }
}

/// Convert CLI Chain enum to core Chain enum
pub fn to_core_chain(chain: Chain) -> csv_core::ChainId {
    csv_core::ChainId::new(chain.as_str())
}
