//! Cross-chain transfer commands (Phase 5 Compliant)
//!
//! This module uses only the csv-sdk runtime API.
//! All chain operations are delegated through `CsvClient::transfers()`.

use anyhow::Result;
use clap::Subcommand;

use csv_hash::ChainId;

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
        /// Override finality depth for source chain (for testing)
        #[arg(long)]
        finality_depth: Option<u64>,
        /// Poll-and-block: after locking, wait for the source-chain lock to
        /// reach finality and complete the transfer in this invocation. Without
        /// this flag the transfer locks, journals, and returns immediately with
        /// an "awaiting finality" status to be finished later via `resume`.
        #[arg(long)]
        wait: bool,
        /// Poll interval in seconds while `--wait` is set.
        #[arg(long, default_value_t = 60)]
        poll_interval_secs: u64,
        /// Give up waiting after this many seconds while `--wait` is set.
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Resume a locked transfer that is awaiting finality (no re-lock)
    Resume {
        /// Transfer ID returned when the transfer was started
        transfer_id: String,
        /// Poll-and-block from here until the transfer completes.
        #[arg(long)]
        wait: bool,
        /// Poll interval in seconds while `--wait` is set.
        #[arg(long, default_value_t = 60)]
        poll_interval_secs: u64,
        /// Give up waiting after this many seconds while `--wait` is set.
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
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
            finality_depth,
            wait,
            poll_interval_secs,
            timeout_secs,
        } => {
            let opts = transfer::WaitOpts::new(wait, poll_interval_secs, timeout_secs);
            transfer::cmd_transfer(
                from,
                to,
                sanad_id,
                dest_owner,
                finality_depth,
                opts,
                config,
                state,
            )
            .await
        }
        CrossChainAction::Resume {
            transfer_id,
            wait,
            poll_interval_secs,
            timeout_secs,
        } => {
            let opts = transfer::WaitOpts::new(wait, poll_interval_secs, timeout_secs);
            transfer::cmd_resume(transfer_id, opts, config, state).await
        }
        CrossChainAction::Status { transfer_id } => {
            status::cmd_status(transfer_id, config, state).await
        }
        CrossChainAction::List { from, to } => status::cmd_list(from, to, state),
        CrossChainAction::Retry { transfer_id } => status::cmd_retry(transfer_id, config, state),
    }
}

/// Convert CLI Chain enum to protocol ChainId
pub fn to_protocol_chain(chain: Chain) -> ChainId {
    ChainId::new(chain.as_str())
}
