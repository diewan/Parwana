//! Wallet command types — encrypted mnemonic management only.

use crate::config::{Chain, Network};
use clap::Subcommand;

/// Wallet management actions (encrypted mnemonics only).
#[derive(Subcommand)]
pub enum WalletAction {
    /// Initialize wallet with encrypted mnemonic (generate, store encrypted)
    Init {
        /// Network (dev/test/main)
        #[arg(value_enum, default_value = "dev")]
        network: Network,
        /// Generate mnemonic (12 or 24 words)
        #[arg(short, long, default_value = "12")]
        words: u8,
        /// Bitcoin account index (BIP-86 derivation path account)
        #[arg(long, default_value = "0")]
        account: u32,
    },
    /// Import wallet from mnemonic phrase (from csv-wallet or other source)
    Import {
        /// Mnemonic phrase (12 or 24 words)
        phrase: String,
        /// Network (dev/test/main)
        #[arg(value_enum, default_value = "dev")]
        network: Network,
        /// Bitcoin account index
        #[arg(long, default_value = "0")]
        account: u32,
    },
    /// Export mnemonic phrase for backup or migration
    Export,
    /// Generate wallet for specific chain
    Generate {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Network (dev/test/main)
        #[arg(value_enum, default_value = "test")]
        network: Network,
    },
    /// Show wallet balance
    Balance {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Address (uses stored address if not provided)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// List all wallet addresses
    List {
        /// Chain name (optional, lists all chains if not specified)
        #[arg(value_enum)]
        chain: Option<Chain>,
        /// Account number (default: 0)
        #[arg(short, long, default_value = "0")]
        account: u32,
        /// Address index (default: 0)
        #[arg(short, long, default_value = "0")]
        index: u32,
    },
    /// Show hex-encoded private key for a chain (derived from mnemonic)
    PrivateKey {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
    },
    /// Get a funding address for the specified chain
    Address {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Account number (default: 0)
        #[arg(short, long, default_value = "0")]
        account: u32,
        /// Address index (default: 0)
        #[arg(short, long, default_value = "0")]
        index: u32,
    },
    /// Scan wallet for UTXOs on the specified chain
    Scan {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Account number to scan (default: 0)
        #[arg(short, long, default_value = "0")]
        account: u32,
        /// Gap limit for address scanning (default: 20)
        #[arg(short, long, default_value = "20")]
        gap_limit: usize,
    },
}
