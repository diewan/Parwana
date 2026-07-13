//! Wallet command types — encrypted mnemonic management only.

use crate::config::{Chain, Network};
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

/// How an imported wallet file is applied to local state.
///
/// The two behaviors have opposite consequences, so the operator names one
/// explicitly; the CLI never guesses, and never merges secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportMode {
    /// Install the file's key source as the sole signing authority, destroying
    /// any mnemonic already stored and re-deriving all accounts from it.
    Replace,
    /// Import only the file's known accounts and labels as a watch profile. The
    /// stored mnemonic is never read or replaced, and a key source in the file
    /// is not installed.
    Profile,
}

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
    /// Import a portable wallet file (the common encrypted format)
    Import {
        /// Path to the portable wallet file
        file: PathBuf,
        /// How to apply the file: replace the signing authority, or import
        /// accounts and labels as a watch profile
        #[arg(long, value_enum)]
        mode: ImportMode,
        /// Bitcoin account index used when re-deriving accounts (replace mode)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Confirm the destructive edge of the chosen mode without prompting:
        /// overwriting an existing wallet secret (replace) or an existing
        /// account address (profile)
        #[arg(long)]
        force: bool,
    },
    /// Import a BIP-39 mnemonic typed at a hidden prompt (never an argument)
    ImportMnemonic {
        /// Bitcoin account index
        #[arg(long, default_value = "0")]
        account: u32,
        /// Overwrite an existing wallet secret without prompting
        #[arg(long)]
        force: bool,
    },
    /// Export the wallet as a portable encrypted wallet file (common format)
    Export {
        /// Destination path for the encrypted wallet file
        #[arg(short, long)]
        out: PathBuf,
        /// Overwrite the destination if it already exists
        #[arg(long)]
        force: bool,
    },
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
        #[arg(long)]
        address: Option<String>,
        /// Account number (default: 0)
        #[arg(short, long, default_value = "0")]
        account: u32,
        /// Address index (default: 0)
        #[arg(short, long, default_value = "0")]
        index: u32,
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
