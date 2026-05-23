//! Wallet mnemonic export.
//!
//! Exports the stored mnemonic phrase for backup or migration purposes.
//! This is the counterpart to `csv wallet import`.

use crate::config::Config;
use crate::output;
use crate::state::UnifiedStateManager;
use anyhow::Result;

/// Export mnemonic phrase from storage.
pub fn cmd_export(_config: &Config, state: &UnifiedStateManager) -> Result<()> {
    output::header("Mnemonic Export");

    // Check if mnemonic is stored
    let mnemonic = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No mnemonic found. Initialize or import a wallet first.")
    })?;

    output::warning("WARNING: This mnemonic phrase controls all your wallet keys!");
    output::warning("Store it securely and never share it with anyone.");
    println!();
    output::info("Your mnemonic phrase:");
    println!("  {}", mnemonic);
    println!();
    output::info("To use this on another device, run:");
    println!("  csv wallet import \"{}\" --network dev", mnemonic);
    println!();
    output::info("This will derive the same private keys and addresses on any device.");

    Ok(())
}
