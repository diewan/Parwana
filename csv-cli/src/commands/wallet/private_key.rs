//! Private key display for a specific chain.
//!
//! Re-derives the private key from the stored mnemonic and displays it
//! as a hex string with 0x prefix. This never stores the raw key.

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;
use anyhow::Result;
use csv_hash::ChainId;
use csv_keys::Mnemonic;
use csv_keys::bip44::derive_all_chain_keys;

/// Show the hex-encoded private key for a specific chain.
pub fn cmd_private_key(
    chain: Chain,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("{} Private Key", chain));

    // Check if mnemonic is stored
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No mnemonic found. Initialize or import a wallet first.")
    })?;

    // Re-derive the mnemonic to get the seed
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(None);
    let mut seed_array = [0u8; 64];
    seed_array.copy_from_slice(seed.as_bytes());

    // Derive keys for all chains (account 0)
    let keys = derive_all_chain_keys(&seed_array, 0);

    // Find the key for the requested chain
    let core_chain = ChainId::new(chain.as_str());
    let secret_key = keys
        .get(&core_chain)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive key for chain: {}", chain))?;

    // Format as hex with 0x prefix
    let hex_key = format!("0x{}", hex::encode(secret_key.as_bytes()));

    // Display with security warning
    println!();
    output::secret(&hex_key);
    println!();
    output::warning("Store this key securely. Anyone with it controls this account.");
    output::info("You can also use 'csv wallet export' to see the full mnemonic phrase.");

    Ok(())
}
