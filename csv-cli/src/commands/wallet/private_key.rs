//! Private key display for a specific chain.
//!
//! Re-derives the private key from the stored mnemonic and displays it
//! as a hex string with 0x prefix. This never stores the raw key.

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;
use anyhow::Result;

/// Show the hex-encoded private key for a specific chain.
pub fn cmd_private_key(
    chain: Chain,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("{} Private Key", chain));

    if chain.as_str() == "bitcoin" {
        return Err(anyhow::anyhow!(
            "Bitcoin signing uses the encrypted HD wallet seed and BIP-86 path, not a single \
             chain-wide private key. Use 'csv wallet export' for recovery."
        ));
    }

    let identity = WalletIdentity::from_state(state)?;
    let handle = identity.signing_handle(&chain, 0, 0, state)?;
    let secret_key = handle
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("No raw signing key available for {}", chain))?;

    // Format as hex with 0x prefix
    let hex_key = format!("0x{}", hex::encode(secret_key));

    // Display with security warning
    println!();
    output::secret(&hex_key);
    println!();
    output::warning("Store this key securely. Anyone with it controls this account.");
    output::info("You can also use 'csv wallet export' to see the full mnemonic phrase.");

    Ok(())
}
