//! Wallet export to the common portable wallet format (WALLETFMT-CLI-003).
//!
//! Export produces exactly one artifact: the versioned, encrypted, authenticated
//! envelope owned by `csv_wallet::format`. It does not print the mnemonic, and
//! it emits no CLI-specific serialization — a wallet exported here is importable
//! by every application that speaks the common format, and by nothing else.

use crate::config::Config;
use crate::output;
use crate::state::UnifiedStateManager;
use anyhow::Result;
use csv_wallet::format;
use std::path::Path;

use super::portable;

/// Export the wallet to a portable encrypted wallet file.
pub fn cmd_export(
    out: &Path,
    force: bool,
    _config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    output::header("Wallet Export");

    // Fail before prompting for a passphrase if there is nothing to export, and
    // settle the overwrite question before any work.
    let payload = portable::build_payload(state)?;
    if out.exists() && !force {
        let question = format!("{} already exists. Overwrite it?", out.display());
        if !portable::confirm(&question)? {
            output::info("Export cancelled. Nothing was written.");
            return Ok(());
        }
    }

    output::info("The wallet file is encrypted with a passphrase of its own.");
    output::info("It is not the passphrase that unlocks this CLI's local state.");
    let passphrase = portable::prompt_new_passphrase()?;

    let envelope = format::encrypt(&payload, &passphrase)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt wallet file: {}", e))?;

    // The overwrite decision was already made above — by the flag or by the
    // operator answering the prompt.
    portable::write_envelope_atomic(out, &envelope, true)?;

    output::success(&format!("Wallet exported to {}", out.display()));
    output::kv("Format", "common encrypted wallet envelope v1");
    output::kv("Accounts", &payload.accounts.len().to_string());
    output::warning(
        "This file carries your key material. Anyone holding the file and its passphrase \
         controls the wallet.",
    );
    output::info("Import it with: csv wallet import <file> --mode replace");

    Ok(())
}
