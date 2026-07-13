//! Wallet import (WALLETFMT-CLI-003).
//!
//! Two explicit entry points, and no automatic fallback between them:
//!
//! - `csv wallet import <file> --mode <replace|profile>` consumes the common
//!   encrypted wallet envelope. Any other input — a plaintext mnemonic file, a
//!   legacy CLI state file, an unknown format version, a tampered envelope — is
//!   rejected. There is no best-effort decode.
//! - `csv wallet import-mnemonic` takes a BIP-39 phrase typed at a hidden
//!   prompt. The phrase is never accepted as a command-line argument, where it
//!   would be written to shell history and exposed in the process list.

use crate::config::Config;
use crate::output;
use crate::state::UnifiedStateManager;
use anyhow::Result;
use csv_wallet::format;
use std::path::Path;

use super::portable;
use super::types::ImportMode;

/// Import a portable wallet file in the common encrypted format.
pub fn cmd_import(
    file: &Path,
    mode: ImportMode,
    account: u32,
    force: bool,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Importing Portable Wallet File");

    let envelope = portable::read_envelope(file)?;
    let passphrase = portable::prompt_passphrase("Wallet file passphrase")?;

    // The shared format is the only decoder. It authenticates the header,
    // rejects unknown versions, bounds KDF cost, and fails closed on tampering,
    // truncation, and a non-canonical payload.
    let payload = format::decrypt(&envelope, &passphrase)
        .map_err(|e| anyhow::anyhow!("Cannot import {}: {}", file.display(), e))?;

    // Confirm the destructive edge before mutating anything.
    let force = force || confirm_destructive(mode, state)?;

    let summary = portable::apply_payload(state, &payload, mode, account, force)?;
    state.save()?;

    portable::report(&summary);
    output::success("Wallet file imported");
    Ok(())
}

/// Import a mnemonic typed at a hidden prompt.
///
/// This is the explicit path for material that is not in the common format. It
/// is deliberately a separate command: normal wallet import never falls back to
/// interpreting an arbitrary phrase or a legacy state file.
pub fn cmd_import_mnemonic(
    account: u32,
    force: bool,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Importing Wallet from Mnemonic");

    let phrase = portable::prompt_mnemonic()?;
    let force = force || confirm_destructive(ImportMode::Replace, state)?;

    // Route through the same payload application as a file import, so both paths
    // share one definition of "install a signing authority".
    let mut payload = format::WalletPayload::new();
    payload.key_sources.push(format::KeySource {
        id: "primary".to_string(),
        kind: format::KeySourceKind::Mnemonic,
        secret: phrase.as_bytes().to_vec(),
    });
    drop(phrase);

    let summary = portable::apply_payload(state, &payload, ImportMode::Replace, account, force)?;
    state.save()?;

    portable::report(&summary);
    for account_record in &state.storage.wallet.accounts {
        output::kv(account_record.chain.as_str(), &account_record.address);
    }
    output::success("Wallet imported. The mnemonic is encrypted in unified state.");
    output::info("Export it in the portable format with: csv wallet export --out <file>");
    Ok(())
}

/// Ask the operator to confirm the destructive edge of `mode`, if this import
/// has one. Returns whether the destructive action is authorized.
///
/// A `false` here is not an authorization to proceed differently — it means
/// `apply_payload` will refuse anything destructive, which is the safe outcome.
fn confirm_destructive(mode: ImportMode, state: &UnifiedStateManager) -> Result<bool> {
    match mode {
        ImportMode::Replace if state.storage.wallet.mnemonic.is_some() => {
            output::warning(
                "This wallet already holds a mnemonic. Replace mode destroys it and every key \
                 derived from it. Anything you cannot recover from a backup will be lost.",
            );
            portable::confirm("Replace the existing wallet secret?")
        }
        _ => Ok(false),
    }
}
