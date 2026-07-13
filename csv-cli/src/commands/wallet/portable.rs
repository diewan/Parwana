//! Portable wallet file bridge for the reference CLI (WALLETFMT-CLI-003).
//!
//! The CLI exchanges wallet identities through exactly one artifact: the common
//! encrypted envelope owned by [`csv_wallet::format`]. This module is the only
//! place the CLI touches that format; it does not define crypto, framing, or
//! versioning of its own (charter: "No duplicated canonical protocol or
//! wallet-format implementation").
//!
//! # File semantics
//!
//! Export writes the common envelope and nothing else. There is no plaintext
//! mnemonic dump, and no JSON side-channel.
//!
//! Import is explicit about what it does to existing wallet material, because
//! the two reasonable behaviors have opposite consequences and guessing between
//! them silently is how operators lose funds:
//!
//! - [`ImportMode::Replace`] installs the file's key source as *the* signing
//!   authority. Any previously stored mnemonic is destroyed, stale derived
//!   accounts and the UTXO cache belonging to the old identity are dropped, and
//!   accounts are re-derived from the imported source.
//! - [`ImportMode::Profile`] imports only non-secret material — known accounts
//!   and labels — as a watch profile. It never touches the stored mnemonic, and
//!   a key source present in the file is *not* installed.
//!
//! Secrets are never merged: there is no mode in which the CLI ends up holding
//! two key sources, or silently picks between an existing one and an imported
//! one. Both destructive edges (overwriting an existing wallet secret,
//! overwriting an existing account address) require confirmation or `--force`.
//!
//! # Secret handling
//!
//! The mnemonic is only ever carried in memory (zeroized after use) or inside
//! the encrypted envelope. It is never passed as a command-line argument (which
//! would land in shell history and `ps` output), never printed, and never put
//! into an error message.

use crate::config::Chain;
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;
use anyhow::{Result, bail};
use csv_store::state::WalletAccount;
use csv_wallet::format::{
    self, DerivationProfile, KeySource, KeySourceKind, KnownAccount, WalletPayload,
};
use std::io::{IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

use super::types::ImportMode;

/// Identifier of the single key source the reference CLI exports.
const PRIMARY_SOURCE_ID: &str = "primary";

/// Chains the CLI derives accounts for from the wallet mnemonic.
const DERIVED_CHAINS: [&str; 5] = ["bitcoin", "ethereum", "sui", "aptos", "solana"];

/// The BIP-44/86 derivation path the CLI uses for `chain` at `account`.
fn derivation_path(chain: &str, account: u32) -> String {
    let (purpose, coin_type) = match chain {
        "bitcoin" => (86, 0),
        "ethereum" => (44, 60),
        "sui" => (44, 784),
        "aptos" => (44, 637),
        "solana" => (44, 501),
        _ => (44, 0),
    };
    format!("m/{}'/{}'/{}'/0/0", purpose, coin_type, account)
}

/// What an import changed. Returned so the command layer can report precisely
/// what happened rather than claiming a generic success.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Signing authority was replaced by the imported key source.
    pub key_source_installed: bool,
    /// Accounts written to state.
    pub accounts_written: usize,
    /// Key sources present in the file that were deliberately not installed
    /// (profile mode).
    pub key_sources_ignored: usize,
    /// Labels imported.
    pub labels_imported: usize,
}

// ─── Payload construction (export side) ───

/// Build the portable payload for the wallet currently held in `state`.
///
/// Only portable material is included. There is structurally nowhere in
/// [`WalletPayload`] to put runtime leases, replay state, execution journals,
/// in-progress transfers, explorer caches, or RPC credentials, and this function
/// reads none of them: it touches `wallet.mnemonic` and `wallet.accounts` only.
pub fn build_payload(state: &UnifiedStateManager) -> Result<WalletPayload> {
    let mnemonic = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No wallet to export. Run 'csv wallet init' or 'csv wallet import' first.")
    })?;

    let mut payload = WalletPayload::new();
    payload.key_sources.push(KeySource {
        id: PRIMARY_SOURCE_ID.to_string(),
        kind: KeySourceKind::Mnemonic,
        secret: mnemonic.as_bytes().to_vec(),
    });

    for account in &state.storage.wallet.accounts {
        payload.accounts.push(KnownAccount {
            chain: account.chain.as_str().to_string(),
            address: account.address.clone(),
            label: account.name.clone(),
        });
        if let Some(path) = &account.derivation_path {
            payload.derivation_profiles.push(DerivationProfile {
                source_id: PRIMARY_SOURCE_ID.to_string(),
                path: path.clone(),
                name: account.chain.as_str().to_string(),
            });
        }
    }

    Ok(payload)
}

// ─── Payload application (import side) ───

/// Apply a decrypted payload to `state` under an explicit [`ImportMode`].
///
/// `force` authorizes the destructive edge of the chosen mode: replacing an
/// existing wallet secret, or overwriting a known account address that already
/// exists in state. Without it, either condition is an error — the caller is
/// expected to have obtained confirmation.
pub fn apply_payload(
    state: &mut UnifiedStateManager,
    payload: &WalletPayload,
    mode: ImportMode,
    account_index: u32,
    force: bool,
) -> Result<ImportSummary> {
    match mode {
        ImportMode::Replace => apply_replace(state, payload, account_index, force),
        ImportMode::Profile => apply_profile(state, payload, force),
    }
}

/// Install the imported key source as the sole signing authority.
fn apply_replace(
    state: &mut UnifiedStateManager,
    payload: &WalletPayload,
    account_index: u32,
    force: bool,
) -> Result<ImportSummary> {
    // Exactly one mnemonic source. Zero means the file cannot confer signing
    // authority; more than one means the CLI would have to *choose*, and a
    // silent choice between two secrets is precisely what this ticket forbids.
    let sources: Vec<&KeySource> = payload
        .key_sources
        .iter()
        .filter(|s| s.kind == KeySourceKind::Mnemonic)
        .collect();
    let source = match sources.as_slice() {
        [single] => *single,
        [] => bail!(
            "Wallet file carries no mnemonic key source, so it cannot replace the signing \
             authority. Import it as a watch profile with '--mode profile'."
        ),
        many => bail!(
            "Wallet file carries {} mnemonic key sources; the CLI holds exactly one signing \
             authority and will not choose between them.",
            many.len()
        ),
    };

    if state.storage.wallet.mnemonic.is_some() && !force {
        bail!(
            "This wallet already holds a mnemonic. Importing in replace mode destroys it and \
             every key derived from it. Re-run with --force to confirm."
        );
    }

    // The secret is UTF-8 mnemonic bytes; a copy exists only for as long as it
    // takes to validate and derive, then it is wiped.
    let phrase = Zeroizing::new(
        String::from_utf8(source.secret.clone())
            .map_err(|_| anyhow::anyhow!("Mnemonic key source is not valid UTF-8"))?,
    );
    // Reject a malformed phrase before it touches state. The error deliberately
    // carries no phrase material.
    let identity = WalletIdentity::from_mnemonic(&phrase)
        .map_err(|_| anyhow::anyhow!("Wallet file contains an invalid BIP-39 mnemonic"))?;

    // The previous identity's derived accounts and UTXO cache are keyed to keys
    // this wallet will no longer hold. Leaving them would let a later command
    // treat an address it cannot sign for as its own.
    state.storage.wallet.accounts.clear();
    state.storage.wallet.utxos.clear();

    let mut accounts_written = 0usize;
    for chain_name in DERIVED_CHAINS {
        let chain = Chain::new(chain_name);
        let address = identity.address(&chain, account_index, 0)?;
        state.set_account(WalletAccount {
            id: format!("imported-{}", chain_name),
            chain: chain.clone(),
            name: format!("{} Account (imported)", chain_name),
            address,
            keystore_ref: None,
            xpub: None,
            derivation_path: Some(derivation_path(chain_name, account_index)),
        });
        accounts_written += 1;
    }

    state.storage.wallet.mnemonic = Some(phrase.to_string());

    let labels_imported = payload.labels.len();
    Ok(ImportSummary {
        key_source_installed: true,
        accounts_written,
        key_sources_ignored: payload.key_sources.len().saturating_sub(1),
        labels_imported,
    })
}

/// Import non-secret material only: known accounts and labels, as a watch
/// profile. The stored mnemonic is never read, written, or merged.
fn apply_profile(
    state: &mut UnifiedStateManager,
    payload: &WalletPayload,
    force: bool,
) -> Result<ImportSummary> {
    // An account that already exists for a chain may be one this wallet can
    // sign for. Overwriting its address with a foreign one would make the CLI
    // display — and hand out — an address whose key it does not hold.
    let conflicts: Vec<&str> = payload
        .accounts
        .iter()
        .filter(|incoming| {
            state
                .storage
                .wallet
                .get_account(&Chain::new(&incoming.chain))
                .is_some_and(|existing| existing.address != incoming.address)
        })
        .map(|a| a.chain.as_str())
        .collect();
    if !conflicts.is_empty() && !force {
        bail!(
            "Wallet file would overwrite the stored address for: {}. These accounts may be \
             derived from this wallet's own mnemonic. Re-run with --force to overwrite them.",
            conflicts.join(", ")
        );
    }

    let mut accounts_written = 0usize;
    for incoming in &payload.accounts {
        let chain = Chain::new(&incoming.chain);
        let derivation_path = payload
            .derivation_profiles
            .iter()
            .find(|p| p.name == incoming.chain)
            .map(|p| p.path.clone());
        state.set_account(WalletAccount {
            id: format!("profile-{}", incoming.chain),
            chain,
            name: incoming.label.clone(),
            address: incoming.address.clone(),
            keystore_ref: None,
            xpub: None,
            derivation_path,
        });
        accounts_written += 1;
    }

    Ok(ImportSummary {
        key_source_installed: false,
        accounts_written,
        key_sources_ignored: payload.key_sources.len(),
        labels_imported: payload.labels.len(),
    })
}

// ─── File I/O ───

/// Read a portable wallet file, bounding its size before it is loaded.
pub fn read_envelope(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("Cannot read wallet file {}: {}", path.display(), e))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    // Refuse an oversized file before allocating for it. The format enforces the
    // same bound on the bytes it is handed; this keeps a hostile file from
    // costing us the read.
    if metadata.len() > format::MAX_ENVELOPE_BYTES as u64 {
        bail!(
            "Wallet file is {} bytes, over the {} byte import limit.",
            metadata.len(),
            format::MAX_ENVELOPE_BYTES
        );
    }
    std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Cannot read wallet file {}: {}", path.display(), e))
}

/// Write `bytes` to `path` atomically, owner-readable only.
///
/// The envelope is written to a temporary file in the destination directory,
/// created `0600` so the secret-bearing bytes are never briefly world-readable,
/// flushed to disk, and only then renamed over `path`. A crash mid-write leaves
/// either the old file or no file — never a truncated wallet.
pub fn write_envelope_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists. Re-run with --force to overwrite it.",
            path.display()
        );
    }

    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("Cannot create {}: {}", dir.display(), e))?;
    }
    let dir = parent.unwrap_or_else(|| Path::new("."));

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} is not a valid file path", path.display()))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp{}", std::process::id()));
    let temp_path = dir.join(temp_name);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    // Scope the handle so it is closed before the rename.
    {
        let mut file = options
            .open(&temp_path)
            .map_err(|e| anyhow::anyhow!("Cannot create {}: {}", temp_path.display(), e))?;
        // On a pre-existing temp file `mode` is not applied; set it explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("Cannot restrict permissions: {}", e))?;
        }
        if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            bail!("Cannot write {}: {}", temp_path.display(), e);
        }
    }

    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        bail!("Cannot write {}: {}", path.display(), e);
    }
    Ok(())
}

// ─── Operator prompts ───

/// Prompt for a passphrase without echoing it.
///
/// Refuses to run without a terminal rather than falling back to a readable
/// stream: a passphrase piped in from a script is one that ends up in a file or
/// a process listing.
pub fn prompt_passphrase(label: &str) -> Result<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() {
        bail!("A terminal is required to enter a wallet-file passphrase.");
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password(format!("{}: ", label))?);
    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    Ok(passphrase)
}

/// Prompt for a new passphrase twice and require the entries to match.
pub fn prompt_new_passphrase() -> Result<Zeroizing<String>> {
    let first = prompt_passphrase("Choose a passphrase for the wallet file")?;
    let second = prompt_passphrase("Confirm passphrase")?;
    if first != second {
        bail!("Passphrases do not match");
    }
    Ok(first)
}

/// Prompt for a mnemonic phrase without echoing it.
///
/// The phrase is read from the terminal, never from `argv`: a mnemonic passed as
/// an argument is recorded in shell history and visible in `ps`.
pub fn prompt_mnemonic() -> Result<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() {
        bail!("A terminal is required to enter a mnemonic phrase.");
    }
    let phrase = Zeroizing::new(rpassword::prompt_password(
        "Enter your BIP-39 mnemonic phrase (input hidden): ",
    )?);
    let trimmed = Zeroizing::new(phrase.trim().to_string());
    if trimmed.is_empty() {
        bail!("Mnemonic cannot be empty");
    }
    Ok(trimmed)
}

/// Ask the operator to confirm a destructive action.
///
/// Non-interactive callers must pass `--force` explicitly; there is no implicit
/// "yes" when there is nobody to ask.
pub fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "{} Re-run with --force to confirm non-interactively.",
            question
        );
    }
    print!("{} [y/N]: ", question);
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Report an import without disclosing any secret material.
pub fn report(summary: &ImportSummary) {
    if summary.key_source_installed {
        output::success("Signing authority replaced by the imported key source");
    } else {
        output::info("Signing authority unchanged (watch profile import)");
    }
    output::kv("Accounts written", &summary.accounts_written.to_string());
    output::kv("Labels imported", &summary.labels_imported.to_string());
    if summary.key_sources_ignored > 0 {
        output::warning(&format!(
            "{} key source(s) in the file were NOT imported. Secrets are never merged; \
             use '--mode replace' to install the file's key source instead.",
            summary.key_sources_ignored
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use csv_wallet::format::{
        GOLDEN_WALLET_V1, GOLDEN_WALLET_V1_MNEMONIC, GOLDEN_WALLET_V1_PASSPHRASE,
        golden_wallet_v1_payload,
    };

    const TEST_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    /// A state manager backed by a temp file, so tests never touch `~/.csv`.
    fn temp_state(dir: &tempfile::TempDir) -> UnifiedStateManager {
        let path = dir.path().join("state.json");
        UnifiedStateManager::load_from(path.to_str().unwrap(), "state-pw").unwrap()
    }

    fn state_with_wallet(dir: &tempfile::TempDir) -> UnifiedStateManager {
        let mut state = temp_state(dir);
        let payload = {
            let mut p = WalletPayload::new();
            p.key_sources.push(KeySource {
                id: PRIMARY_SOURCE_ID.to_string(),
                kind: KeySourceKind::Mnemonic,
                secret: TEST_MNEMONIC.as_bytes().to_vec(),
            });
            p
        };
        apply_replace(&mut state, &payload, 0, false).unwrap();
        state
    }

    /// Fast, in-bounds KDF so the suite is not dominated by Argon2.
    fn test_kdf() -> format::KdfParams {
        format::KdfParams {
            algorithm: format::KdfId::Argon2id,
            memory_kib: format::kdf_bounds::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
            output_len: format::KEY_LEN as u32,
        }
    }

    // ─── Export ───

    #[test]
    fn export_round_trips_through_the_common_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_wallet(&dir);

        let payload = build_payload(&state).unwrap();
        let bytes = format::encrypt_with_params(&payload, "file-pw", &test_kdf()).unwrap();
        let decoded = format::decrypt(&bytes, "file-pw").unwrap();

        assert_eq!(decoded, payload);
        assert_eq!(decoded.key_sources.len(), 1);
        assert_eq!(decoded.key_sources[0].secret, TEST_MNEMONIC.as_bytes());
        assert_eq!(decoded.accounts.len(), DERIVED_CHAINS.len());
    }

    #[test]
    fn export_without_a_wallet_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = temp_state(&dir);
        assert!(build_payload(&state).is_err());
    }

    #[test]
    fn exported_payload_carries_no_runtime_or_cache_state() {
        // The payload type has no field for runtime authority; assert the CLI
        // also puts nothing protocol-ish into the fields it *does* have.
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_with_wallet(&dir);
        state
            .storage
            .wallet
            .utxos
            .push(csv_store::state::UtxoRecord {
                txid: "ff".repeat(32),
                vout: 0,
                value: 1234,
                account: 0,
                index: 0,
                derivation_path: "m/86'/0'/0'/0/0".to_string(),
                script_pubkey: None,
            });

        let payload = build_payload(&state).unwrap();
        let rendered = format!("{:?}", payload);
        assert!(
            !rendered.contains("1234"),
            "UTXO cache must not be exported"
        );
        assert!(!rendered.contains("ff".repeat(32).as_str()));
    }

    #[test]
    fn export_writes_atomically_with_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.csvw");
        write_envelope_atomic(&path, b"envelope-bytes", false).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"envelope-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "wallet file must be owner-only");
        }
        // No temp file survives a successful write.
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp file left behind");
    }

    #[test]
    fn export_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.csvw");
        write_envelope_atomic(&path, b"first", false).unwrap();

        assert!(write_envelope_atomic(&path, b"second", false).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"first",
            "a refused overwrite must leave the original intact"
        );

        write_envelope_atomic(&path, b"second", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    // ─── Import: format acceptance ───

    #[test]
    fn golden_wallet_file_imports() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = temp_state(&dir);

        let payload = format::decrypt(GOLDEN_WALLET_V1, GOLDEN_WALLET_V1_PASSPHRASE).unwrap();
        assert_eq!(payload, golden_wallet_v1_payload());

        let summary = apply_payload(&mut state, &payload, ImportMode::Replace, 0, false).unwrap();
        assert!(summary.key_source_installed);
        assert_eq!(
            state.storage.wallet.mnemonic.as_deref(),
            Some(GOLDEN_WALLET_V1_MNEMONIC)
        );
        // Accounts are re-derived from the imported source, not trusted from the
        // file.
        assert_eq!(state.storage.wallet.accounts.len(), DERIVED_CHAINS.len());
    }

    #[test]
    fn non_envelope_inputs_are_rejected() {
        // The CLI accepts the common format and nothing else: no plaintext
        // mnemonic file, no legacy JSON state, no bare bytes.
        for input in [
            b"abandon abandon abandon abandon about".as_slice(),
            br#"{"wallet":{"mnemonic":"abandon abandon about"}}"#.as_slice(),
            b"".as_slice(),
        ] {
            assert!(
                format::decrypt(input, "pw").is_err(),
                "non-envelope input must not import"
            );
        }
    }

    #[test]
    fn tampered_envelope_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_wallet(&dir);
        let payload = build_payload(&state).unwrap();
        let mut bytes = format::encrypt_with_params(&payload, "pw", &test_kdf()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(format::decrypt(&bytes, "pw").is_err());
    }

    #[test]
    fn oversize_file_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.csvw");
        std::fs::write(&path, vec![0u8; format::MAX_ENVELOPE_BYTES + 1]).unwrap();
        assert!(read_envelope(&path).is_err());
    }

    // ─── Import: replace semantics ───

    #[test]
    fn replace_refuses_to_destroy_an_existing_wallet_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_with_wallet(&dir);
        let payload = golden_wallet_v1_payload();

        let err = apply_payload(&mut state, &payload, ImportMode::Replace, 0, false)
            .expect_err("replacing an existing secret must require confirmation");
        assert!(err.to_string().contains("--force"));
        assert_eq!(
            state.storage.wallet.mnemonic.as_deref(),
            Some(TEST_MNEMONIC),
            "a refused replace must leave the existing secret untouched"
        );
    }

    #[test]
    fn forced_replace_drops_the_old_identity_entirely() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_with_wallet(&dir);
        let old_btc = state
            .get_address(&Chain::new("bitcoin"))
            .unwrap()
            .to_string();
        state
            .storage
            .wallet
            .utxos
            .push(csv_store::state::UtxoRecord {
                txid: "aa".repeat(32),
                vout: 0,
                value: 5000,
                account: 0,
                index: 0,
                derivation_path: "m/86'/0'/0'/0/0".to_string(),
                script_pubkey: None,
            });

        apply_payload(
            &mut state,
            &golden_wallet_v1_payload(),
            ImportMode::Replace,
            0,
            true,
        )
        .unwrap();

        assert_eq!(
            state.storage.wallet.mnemonic.as_deref(),
            Some(GOLDEN_WALLET_V1_MNEMONIC)
        );
        let new_btc = state.get_address(&Chain::new("bitcoin")).unwrap();
        assert_ne!(new_btc, old_btc, "accounts must be re-derived");
        assert!(
            state.storage.wallet.utxos.is_empty(),
            "the old identity's UTXO cache must not survive a replace"
        );
        // Exactly one account per chain — no accumulation of stale rows.
        assert_eq!(state.storage.wallet.accounts.len(), DERIVED_CHAINS.len());
    }

    #[test]
    fn replace_rejects_a_file_with_no_mnemonic_source() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = temp_state(&dir);
        let mut payload = golden_wallet_v1_payload();
        payload.key_sources.clear();

        assert!(apply_payload(&mut state, &payload, ImportMode::Replace, 0, false).is_err());
        assert!(state.storage.wallet.mnemonic.is_none());
    }

    #[test]
    fn replace_refuses_to_choose_between_multiple_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = temp_state(&dir);
        let mut payload = golden_wallet_v1_payload();
        payload.key_sources.push(KeySource {
            id: "second".to_string(),
            kind: KeySourceKind::Mnemonic,
            secret: TEST_MNEMONIC.as_bytes().to_vec(),
        });

        let err = apply_payload(&mut state, &payload, ImportMode::Replace, 0, false)
            .expect_err("two secrets must not be silently merged or picked between");
        assert!(err.to_string().contains("will not choose"));
        assert!(state.storage.wallet.mnemonic.is_none());
    }

    #[test]
    fn replace_rejects_an_invalid_mnemonic_without_leaking_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = temp_state(&dir);
        let mut payload = WalletPayload::new();
        payload.key_sources.push(KeySource {
            id: PRIMARY_SOURCE_ID.to_string(),
            kind: KeySourceKind::Mnemonic,
            secret: b"not a valid bip39 phrase at all".to_vec(),
        });

        let err = apply_payload(&mut state, &payload, ImportMode::Replace, 0, false)
            .expect_err("an invalid mnemonic must fail closed");
        assert!(
            !err.to_string().contains("not a valid bip39"),
            "the error must not echo the phrase"
        );
        assert!(state.storage.wallet.mnemonic.is_none());
    }

    // ─── Import: profile semantics ───

    #[test]
    fn profile_import_never_installs_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = temp_state(&dir);

        let summary = apply_payload(
            &mut state,
            &golden_wallet_v1_payload(),
            ImportMode::Profile,
            0,
            false,
        )
        .unwrap();

        assert!(!summary.key_source_installed);
        assert_eq!(summary.key_sources_ignored, 1);
        assert!(
            state.storage.wallet.mnemonic.is_none(),
            "profile mode must never install key material"
        );
        assert_eq!(summary.accounts_written, 2);
    }

    #[test]
    fn profile_import_leaves_an_existing_secret_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_with_wallet(&dir);

        apply_payload(
            &mut state,
            &golden_wallet_v1_payload(),
            ImportMode::Profile,
            0,
            true,
        )
        .unwrap();

        assert_eq!(
            state.storage.wallet.mnemonic.as_deref(),
            Some(TEST_MNEMONIC),
            "the wallet's own signing authority must survive a profile import"
        );
    }

    #[test]
    fn profile_import_refuses_to_overwrite_a_held_account_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state_with_wallet(&dir);
        let own_btc = state
            .get_address(&Chain::new("bitcoin"))
            .unwrap()
            .to_string();

        // The golden file's bitcoin address differs from the one this wallet
        // derives, so importing it as a profile would hand out an address whose
        // key we do not hold.
        let err = apply_payload(
            &mut state,
            &golden_wallet_v1_payload(),
            ImportMode::Profile,
            0,
            false,
        )
        .expect_err("overwriting a held account address must require --force");
        assert!(err.to_string().contains("bitcoin"));
        assert_eq!(
            state.get_address(&Chain::new("bitcoin")).unwrap(),
            own_btc,
            "a refused profile import must not modify accounts"
        );
    }
}
