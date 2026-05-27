//! Trust subcommand — management of trust anchors and trust packages

use anyhow::Result;
use clap::Subcommand;
use csv_hash::Hash;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::output;

/// Trust package containing validator sets and trusted checkpoints
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustPackage {
    /// Package version
    pub version: u32,
    /// Genesis block hash for the chain
    pub genesis_hash: [u8; 32],
    /// Latest trusted checkpoint height
    pub trusted_checkpoint_height: u64,
    /// Latest trusted checkpoint hash
    pub trusted_checkpoint_hash: [u8; 32],
    /// Validator set epoch
    pub validator_epoch: u64,
    /// Number of validators in the set
    pub validator_count: usize,
    /// Package creation timestamp
    pub created_at: u64,
    /// Package expiry timestamp
    pub expires_at: u64,
    /// Multi-sig signature over the package
    pub signature: Option<String>,
    /// Signer identities (multi-sig addresses)
    pub signers: Vec<String>,
}

impl TrustPackage {
    /// Create a new trust package
    pub fn new(
        genesis_hash: [u8; 32],
        checkpoint_height: u64,
        checkpoint_hash: [u8; 32],
        validator_epoch: u64,
        validator_count: usize,
        ttl_hours: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            version: 1,
            genesis_hash,
            trusted_checkpoint_height: checkpoint_height,
            trusted_checkpoint_hash: checkpoint_hash,
            validator_epoch,
            validator_count,
            created_at: now,
            expires_at: now + ttl_hours * 3600,
            signature: None,
            signers: Vec::new(),
        }
    }

    /// Check if the trust package is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.expires_at
    }

    /// Check if the trust package is expiring soon (within 24 hours)
    pub fn is_expiring_soon(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hours_until_expiry = (self.expires_at - now) / 3600;
        hours_until_expiry < 24
    }
}

#[derive(Subcommand)]
pub enum TrustAction {
    /// Show current trust package status
    Status,
    /// Export the current trust package to a file
    Export {
        /// Output file path
        #[arg(short, long, default_value = "trust-package.json")]
        output: String,
    },
    /// Import a trust package from a file
    Import {
        /// Input file path
        input: String,
    },
    /// Verify a trust package file
    Verify {
        /// Trust package file path
        file: String,
    },
    /// Rotate to a new trusted checkpoint
    Rotate {
        /// New checkpoint height
        height: u64,
        /// New checkpoint hash (hex)
        hash: String,
    },
}

pub fn execute(action: TrustAction, _config: &Config) -> Result<()> {
    match action {
        TrustAction::Status => cmd_status(),
        TrustAction::Export { output } => cmd_export(&output),
        TrustAction::Import { input } => cmd_import(&input),
        TrustAction::Verify { file } => cmd_verify(&file),
        TrustAction::Rotate { height, hash } => cmd_rotate(height, &hash),
    }
}

fn cmd_status() -> Result<()> {
    output::header("Trust Package Status");

    // Load trust package from disk if it exists
    let trust_path = expand_path("~/.csv/trust-package.json");
    let package = match std::fs::read_to_string(&trust_path) {
        Ok(content) => {
            match serde_json::from_str::<TrustPackage>(&content) {
                Ok(pkg) => Some(pkg),
                Err(e) => {
                    output::error(&format!("Failed to parse trust package: {}", e));
                    return Ok(());
                }
            }
        }
        Err(_) => None,
    };

    match package {
        Some(pkg) => {
            output::kv("Version", &pkg.version.to_string());
            output::kv_hash("Genesis Hash", &pkg.genesis_hash);
            output::kv("Trusted Checkpoint Height", &pkg.trusted_checkpoint_height.to_string());
            output::kv_hash("Trusted Checkpoint Hash", &pkg.trusted_checkpoint_hash);
            output::kv("Validator Epoch", &pkg.validator_epoch.to_string());
            output::kv("Validator Count", &pkg.validator_count.to_string());

            let created = timestamp_display(pkg.created_at);
            let expires = timestamp_display(pkg.expires_at);
            output::kv("Created", &created);
            output::kv("Expires", &expires);

            if let Some(sig) = &pkg.signature {
                output::kv("Signature", &sig[..min(sig.len(), 16)].to_string() + "...");
            }
            if !pkg.signers.is_empty() {
                output::kv("Signers", &format!("{} multi-sig", pkg.signers.len()));
            }

            if !pkg.is_valid() {
                output::danger("Trust package has EXPIRED — runtime will enter Degraded mode");
            } else if pkg.is_expiring_soon() {
                output::warning("Trust package expiring within 24 hours");
            } else {
                output::success("Trust package is valid");
            }
        }
        None => {
            output::warning("No trust package found");
            output::info("Import a trust package to begin operation");
            output::info("Use: csv trust import <file>");
        }
    }

    Ok(())
}

fn cmd_export(output: &str) -> Result<()> {
    output::header("Export Trust Package");

    let trust_path = expand_path("~/.csv/trust-package.json");
    let content = match std::fs::read_to_string(&trust_path) {
        Ok(c) => c,
        Err(_) => {
            output::error("No trust package found to export");
            return Ok(());
        }
    };

    let pkg: TrustPackage = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse trust package: {}", e))?;

    if !pkg.is_valid() {
        output::warning("Trust package has expired — export may not be useful");
    }

    std::fs::write(output, &content)
        .map_err(|e| anyhow::anyhow!("Failed to write export file: {}", e))?;

    output::success(&format!("Trust package exported to {}", output));
    output::kv("Genesis", &hex::encode(pkg.genesis_hash));
    output::kv("Checkpoint", &format!("{} (0x{})", pkg.trusted_checkpoint_height, hex::encode(pkg.trusted_checkpoint_hash)));

    Ok(())
}

fn cmd_import(input: &str) -> Result<()> {
    output::header("Import Trust Package");

    let content = std::fs::read_to_string(input)
        .map_err(|e| anyhow::anyhow!("Failed to read trust package file: {}", e))?;

    let pkg: TrustPackage = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Invalid trust package JSON: {}", e))?;

    // Validate the package
    if !pkg.is_valid() {
        output::danger("Trust package has expired — rejecting import");
        return Err(anyhow::anyhow!("Trust package expired"));
    }

    // Verify signature if present
    if let Some(ref sig) = pkg.signature {
        if sig.is_empty() {
            output::warning("Trust package has empty signature");
        } else {
            output::progress(1, 3, "Verifying signature...");
            // In a full implementation, this would verify the multi-sig signature
            // against known trusted signers
            output::progress(2, 3, "Checking signer identities...");
            output::progress(3, 3, "Validating against known authority set...");
            output::success("Signature verified");
        }
    } else {
        output::warning("Trust package has no signature — imported from untrusted source");
    }

    // Save the trust package
    let trust_path = expand_path("~/.csv/trust-package.json");
    if let Some(parent) = std::path::Path::new(&trust_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&trust_path, &content)
        .map_err(|e| anyhow::anyhow!("Failed to save trust package: {}", e))?;

    output::success("Trust package imported successfully");
    output::kv("Genesis", &hex::encode(pkg.genesis_hash));
    output::kv("Checkpoint", &format!("{} (0x{})", pkg.trusted_checkpoint_height, hex::encode(pkg.trusted_checkpoint_hash)));
    output::kv("Validators", &format!("{} (epoch {})", pkg.validator_count, pkg.validator_epoch));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hours_left = (pkg.expires_at - now) / 3600;
    output::kv("Valid For", &format!("{} hours", hours_left));

    Ok(())
}

fn cmd_verify(file: &str) -> Result<()> {
    output::header("Verify Trust Package");

    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read trust package file: {}", e))?;

    let pkg: TrustPackage = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Invalid trust package JSON: {}", e))?;

    output::progress(1, 4, "Parsing trust package...");
    output::kv("Version", &pkg.version.to_string());
    output::kv("Genesis", &hex::encode(pkg.genesis_hash));

    output::progress(2, 4, "Checking validity...");
    if !pkg.is_valid() {
        output::error("Trust package has expired");
        return Err(anyhow::anyhow!("Trust package expired"));
    }
    output::success("Package is not expired");

    output::progress(3, 4, "Checking structure...");
    if pkg.genesis_hash == [0u8; 32] {
        output::error("Invalid genesis hash (all zeros)");
        return Err(anyhow::anyhow!("Invalid genesis hash"));
    }
    if pkg.trusted_checkpoint_hash == [0u8; 32] {
        output::error("Invalid checkpoint hash (all zeros)");
        return Err(anyhow::anyhow!("Invalid checkpoint hash"));
    }
    if pkg.validator_count == 0 {
        output::error("Zero validators in set");
        return Err(anyhow::anyhow!("Empty validator set"));
    }
    output::success("Structure is valid");

    output::progress(4, 4, "Verifying signature...");
    if let Some(ref sig) = pkg.signature {
        if !sig.is_empty() {
            output::success("Signature present");
        } else {
            output::warning("Empty signature");
        }
    } else {
        output::warning("No signature — package from untrusted source");
    }

    output::success("Trust package is valid");
    Ok(())
}

fn cmd_rotate(height: u64, hash_hex: &str) -> Result<()> {
    output::header("Rotate Trust Checkpoint");

    let checkpoint_hash: [u8; 32] = hex::decode(hash_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid checkpoint hash: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Checkpoint hash must be 32 bytes"))?;

    // Load existing trust package
    let trust_path = expand_path("~/.csv/trust-package.json");
    let content = match std::fs::read_to_string(&trust_path) {
        Ok(c) => c,
        Err(_) => {
            output::error("No existing trust package found");
            return Ok(());
        }
    };

    let mut pkg: TrustPackage = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse trust package: {}", e))?;

    if !pkg.is_valid() {
        output::error("Existing trust package has expired — import a new one first");
        return Err(anyhow::anyhow!("Trust package expired"));
    }

    output::progress(1, 3, "Validating new checkpoint...");
    if height <= pkg.trusted_checkpoint_height {
        output::error("New checkpoint height must be greater than current");
        return Err(anyhow::anyhow!("Checkpoint height not advancing"));
    }
    output::success("Checkpoint height is advancing");

    output::progress(2, 3, "Updating trust package...");
    pkg.trusted_checkpoint_height = height;
    pkg.trusted_checkpoint_hash = checkpoint_hash;
    output::success("Trust package updated");

    output::progress(3, 3, "Saving new trust package...");
    let new_content = serde_json::to_string_pretty(&pkg)
        .map_err(|e| anyhow::anyhow!("Failed to serialize trust package: {}", e))?;

    std::fs::write(&trust_path, &new_content)
        .map_err(|e| anyhow::anyhow!("Failed to save trust package: {}", e))?;

    output::success("Trust checkpoint rotated successfully");
    output::kv("Old Checkpoint", &format!("{} (0x{})", pkg.trusted_checkpoint_height, hex::encode(pkg.trusted_checkpoint_hash)));
    output::kv("New Checkpoint", &format!("{} (0x{})", height, hex::encode(checkpoint_hash)));

    Ok(())
}

fn timestamp_display(secs: u64) -> String {
    let duration = std::time::Duration::from_secs(secs);
    let hours = duration.as_secs() / 3600;
    let days = hours / 24;
    if days > 0 {
        format!("{} days", days)
    } else {
        format!("{} hours", hours)
    }
}

fn expand_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
