//! Protocol inspection commands (`csv inspect replay|merkle`).

use anyhow::{Context, Result};
use clap::Subcommand;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum InspectAction {
    /// Inspect replay registry entry or ReplayId derivation inputs
    Replay {
        /// Hex-encoded 32-byte replay id or path to replay record file
        #[arg(long)]
        id: Option<String>,
        /// Path to canonical CBOR replay record
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Inspect Merkle proof / root from canonical CBOR or hex siblings
    Merkle {
        /// Hex-encoded Merkle root
        #[arg(long)]
        root: Option<String>,
        /// Path to proof bundle or inclusion proof JSON/CBOR file
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

pub fn execute(action: InspectAction) -> Result<()> {
    match action {
        InspectAction::Replay { id, file } => inspect_replay(id, file),
        InspectAction::Merkle { root, file } => inspect_merkle(root, file),
    }
}

fn inspect_replay(id: Option<String>, file: Option<PathBuf>) -> Result<()> {
    if let Some(path) = file {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let value: serde_json::Value = if path.extension().is_some_and(|e| e == "json") {
            serde_json::from_slice(&bytes)?
        } else {
            let decoded: serde_json::Value = from_canonical_cbor(&bytes)
                .map_err(|e| anyhow::anyhow!("canonical CBOR decode failed: {e}"))?;
            decoded
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if let Some(hex_id) = id {
        let raw = hex::decode(hex_id.trim_start_matches("0x"))
            .context("replay id must be hex")?;
        anyhow::ensure!(raw.len() == 32, "replay id must be 32 bytes");
        let canonical = to_canonical_cbor(&raw).context("canonical encode replay id")?;
        println!("replay_id_hex: {}", hex::encode(&raw));
        println!("canonical_cbor_hex: {}", hex::encode(canonical));
        return Ok(());
    }
    anyhow::bail!("provide --id or --file for replay inspection")
}

fn inspect_merkle(root: Option<String>, file: Option<PathBuf>) -> Result<()> {
    if let Some(ref hex_root) = root {
        let raw = hex::decode(hex_root.trim_start_matches("0x")).context("root must be hex")?;
        anyhow::ensure!(raw.len() == 32, "root must be 32 bytes");
        println!("merkle_root: {}", hex::encode(raw));
    }
    if let Some(path) = file {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if path.extension().is_some_and(|e| e == "json") {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            let v: serde_json::Value = from_canonical_cbor(&bytes)
                .map_err(|e| anyhow::anyhow!("canonical CBOR decode failed: {e}"))?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        return Ok(());
    }
    if root.is_none() {
        anyhow::bail!("provide --root and/or --file for merkle inspection");
    }
    Ok(())
}
