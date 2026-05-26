//! Seal management commands (Phase 5 Compliant)
//!
//! Uses csv-sdk runtime APIs only - no direct chain adapter dependencies.

use anyhow::Result;
use clap::Subcommand;

use csv_hash::Hash;
use csv_protocol::SanadId;
use csv_sdk::CsvClient;

use crate::commands::cross_chain::to_protocol_chain;
use crate::config::{Chain, Config};
use crate::output;
use crate::state::{SealRecord, UnifiedStateManager};

#[derive(Subcommand)]
pub enum SealAction {
    /// Create a new seal on a chain
    Create {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Value (chain-specific)
        #[arg(short, long)]
        value: Option<u64>,
    },
    /// Consume a seal
    Consume {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Seal reference (chain-specific format)
        seal_ref: String,
    },
    /// Verify seal status
    Verify {
        /// Chain name
        #[arg(value_enum)]
        chain: Chain,
        /// Seal reference
        seal_ref: String,
    },
    /// List consumed seals
    List {
        /// Filter by chain
        #[arg(short, long, value_enum)]
        chain: Option<Chain>,
    },
}

pub fn execute(
    action: SealAction,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        SealAction::Create { chain, value } => cmd_create(chain, value, state),
        SealAction::Consume { chain, seal_ref } => cmd_consume(chain, seal_ref, state),
        SealAction::Verify { chain, seal_ref } => cmd_verify(chain, seal_ref, state),
        SealAction::List { chain } => cmd_list(chain, state),
    }
}

fn cmd_create(chain: Chain, value: Option<u64>, state: &mut UnifiedStateManager) -> Result<()> {
    output::header(&format!("Creating Seal on {}", chain));

    let core_chain = to_protocol_chain(chain.clone());

    // Phase 5: Use runtime client to create seal via SanadsManager
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Create a seal by creating a basic Sanad (which creates a seal)
    let sanads = client.sanads();

    // Generate a commitment for seal creation
    let commitment = Hash::new(generate_commitment());

    // Create the sanad (which internally creates a seal via the runtime)
    match sanads.create(commitment, core_chain) {
        Ok(sanad) => {
            let seal_id = hex::encode(sanad.id.as_bytes());
            let value_sat = value.unwrap_or(100_000);

            output::kv("Chain", chain.as_ref());
            output::kv("Seal ID", &seal_id[..16.min(seal_id.len())]);
            output::kv("Value", &format!("{} satoshis", value_sat));
            output::kv("Sanad ID", &hex::encode(sanad.id.as_bytes())[..16]);
            output::success("Seal created successfully via runtime");

            // Record in state
            state.storage.seals.push(SealRecord::new(
                seal_id,
                chain,
                value_sat,
                chrono::Utc::now().timestamp() as u64,
            ));
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to create seal via runtime: {}", e));
        }
    }

    Ok(())
}

/// Generate a random 32-byte commitment for seal creation.
fn generate_commitment() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn cmd_consume(chain: Chain, seal_ref: String, state: &mut UnifiedStateManager) -> Result<()> {
    output::header(&format!("Consuming Seal on {}", chain));

    let seal_bytes = hex::decode(seal_ref.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid seal reference: {}", e))?;
    let seal_hex = hex::encode(&seal_bytes);

    if state.is_seal_consumed(&seal_hex) {
        output::error("Seal already consumed");
        return Err(anyhow::anyhow!("Seal replay detected"));
    }

    let core_chain = to_protocol_chain(chain.clone());

    // Use runtime to consume the seal
    let client = CsvClient::builder()
        .with_chain(core_chain)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Find the sanad associated with this seal and burn it (consuming the seal)
    let sanads = client.sanads();

    // Create a SanadId from the seal reference
    let sanad_id_bytes: [u8; 32] = seal_bytes[..32.min(seal_bytes.len())]
        .try_into()
        .unwrap_or_else(|_| {
            let mut padded = [0u8; 32];
            padded[..seal_bytes.len().min(32)]
                .copy_from_slice(&seal_bytes[..seal_bytes.len().min(32)]);
            padded
        });
    let sanad_id = SanadId::new(sanad_id_bytes);

    // Burn the sanad, which consumes the seal
    match sanads.burn(&sanad_id) {
        Ok(()) => {
            state.record_seal_consumption(seal_hex.clone());

            output::kv("Chain", chain.as_ref());
            output::kv_hash("Seal", &seal_bytes);
            output::success("Seal consumed via runtime");
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to consume seal via runtime: {}", e));
        }
    }

    Ok(())
}

fn cmd_verify(chain: Chain, seal_ref: String, state: &UnifiedStateManager) -> Result<()> {
    output::header(&format!("Verifying Seal on {}", chain));

    let seal_bytes = hex::decode(seal_ref.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid seal reference: {}", e))?;

    let core_chain = to_protocol_chain(chain.clone());

    // Use runtime to verify seal status
    let client = CsvClient::builder()
        .with_chain(core_chain)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Query the sanad status via the sanads manager
    let sanads = client.sanads();

    // Create a SanadId from the seal reference
    let sanad_id_bytes: [u8; 32] = seal_bytes[..32.min(seal_bytes.len())]
        .try_into()
        .unwrap_or_else(|_| {
            let mut padded = [0u8; 32];
            padded[..seal_bytes.len().min(32)]
                .copy_from_slice(&seal_bytes[..seal_bytes.len().min(32)]);
            padded
        });
    let sanad_id = SanadId::new(sanad_id_bytes);

    // Check if the sanad exists and get its status
    let local_consumed = state.is_seal_consumed(&hex::encode(&seal_bytes));

    match sanads.get(&sanad_id) {
        Ok(Some(sanad)) => {
            // Sanad exists in the system
            let status = if local_consumed || sanad.nullifier.is_some() {
                "Consumed"
            } else {
                "Unconsumed"
            };
            output::kv("Chain", chain.as_ref());
            output::kv_hash("Seal", &seal_bytes);
            output::kv("Status", status);
            output::kv("Sanad ID", &hex::encode(sanad.id.as_bytes())[..16]);

            if !local_consumed && sanad.nullifier.is_none() {
                output::info("Seal is available for use");
            }
        }
        Ok(None) => {
            // Sanad not found in the system
            output::kv("Chain", chain.as_ref());
            output::kv_hash("Seal", &seal_bytes);
            output::kv(
                "Status",
                if local_consumed {
                    "Consumed"
                } else {
                    "Unknown"
                },
            );

            if local_consumed {
                output::info("Seal was consumed locally but not found in runtime");
            } else {
                output::warning("Seal not found in the system");
            }
        }
        Err(e) => {
            // Query failed, fall back to local state
            output::warning(&format!("Provider query failed: {}", e));
            output::kv("Chain", chain.as_ref());
            output::kv_hash("Seal", &seal_bytes);
            output::kv(
                "Status",
                if local_consumed {
                    "Consumed"
                } else {
                    "Unconsumed"
                },
            );
        }
    }

    Ok(())
}

fn cmd_list(chain: Option<Chain>, state: &UnifiedStateManager) -> Result<()> {
    output::header("Consumed Seals");

    let consumed_seals: Vec<&SealRecord> =
        state.storage.seals.iter().filter(|s| s.consumed).collect();

    if consumed_seals.is_empty() {
        output::info("No seals consumed");
    } else {
        let headers = vec!["#", "Seal (hex)", "Chain", "Consumed"];
        let mut rows = Vec::new();

        for (i, seal) in consumed_seals.iter().enumerate() {
            // Filter by chain if specified
            if let Some(ref filter_chain) = chain
                && &seal.chain != filter_chain
            {
                continue;
            }

            rows.push(vec![
                (i + 1).to_string(),
                seal.seal_ref[..16.min(seal.seal_ref.len())].to_string(),
                seal.chain.to_string(),
                "Yes".to_string(),
            ]);
        }

        output::table(&headers, &rows);
    }

    Ok(())
}
