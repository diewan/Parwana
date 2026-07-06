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
        #[arg(long)]
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

pub async fn execute(
    action: SealAction,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        SealAction::Create { chain, value } => cmd_create(chain, value, state).await,
        SealAction::Consume { chain, seal_ref } => cmd_consume(chain, seal_ref, state).await,
        SealAction::Verify { chain, seal_ref } => cmd_verify(chain, seal_ref, state).await,
        SealAction::List { chain } => cmd_list(chain, state),
    }
}

async fn cmd_create(
    chain: Chain,
    value: Option<u64>,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Creating Seal on {}", chain));

    let core_chain = to_protocol_chain(chain.clone());

    // Phase 5: Use runtime client to create seal via SanadsManager
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Check chain readiness for seal creation
    let runtime = client.chain_runtime();
    let readiness = runtime
        .check_readiness(core_chain.clone(), 0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check chain readiness: {}", e))?;

    if !readiness.write_capable {
        output::error("Chain readiness check failed: Write capability not available");
        return Err(anyhow::anyhow!(
            "Cannot create seal: write capability not available"
        ));
    }

    output::success("Chain readiness check passed");

    // Create a seal by creating a basic Sanad (which creates a seal)
    let sanads = client.sanads();

    // Generate a commitment for seal creation
    let commitment = Hash::new(generate_commitment());

    // Generate non-zero placeholder hashes for required fields
    let schema_hash = Hash::new([1u8; 32]);
    let disclosure_policy_hash = Hash::new([2u8; 32]);
    let proof_policy_hash = Hash::new([3u8; 32]);

    // Create a minimal SanadPayloadDescriptor
    let descriptor = csv_protocol::SanadPayloadDescriptor::new(
        csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
        schema_hash,
        1,
        commitment,
        None,
        disclosure_policy_hash,
        proof_policy_hash,
    );

    // Create ownership proof with empty owner
    let ownership_proof = csv_protocol::OwnershipProof {
        owner: vec![],
        proof: vec![],
        scheme: None,
    };

    let salt: [u8; 16] = rand::random();

    // Create the sanad (which internally creates a seal via the runtime)
    match sanads.create(&descriptor, commitment, ownership_proof, &salt, core_chain) {
        Ok(sanad) => {
            let seal_id = sanad.id.bytes.clone();
            let value_sat = value.unwrap_or(100_000);

            output::kv("Chain", chain.as_ref());
            output::kv("Seal ID", &seal_id[..16.min(seal_id.len())]);
            output::kv("Value", &format!("{} satoshis", value_sat));
            output::kv("Sanad ID", &sanad.id.bytes[..16.min(sanad.id.bytes.len())]);
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

async fn cmd_consume(
    chain: Chain,
    seal_ref: String,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Consuming Seal on {}", chain));

    let seal_bytes = hex::decode(seal_ref.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid seal reference: {}", e))?;
    let seal_hash = csv_hash::Hash::new(
        seal_bytes[..32.min(seal_bytes.len())]
            .try_into()
            .unwrap_or([0u8; 32]),
    );
    let seal_hex = hex::encode(&seal_bytes);

    let core_chain = to_protocol_chain(chain.clone());

    // Use runtime to check canonical seal state before consuming (CLI-STATE-001)
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    let runtime = client.chain_runtime();

    // Query canonical seal state via ChainBackend (fail closed if unavailable)
    match runtime.get_adapter(core_chain.clone()).await {
        Ok(adapter) => {
            match adapter.get_seal_state(&seal_hash).await {
                Ok(canonical_state) => {
                    // Check if seal is already consumed on-chain
                    if let Some(consumed_at) = canonical_state.consumed_at {
                        output::error("Seal already consumed on-chain");
                        return Err(anyhow::anyhow!(
                            "Seal replay detected: canonical state shows seal consumed at {}",
                            consumed_at
                        ));
                    }
                    output::info("Canonical state check passed: seal is not consumed on-chain");
                }
                Err(e) => {
                    // Chain query failed - fail closed (CLI-STATE-001)
                    return Err(anyhow::anyhow!(
                        "Failed to query canonical seal state from chain: {}. \
                         Cannot proceed without on-chain validation.",
                        e
                    ));
                }
            }
        }
        Err(e) => {
            // Adapter not available - fail closed (CLI-STATE-001)
            return Err(anyhow::anyhow!(
                "Chain adapter not available for {}: {}. \
                 Cannot determine canonical seal state without chain access.",
                chain,
                e
            ));
        }
    }

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
            // Update local display cache AFTER successful on-chain consumption
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

async fn cmd_verify(chain: Chain, seal_ref: String, state: &UnifiedStateManager) -> Result<()> {
    output::header(&format!("Verifying Seal on {}", chain));

    let seal_bytes = hex::decode(seal_ref.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid seal reference: {}", e))?;
    let seal_hash = csv_hash::Hash::new(
        seal_bytes[..32.min(seal_bytes.len())]
            .try_into()
            .unwrap_or([0u8; 32]),
    );

    let core_chain = to_protocol_chain(chain.clone());

    // Use runtime to verify seal status via ChainBackend (CLI-STATE-001)
    let client = CsvClient::builder()
        .with_chain(core_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    let runtime = client.chain_runtime();

    // Query canonical seal state via ChainBackend (fail closed if unavailable)
    match runtime.get_adapter(core_chain.clone()).await {
        Ok(adapter) => {
            match adapter.get_seal_state(&seal_hash).await {
                Ok(canonical_state) => {
                    // Display canonical state from chain
                    output::kv("Chain", chain.as_ref());
                    output::kv_hash("Seal", &seal_bytes);
                    output::kv("State", &format!("State({})", canonical_state.state));
                    output::kv("Owner", &canonical_state.owner);
                    output::kv_hash("Commitment", canonical_state.commitment.as_bytes());
                    if canonical_state.created_at > 0 {
                        output::kv(
                            "Created",
                            &chrono::DateTime::from_timestamp(canonical_state.created_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| canonical_state.created_at.to_string()),
                        );
                    }
                    if let Some(consumed_at) = canonical_state.consumed_at {
                        output::kv(
                            "Consumed",
                            &chrono::DateTime::from_timestamp(consumed_at, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| consumed_at.to_string()),
                        );
                    }
                    output::success("Canonical seal state from chain");
                }
                Err(e) => {
                    // Chain query failed - fail closed (CLI-STATE-001)
                    return Err(anyhow::anyhow!(
                        "Failed to query canonical seal state from chain: {}. \
                         Local state cannot be used as canonical truth.",
                        e
                    ));
                }
            }
        }
        Err(e) => {
            // Adapter not available - fail closed (CLI-STATE-001)
            return Err(anyhow::anyhow!(
                "Chain adapter not available for {}: {}. \
                 Cannot determine canonical seal state without chain access.",
                chain,
                e
            ));
        }
    }

    // Show local display cache if available (non-canonical)
    let local_consumed = state.is_seal_consumed(&hex::encode(&seal_bytes));
    if local_consumed {
        output::info("---");
        output::info("Local display cache (non-canonical, for reference only):");
        output::kv("Local Status", "Consumed");
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
