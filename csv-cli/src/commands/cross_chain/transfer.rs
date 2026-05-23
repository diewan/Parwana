//! Cross-chain transfer command implementation (Phase 5 Compliant)
//!
//! Uses only csv-adapter runtime APIs - no direct chain adapter dependencies.

use anyhow::Result;

use csv_core::SanadId;
use csv_core::Hash;
use csv_core::lease::LeaseManager;
use csv_sdk::CsvClient;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferRecord, TransferStatus, UnifiedStateManager};

use super::to_core_chain;

/// Execute cross-chain transfer using only runtime API
pub async fn cmd_transfer(
    from: Chain,
    to: Chain,
    sanad_id: String,
    dest_owner: Option<String>,
    lease_token: Option<String>,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let from_chain = to_core_chain(from.clone());
    let to_chain = to_core_chain(to.clone());

    output::header(&format!(
        "Cross-Chain Transfer: {:?} → {:?}",
        from_chain, to_chain
    ));

    // Parse sanad ID
    let bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    if bytes.len() < 32 {
        return Err(anyhow::anyhow!(
            "Invalid Sanad ID: expected at least 32 bytes, got {} bytes",
            bytes.len()
        ));
    }
    let mut sanad_bytes = [0u8; 32];
    sanad_bytes.copy_from_slice(&bytes[..32]);
    let sanad_id_hash = Hash::new(sanad_bytes);

    // Check if we have the sanad
    if state.get_sanad(&sanad_id_hash.to_string()).is_none() {
        return Err(anyhow::anyhow!(
            "Sanad {} not found in local state",
            sanad_id_hash
        ));
    }

    // Validate lease if provided
    if let Some(lease_token_str) = &lease_token {
        let lease_bytes = hex::decode(lease_token_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid lease token: {}", e))?;
        if lease_bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Invalid lease token: expected at least 32 bytes, got {} bytes",
                lease_bytes.len()
            ));
        }

        let mut lease_bytes_arr = [0u8; 32];
        lease_bytes_arr.copy_from_slice(&lease_bytes[..32]);
        let lease_id = csv_core::lease::LeaseId(Hash::new(lease_bytes_arr));

        // Get stored lease info
        let stored_lease = state
            .get_lease(&sanad_id_hash.to_string())
            .ok_or_else(|| anyhow::anyhow!("No lease found for this sanad. Run acquire-lease first."))?;

        // Parse stored owner hash
        let stored_owner_bytes = hex::decode(stored_lease.owner.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid stored owner: {}", e))?;
        let mut owner_arr = [0u8; 32];
        owner_arr.copy_from_slice(&stored_owner_bytes[..32]);
        let owner_hash = Hash::new(owner_arr);

        // Validate lease using in-memory lease manager
        let lease_manager = LeaseManager::new();
        lease_manager
            .validate(lease_id, sanad_id_hash, owner_hash)
            .map_err(|e| anyhow::anyhow!("Lease validation failed: {}", e))?;

        output::info("Lease validated successfully.");
    }

    // Get destination owner address
    let dest_owner_str = dest_owner.or_else(|| state.get_address(&from).map(|s| s.to_string()));

    if dest_owner_str.is_none() {
        return Err(anyhow::anyhow!(
            "No destination address specified and no wallet address found for {:?}",
            to_chain
        ));
    }

    let dest_addr = dest_owner_str.unwrap();

    // Create client builder with source and destination chains
    let client = CsvClient::builder()
        .with_chain(from_chain.clone())
        .with_chain(to_chain.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Execute the real cross-chain transfer via runtime
    output::info(&format!(
        "Locking Sanad {} on {:?}",
        sanad_id_hash, from_chain
    ));
    let sanad = SanadId(sanad_id_hash);
    let transfer_id = client
        .transfers()
        .cross_chain(sanad, to_chain.clone())
        .to_address(dest_addr.clone())
        .from_chain(from_chain.clone())
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("Transfer execution failed: {}", e))?;

    output::success(&format!(
        "Transfer {} initiated. Sanad locked on source chain.",
        transfer_id
    ));

    // Clone for use in record after get_address call
    let from_chain_clone = from.clone();
    let sender = state.get_address(&from).map(|s| s.to_string());

    // Record transfer in state
    let transfer_record = TransferRecord {
        id: transfer_id.clone(),
        source_chain: from_chain_clone,
        dest_chain: to,
        sanad_id: sanad_id_hash.to_string(),
        sender_address: sender,
        destination_address: Some(dest_addr),
        source_tx_hash: None,
        source_fee: None,
        dest_tx_hash: None,
        dest_fee: None,
        destination_contract: None,
        proof: None,
        status: TransferStatus::Initiated,
        created_at: chrono::Utc::now().timestamp() as u64,
        completed_at: None,
    };

    state.add_transfer(transfer_record);

    output::success(&format!(
        "Transfer {} recorded in local state.",
        transfer_id
    ));

    Ok(())
}

/// Generate deterministic transfer ID
fn generate_transfer_id(sanad_id: &Hash, from: &Chain, to: &Chain) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(sanad_id.as_bytes());
    hasher.update(from.to_string().as_bytes());
    hasher.update(to.to_string().as_bytes());
    hasher.update(chrono::Utc::now().timestamp().to_le_bytes());

    format!("0x{}", hex::encode(hasher.finalize()))
}
