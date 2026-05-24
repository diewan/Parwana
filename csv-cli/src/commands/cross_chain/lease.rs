//! Acquire lease command implementation

use anyhow::Result;

use csv_hash::Hash;
use csv_protocol::lease::LeaseManager;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;

use super::to_core_chain;

/// Acquire a lease for a sanad to prepare for cross-chain transfer
pub fn cmd_acquire_lease(
    sanad_id: String,
    ttl_secs: u64,
    chain: Chain,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let from_chain = to_core_chain(chain.clone());

    output::header(&format!("Acquire Lease: {:?}", from_chain));

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

    // Get the owner address for this chain
    let owner_addr = state
        .get_address(&chain)
        .ok_or_else(|| anyhow::anyhow!("No wallet address found for chain {:?}", chain))?;

    // Hash the owner address to get a 32-byte value
    let owner_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(owner_addr.as_bytes());
        Hash::new(hasher.finalize().into())
    };

    // Create lease manager and acquire lease
    let mut lease_manager = LeaseManager::new();
    let lease_id = lease_manager
        .acquire(sanad_id_hash, owner_hash, ttl_secs)
        .map_err(|e| anyhow::anyhow!("Failed to acquire lease: {}", e))?;

    // Get the lease for display
    let lease = lease_manager
        .leases
        .get(&sanad_id_hash)
        .ok_or_else(|| anyhow::anyhow!("Lease not found after acquisition"))?;

    output::success(&format!("Lease acquired: {}", lease_id));
    output::info(&format!("  Sanad ID: {}", sanad_id_hash));
    output::info(&format!("  Owner: {}", owner_addr));
    output::info(&format!("  TTL: {} seconds", lease.ttl_secs));
    output::info(&format!("  Expires: {} seconds from now", lease.ttl_secs));
    output::info(&format!(
        "  Lease ID: 0x{}",
        hex::encode(lease_id.as_bytes())
    ));

    // Note: Lease state is managed exclusively by csv-runtime.
    // The CLI returns the lease token to the user for use with transfer commands.

    Ok(())
}
