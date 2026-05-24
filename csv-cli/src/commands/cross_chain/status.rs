//! Cross-chain transfer status commands

use anyhow::Result;

use csv_hash::Hash;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferStatus, UnifiedStateManager};

pub fn cmd_status(transfer_id: String, state: &UnifiedStateManager) -> Result<()> {
    let bytes = hex::decode(transfer_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Transfer ID: {}", e))?;
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes[..32]);
    let transfer_id_hash = Hash::new(hash_bytes);

    output::header(&format!("Transfer: {}", transfer_id));

    if let Some(transfer) = state.get_transfer(&transfer_id_hash.to_string()) {
        output::header("📋 Cross-Chain Transfer Report");

        output::kv("Transfer ID", &hex::encode(transfer.id.as_bytes()));
        output::kv("Sanad ID", &hex::encode(transfer.sanad_id.as_bytes()));
        output::kv("Status", &format!("{:?}", transfer.status));
        output::kv(
            "Created At",
            &chrono::DateTime::<chrono::Utc>::from_timestamp(transfer.created_at as i64, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| transfer.created_at.to_string()),
        );

        if let Some(completed) = transfer.completed_at {
            output::kv(
                "Completed At",
                &chrono::DateTime::<chrono::Utc>::from_timestamp(completed as i64, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| completed.to_string()),
            );
        }

        output::header("🔹 Source Chain");
        output::kv("Chain", transfer.source_chain.as_ref());
        if let Some(sender) = &transfer.sender_address {
            output::kv("Sender Address", sender);
        }
        if let Some(source_tx) = &transfer.source_tx_hash {
            output::kv_hash("Transaction ID", source_tx.as_bytes());
        }
        if let Some(fee) = transfer.source_fee {
            output::kv("Transaction Fee", &fee.to_string());
        }

        output::header("🔸 Destination Chain");
        output::kv("Chain", transfer.dest_chain.as_ref());
        if let Some(dest_addr) = &transfer.destination_address {
            output::kv("Destination Address", dest_addr);
        }
        if let Some(dest_tx) = &transfer.dest_tx_hash {
            output::kv_hash("Transaction ID", dest_tx.as_bytes());
        }
        if let Some(fee) = transfer.dest_fee {
            output::kv("Transaction Fee", &fee.to_string());
        }
        if let Some(contract) = &transfer.destination_contract {
            output::kv("Contract Address", contract);
        }
    } else {
        output::warning("Transfer not found");
    }

    Ok(())
}

pub fn cmd_list(from: Option<Chain>, to: Option<Chain>, state: &UnifiedStateManager) -> Result<()> {
    output::header("Cross-Chain Transfers");

    let headers = vec!["Transfer ID", "From", "To", "Sanad ID", "Status"];
    let mut rows = Vec::new();

    for transfer in &state.storage.transfers {
        if let Some(ref filter_from) = from
            && transfer.source_chain != *filter_from
        {
            continue;
        }
        if let Some(ref filter_to) = to
            && transfer.dest_chain != *filter_to
        {
            continue;
        }

        let status_str = match &transfer.status {
            TransferStatus::Completed => "Completed".to_string(),
            TransferStatus::Failed => "Failed".to_string(),
            other => format!("{:?}", other),
        };

        rows.push(vec![
            hex::encode(transfer.id.as_bytes())[..10].to_string(),
            transfer.source_chain.to_string(),
            transfer.dest_chain.to_string(),
            hex::encode(transfer.sanad_id.as_bytes())[..10].to_string(),
            status_str,
        ]);
    }

    if rows.is_empty() {
        output::info("No transfers recorded. Use 'csv cross-chain transfer' to start one.");
    } else {
        output::table(&headers, &rows);
    }

    Ok(())
}

pub fn cmd_retry(
    transfer_id: String,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Retrying Transfer");
    output::kv("Transfer ID", &transfer_id);

    // Parse transfer ID
    let bytes = hex::decode(transfer_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Transfer ID: {}", e))?;
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes[..32]);
    let transfer_id_hash = Hash::new(hash_bytes);

    // Look up transfer
    let transfer = state.get_transfer(&transfer_id_hash.to_string());
    match transfer {
        Some(t) => {
            output::kv("Source", t.source_chain.as_ref());
            output::kv("Destination", t.dest_chain.as_ref());
            output::kv("Status", &format!("{:?}", t.status));

            match &t.status {
                TransferStatus::Failed => {
                    output::warning("Transfer failed");
                    output::info(
                        "If lock was successful but mint failed, wait for timeout (24h) and the source chain seal will be recoverable via refund.",
                    );
                    output::info(
                        "For timed-out locks: the refund function is available on the source chain contract.",
                    );
                }
                TransferStatus::Locked | TransferStatus::Initiated => {
                    output::info(
                        "Transfer is in progress. If stuck, wait for lock timeout and refund.",
                    );
                }
                TransferStatus::Completed => {
                    output::success("Transfer already completed successfully.");
                }
                _ => {
                    output::info("Transfer status does not support retry.");
                }
            }
        }
        None => {
            output::warning("Transfer not found in state.");
        }
    }

    Ok(())
}
