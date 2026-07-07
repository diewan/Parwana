//! Cross-chain transfer status commands

use anyhow::Result;

use crate::commands::cross_chain::transfer::emit_provenance_strength_warning;
use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferStatus, UnifiedStateManager};

pub async fn cmd_status(
    transfer_id: String,
    _config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Transfer: {}", transfer_id));

    // Try to get canonical transfer state from runtime (CLI-STATE-001)
    // For now, we display local state but label it as non-canonical
    // Full runtime-backed transfer state requires csv-runtime TransferCoordinator integration

    if let Some(transfer) = state.get_transfer(&transfer_id) {
        output::header("📋 Cross-Chain Transfer Report");
        output::info("Source: Local display cache (non-canonical)");
        output::info(
            "Note: Runtime-backed canonical transfer state requires csv-runtime TransferCoordinator integration",
        );

        // `id` and `sanad_id` are already hex strings; don't hex-encode the
        // ASCII of the string again.
        output::kv("Transfer ID", &transfer.id);
        output::kv("Sanad ID", &transfer.sanad_id);
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
            output::kv("Transaction ID", source_tx);
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
            output::kv("Transaction ID", dest_tx);
        }
        if let Some(fee) = transfer.dest_fee {
            output::kv("Transaction Fee", &fee.to_string());
        }
        if let Some(contract) = &transfer.destination_contract {
            output::kv("Contract Address", contract);
        }
        if let Some(signal) = &transfer.provenance_strength {
            output::header("Provenance Strength");
            emit_provenance_strength_warning(signal);
        }
    } else {
        output::warning("Transfer not found in local display cache");
    }

    Ok(())
}

pub fn cmd_list(from: Option<Chain>, to: Option<Chain>, state: &UnifiedStateManager) -> Result<()> {
    output::header("Cross-Chain Transfers");
    output::info("Source: Local display cache (non-canonical)");
    output::info(
        "Note: Runtime-backed canonical transfer state requires csv-runtime TransferCoordinator integration",
    );

    // Full Sanad ID (not truncated): it is the argument `cross-chain resume`
    // needs, so it must be copy-pasteable straight from this table.
    let headers = vec!["Transfer ID", "From", "To", "Sanad ID", "Status"];
    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();

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

        // Older caches accumulated one duplicate row per finality re-check;
        // collapse them so each transfer appears once.
        if !seen.insert(transfer.id.clone()) {
            continue;
        }

        let status_str = match &transfer.status {
            TransferStatus::Completed => "Completed".to_string(),
            TransferStatus::Failed => "Failed".to_string(),
            other => format!("{:?}", other),
        };

        // `id` and `sanad_id` are already hex/UUID strings; render them directly
        // rather than hex-encoding the ASCII of the string again. Show the full
        // Transfer ID — `cross-chain resume` looks it up by exact match, so a
        // truncated value is useless.
        rows.push(vec![
            transfer.id.clone(),
            transfer.source_chain.to_string(),
            transfer.dest_chain.to_string(),
            transfer.sanad_id.clone(),
            status_str,
        ]);
    }

    if rows.is_empty() {
        output::info(
            "No transfers recorded. Use 'csv cross-chain send' (off-chain) or \
             'csv cross-chain materialize' (on-chain) to start one.",
        );
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

    // Look up transfer
    let transfer = state.get_transfer(&transfer_id);
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
