//! Shared helpers for Sui gRPC transaction execution.

use std::future::Future;

/// Well-known initial shared version of the Sui system `Clock` object (`0x6`).
///
/// The `Clock` is shared at genesis on every Sui network, so its
/// `initial_shared_version` is a fixed constant rather than something to fetch.
pub(crate) const CLOCK_INITIAL_SHARED_VERSION: u64 = 1;

/// The `0x6` system `Clock` object id (32-byte, big-endian).
pub(crate) const CLOCK_OBJECT_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[31] = 0x06;
    id
};

/// Bound a Sui gRPC call in time.
///
/// `sui_rpc::Client` sets a connect timeout but no per-request timeout, so a call the
/// fullnode accepts and never answers blocks its caller forever. Every RPC on a path that
/// can submit or gate a transfer must fail closed instead of hanging.
pub(crate) async fn with_rpc_timeout<T, E, F>(
    timeout_ms: u64,
    operation: &str,
    future: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let duration = std::time::Duration::from_millis(timeout_ms);
    match tokio::time::timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{} failed: {}", operation, e)),
        Err(_) => Err(format!(
            "{} timed out after {}ms (no response from the Sui node)",
            operation, timeout_ms
        )),
    }
}

/// Identity of a source-chain lock event, as the destination registry records it.
///
/// `csv_tagged_hash("csv.mint.lock-event.v1", tx_digest || u32_le(output_index))`. Sui has
/// no transaction output index, so the runtime records `0`; the Move `csv_seal::lock_sanad`
/// derives the same value on-chain from its own transaction digest. Both sides are pinned
/// to the vector in `lock_event_id_matches_move_contract`.
pub(crate) fn lock_event_id(tx_digest: &[u8; 32], output_index: u32) -> [u8; 32] {
    let mut preimage = tx_digest.to_vec();
    preimage.extend_from_slice(&output_index.to_le_bytes());
    csv_hash::csv_tagged_hash("csv.mint.lock-event.v1", &preimage)
}

/// Field mask applied to every `ExecuteTransactionRequest`.
///
/// The service defaults to `effects.status,checkpoint` when no mask is set, so
/// `digest` and `effects.changed_objects` come back absent/empty unless they are
/// requested explicitly. Callers depend on all three.
pub(crate) fn execution_read_mask() -> prost_types::FieldMask {
    prost_types::FieldMask {
        paths: vec![
            "digest".to_string(),
            "effects".to_string(),
            "checkpoint".to_string(),
        ],
    }
}

/// Fail closed when a transaction executed but reverted on chain.
pub(crate) fn ensure_execution_succeeded(
    effects: &sui_rpc::proto::sui::rpc::v2::TransactionEffects,
) -> Result<(), String> {
    let Some(status) = effects.status.as_ref() else {
        return Err("Sui execution effects did not include a status".to_string());
    };
    match status.success {
        Some(true) => Ok(()),
        Some(false) => Err(status
            .error
            .as_ref()
            .map(|e| format!("Sui transaction reverted: {:?}", e))
            .unwrap_or_else(|| "Sui transaction reverted (unknown error)".to_string())),
        None => Err("Sui execution status did not report success".to_string()),
    }
}

/// Normalize a Sui transaction digest into the 32-byte hex form the runtime
/// records. Sui reports digests as Base58; hex is accepted for callers that
/// already normalized.
pub(crate) fn tx_digest_to_runtime_hex(digest: &str) -> Result<String, String> {
    let digest = digest.trim();
    if digest.is_empty() {
        return Err("empty transaction digest".to_string());
    }
    if let Ok(bytes) = hex::decode(digest.trim_start_matches("0x")) {
        if bytes.len() == 32 {
            return Ok(hex::encode(bytes));
        }
    }
    let bytes = bs58::decode(digest)
        .into_vec()
        .map_err(|e| format!("invalid Sui transaction digest: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Sui transaction digest must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

/// Decode a 32-byte transaction digest from its on-wire representation.
pub(crate) fn tx_digest_to_bytes(digest: &str) -> Result<[u8; 32], String> {
    let hex_digest = tx_digest_to_runtime_hex(digest)?;
    let bytes = hex::decode(&hex_digest).map_err(|e| format!("invalid digest hex: {}", e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Move `csv_seal::lock_event_id_for_digest` test asserts this same constant, so a
    /// change to either derivation breaks one of the two suites.
    #[test]
    fn lock_event_id_matches_move_contract() {
        assert_eq!(
            hex::encode(lock_event_id(&[7u8; 32], 0)),
            "c07e02ce3a004f8f071cbb6d89f4e57f3d0aa0f80e848d09af755672e4e67076"
        );
    }

    #[tokio::test]
    async fn rpc_timeout_fails_closed_on_a_call_that_never_answers() {
        let never = std::future::pending::<Result<(), String>>();
        let err = with_rpc_timeout(10, "GetObject", never).await.unwrap_err();
        assert!(err.contains("timed out"), "{}", err);
    }

    #[test]
    fn read_mask_requests_digest_and_effects() {
        let mask = execution_read_mask();
        assert!(mask.paths.contains(&"digest".to_string()));
        assert!(mask.paths.contains(&"effects".to_string()));
    }

    #[test]
    fn base58_digest_decodes_to_32_byte_hex() {
        let raw = [7u8; 32];
        let b58 = bs58::encode(raw).into_string();
        assert_eq!(tx_digest_to_runtime_hex(&b58).unwrap(), hex::encode(raw));
        assert_eq!(tx_digest_to_bytes(&b58).unwrap(), raw);
    }

    #[test]
    fn hex_digest_round_trips() {
        let raw = [9u8; 32];
        let hexed = format!("0x{}", hex::encode(raw));
        assert_eq!(tx_digest_to_runtime_hex(&hexed).unwrap(), hex::encode(raw));
    }

    #[test]
    fn short_digest_is_rejected() {
        let b58 = bs58::encode([1u8; 16]).into_string();
        assert!(tx_digest_to_runtime_hex(&b58).is_err());
        assert!(tx_digest_to_runtime_hex("").is_err());
    }

    #[test]
    fn reverted_transaction_fails_closed() {
        use sui_rpc::proto::sui::rpc::v2::{ExecutionStatus, TransactionEffects};

        let mut effects = TransactionEffects::default();
        assert!(ensure_execution_succeeded(&effects).is_err());

        let mut status = ExecutionStatus::default();
        status.success = Some(false);
        effects.status = Some(status);
        assert!(ensure_execution_succeeded(&effects).is_err());

        let mut status = ExecutionStatus::default();
        status.success = Some(true);
        effects.status = Some(status);
        assert!(ensure_execution_succeeded(&effects).is_ok());
    }
}
