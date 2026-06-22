//! Mint operations for CSV sanads on Solana
//!
//! This module provides SDK-based minting using solana-sdk for transaction building
//! and JSON-RPC for submission (avoids version compatibility issues).

use crate::error::{SolanaError, SolanaResult};
use csv_hash::Hash as CsvHash;
use solana_sdk::pubkey::Pubkey;

/// Preflight check for Sanad creation
///
/// Validates that the signer account exists and has sufficient SOL for rent + transaction fees.
/// Returns an actionable error if checks fail, allowing early failure before transaction simulation.
async fn preflight_check_signer(
    rpc_url: &str,
    signer_pubkey: &Pubkey,
    _program_id: &Pubkey,
    _sanad_id: &CsvHash,
) -> SolanaResult<()> {
    use serde_json::json;

    /// Async RPC helper
    async fn post_rpc_json_async(
        rpc_url: String,
        request: serde_json::Value,
    ) -> SolanaResult<serde_json::Value> {
        let response = reqwest::Client::new()
            .post(&rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| SolanaError::Rpc(format!("RPC request failed: {}", e)))?;

        response
            .json()
            .await
            .map_err(|e| SolanaError::Rpc(format!("Failed to parse RPC response: {}", e)))
    }

    // Check account existence
    let account_json = post_rpc_json_async(
        rpc_url.to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "getAccountInfo",
            "params": [signer_pubkey.to_string(), {"encoding": "base64"}],
            "id": 1
        }),
    )
    .await?;

    let account_exists = account_json
        .get("result")
        .and_then(|r| r.get("value"))
        .is_some();

    if !account_exists {
        return Err(SolanaError::AccountNotFound(format!(
            "Signer account {} does not exist. Fund it with at least 0.001 SOL (rent-exempt minimum) via https://faucet.solana.com",
            signer_pubkey
        )));
    }

    // Get SOL balance
    let balance_json = post_rpc_json_async(
        rpc_url.to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "getBalance",
            "params": [signer_pubkey.to_string()],
            "id": 1
        }),
    )
    .await?;

    let balance_lamports = balance_json
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| SolanaError::Rpc("Missing balance in response".to_string()))?;

    // Estimate rent exemption for seal PDA
    // Seal account size: sanad_id (32) + commitment (32) + state_root (32) + source_chain (1) + source_seal_ref (32) + discriminator (8) + owner (32) + bump (1) = ~200 bytes
    const SEAL_ACCOUNT_SIZE: usize = 200;

    let rent_json = post_rpc_json_async(
        rpc_url.to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "getMinimumBalanceForRentExemption",
            "params": [SEAL_ACCOUNT_SIZE],
            "id": 1
        }),
    )
    .await?;

    let rent_lamports = rent_json
        .get("result")
        .and_then(|r| r.as_u64())
        .ok_or_else(|| SolanaError::Rpc("Missing rent in response".to_string()))?;

    // Estimate transaction fee (typical Solana transaction: ~5000 lamports)
    const TRANSACTION_FEE_LAMPORTS: u64 = 5000;

    let total_required = rent_lamports + TRANSACTION_FEE_LAMPORTS;

    if balance_lamports < total_required {
        let deficit = total_required - balance_lamports;
        let _deficit_sol = deficit as f64 / 1e9;
        return Err(SolanaError::InsufficientFunds {
            required: total_required,
            available: balance_lamports,
        });
    }

    Ok(())
}

/// Mint a sanad on Solana using JSON-RPC
///
/// This uses solana-sdk for keypair/transaction construction and direct JSON-RPC for sending.
#[allow(clippy::too_many_arguments)]
pub async fn mint_sanad_from_hex_key(
    rpc_url: &str,
    program_id: &str,
    private_key_hex: &str,
    sanad_id: CsvHash,
    commitment: CsvHash,
    state_root: CsvHash,
    source_chain: u8,
    source_seal_ref: CsvHash,
) -> SolanaResult<String> {
    use serde_json::json;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    /// Async version of post_rpc_json for use in async contexts.
    async fn post_rpc_json_async(
        rpc_url: String,
        request: serde_json::Value,
    ) -> SolanaResult<serde_json::Value> {
        let response = reqwest::Client::new()
            .post(&rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| SolanaError::Rpc(format!("RPC request failed: {}", e)))?;

        response
            .json()
            .await
            .map_err(|e| SolanaError::Rpc(format!("Failed to parse RPC response: {}", e)))
    }

    // Parse private key from hex
    let cleaned = private_key_hex.trim().trim_start_matches("0x").trim();
    let key_bytes =
        hex::decode(cleaned).map_err(|e| SolanaError::Wallet(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(SolanaError::Wallet(format!(
            "Invalid key length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    // Convert to fixed-size array and create keypair
    let secret_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| SolanaError::Wallet("Invalid key length".to_string()))?;
    let payer = Keypair::new_from_array(secret_key);

    // SOLANA-PREFLIGHT-001: Preflight check before transaction construction
    // Validates account existence, SOL balance, and rent/fee requirements
    let program_id_pubkey = program_id
        .parse::<Pubkey>()
        .map_err(|e| SolanaError::InvalidProgramId(format!("Invalid program ID: {}", e)))?;
    preflight_check_signer(rpc_url, &payer.pubkey(), &program_id_pubkey, &sanad_id).await?;

    // Get recent blockhash via JSON-RPC
    let blockhash_json = post_rpc_json_async(
        rpc_url.to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "getLatestBlockhash",
            "params": [],
            "id": 1
        }),
    )
    .await?;

    let blockhash_str = blockhash_json
        .get("result")
        .and_then(|r| {
            r.get("value")
                .and_then(|v| v.get("blockhash").and_then(|b| b.as_str()))
        })
        .ok_or_else(|| SolanaError::Rpc("Missing blockhash in response".to_string()))?;

    let blockhash = blockhash_str
        .parse()
        .map_err(|e| SolanaError::Rpc(format!("Invalid blockhash: {}", e)))?;

    // Derive the sanad PDA with correct seeds: ["sanad", owner, sanad_id]
    let (sanad_pda, _bump) = Pubkey::find_program_address(
        &[b"sanad", payer.pubkey().as_ref(), sanad_id.as_bytes()],
        &program_id_pubkey,
    );

    // Build instruction data with correct Anchor discriminator
    // Anchor discriminator = first 8 bytes of sha256("global:instruction_name")
    // For mint_sanad: sha256("global:mint_sanad")[0..8]
    let discriminator = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"global:mint_sanad");
        let hash = hasher.finalize();
        hash[..8].to_vec()
    };
    let mut data = discriminator;
    data.extend_from_slice(sanad_id.as_bytes());
    data.extend_from_slice(commitment.as_bytes());
    data.extend_from_slice(state_root.as_bytes());
    data.push(source_chain);
    data.extend_from_slice(source_seal_ref.as_bytes());

    // Build instruction
    let instruction = Instruction::new_with_bytes(
        program_id_pubkey,
        &data,
        vec![
            AccountMeta::new(sanad_pda, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(
                "11111111111111111111111111111111"
                    .parse::<Pubkey>()
                    .expect("System program ID is a valid Pubkey"),
                false,
            ), // system program
        ],
    );

    // Build and sign transaction
    let mut transaction =
        Transaction::new_unsigned(solana_sdk::message::Message::new_with_blockhash(
            &[instruction],
            Some(&payer.pubkey()),
            &blockhash,
        ));
    transaction.sign(&[&payer], blockhash);

    // Serialize transaction
    let tx_bytes = bincode::serialize(&transaction)
        .map_err(|e| SolanaError::Serialization(format!("Failed to serialize: {}", e)))?;
    use base64::engine::{Engine as _, general_purpose};
    let tx_base64 = general_purpose::STANDARD.encode(&tx_bytes);

    // Send via JSON-RPC
    let send_json = post_rpc_json_async(
        rpc_url.to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "sendTransaction",
            "params": [tx_base64, {"encoding": "base64"}],
            "id": 1
        }),
    )
    .await?;

    if let Some(error) = send_json.get("error") {
        return Err(SolanaError::Transaction(format!("RPC error: {}", error)));
    }

    let signature = send_json
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| SolanaError::Transaction("Missing signature in response".to_string()))?;

    Ok(signature.to_string())
}
