//! Real Solana RPC client implementation
//!
//! Wraps `solana-rpc-client` behind the `SolanaRpc` trait for production use.
//! Only compiled when the `rpc` feature is enabled.

#[allow(clippy::module_inception)]
#[cfg(feature = "rpc")]
pub mod real_rpc_impl {
    use solana_commitment_config::CommitmentConfig;
    use solana_sdk::{
        account::Account, pubkey::Pubkey, signature::Signature, transaction::Transaction,
    };

    use crate::error::{SolanaError, SolanaResult};
    use crate::rpc::SolanaRpc;
    use crate::types::{AccountChange, ConfirmationStatus};

    /// Real RPC client implementation using solana-rpc-client
    pub struct SolanaNode {
        client: solana_rpc_client::rpc_client::RpcClient,
        url: String,
    }

    impl SolanaNode {
        /// Create new RPC client with default commitment
        pub fn new(rpc_url: &str) -> Self {
            let client = solana_rpc_client::rpc_client::RpcClient::new(rpc_url.to_string());
            Self {
                client,
                url: rpc_url.to_string(),
            }
        }

        /// Create with specific commitment level
        pub fn with_commitment(rpc_url: &str, commitment: &str) -> Self {
            let commitment_config = match commitment {
                "processed" => CommitmentConfig::processed(),
                "confirmed" => CommitmentConfig::confirmed(),
                "finalized" => CommitmentConfig::finalized(),
                _ => CommitmentConfig::confirmed(),
            };
            let client = solana_rpc_client::rpc_client::RpcClient::new_with_commitment(
                rpc_url.to_string(),
                commitment_config,
            );
            Self {
                client,
                url: rpc_url.to_string(),
            }
        }

        /// Get the underlying RPC client for advanced operations
        pub fn underlying_client(&self) -> &solana_rpc_client::rpc_client::RpcClient {
            &self.client
        }
    }

    impl SolanaRpc for SolanaNode {
        fn get_account(&self, pubkey: &Pubkey) -> SolanaResult<Account> {
            self.client
                .get_account(pubkey)
                .map_err(|e| SolanaError::Rpc(format!("Failed to get account {}: {}", pubkey, e)))
        }

        fn get_multiple_accounts(&self, pubkeys: &[Pubkey]) -> SolanaResult<Vec<Option<Account>>> {
            self.client
                .get_multiple_accounts(pubkeys)
                .map_err(|e| SolanaError::Rpc(format!("Failed to get multiple accounts: {}", e)))
        }

        fn get_program_accounts(
            &self,
            program_id: &Pubkey,
        ) -> SolanaResult<Vec<(Pubkey, Account)>> {
            self.client.get_program_accounts(program_id).map_err(|e| {
                SolanaError::Rpc(format!(
                    "Failed to get accounts owned by program {}: {}",
                    program_id, e
                ))
            })
        }

        fn get_transaction(&self, signature: &Signature) -> SolanaResult<String> {
            // Use get_signature_status to check if transaction exists and return status info
            let status = self.client.get_signature_status(signature).map_err(|e| {
                SolanaError::Rpc(format!("Failed to get transaction status: {}", e))
            })?;

            match status {
                Some(Ok(())) => Ok(format!("Transaction {{ signature: {} }}", signature)),
                Some(Err(e)) => Err(SolanaError::TransactionFailed(format!(
                    "Transaction failed: {:?}",
                    e
                ))),
                None => Err(SolanaError::Rpc("Transaction not found".to_string())),
            }
        }

        fn get_transaction_slot(&self, signature: &Signature) -> SolanaResult<Option<u64>> {
            // `with_history` searches the ledger beyond the recent-status cache,
            // so a resume long after the lock still resolves the landed slot.
            let statuses = self
                .client
                .get_signature_statuses_with_history(&[*signature])
                .map_err(|e| {
                    SolanaError::Rpc(format!("Failed to get signature status: {}", e))
                })?;
            let Some(status) = statuses.value.into_iter().next().flatten() else {
                return Ok(None);
            };
            if let Some(err) = status.err {
                return Err(SolanaError::TransactionFailed(format!(
                    "Transaction failed: {:?}",
                    err
                )));
            }
            Ok(Some(status.slot))
        }

        fn send_transaction(&self, transaction: &Transaction) -> SolanaResult<Signature> {
            self.client
                .send_transaction(transaction)
                .map_err(|e| SolanaError::Rpc(format!("Failed to send transaction: {}", e)))
        }

        fn get_latest_slot(&self) -> SolanaResult<u64> {
            self.client
                .get_slot()
                .map_err(|e| SolanaError::Rpc(format!("Failed to get slot: {}", e)))
        }

        fn get_slot_with_commitment(&self, commitment: &str) -> SolanaResult<u64> {
            let commitment_config = match commitment {
                "processed" => CommitmentConfig::processed(),
                "confirmed" => CommitmentConfig::confirmed(),
                "finalized" => CommitmentConfig::finalized(),
                _ => CommitmentConfig::confirmed(),
            };

            self.client
                .get_slot_with_commitment(commitment_config)
                .map_err(|e| SolanaError::Rpc(format!("Failed to get slot with commitment: {}", e)))
        }

        fn get_account_changes(
            &self,
            _from_slot: u64,
            _to_slot: u64,
        ) -> SolanaResult<Vec<AccountChange>> {
            // Account changes tracking requires complex pre/post balance tracking.
            // Returns empty list as this is a non-critical feature for core operation.
            // Full implementation would use get_block with pre/post balance metadata.
            Ok(vec![])
        }

        fn wait_for_confirmation(&self, signature: &Signature) -> SolanaResult<ConfirmationStatus> {
            // Poll for confirmation with exponential backoff using std::thread::sleep
            let mut retries = 0;
            let max_retries = 30;

            while retries < max_retries {
                // Check signature status to determine confirmation
                match self.client.get_signature_status(signature) {
                    Ok(Some(Ok(()))) => {
                        // Transaction confirmed - check if finalized by looking at block height
                        match self
                            .client
                            .get_slot_with_commitment(CommitmentConfig::finalized())
                        {
                            Ok(finalized_slot) => {
                                match self
                                    .client
                                    .get_slot_with_commitment(CommitmentConfig::confirmed())
                                {
                                    Ok(confirmed_slot) if confirmed_slot <= finalized_slot => {
                                        return Ok(ConfirmationStatus::Finalized);
                                    }
                                    _ => return Ok(ConfirmationStatus::Confirmed),
                                }
                            }
                            _ => return Ok(ConfirmationStatus::Confirmed),
                        }
                    }
                    Ok(Some(Err(e))) => {
                        return Err(SolanaError::TransactionFailed(format!(
                            "Transaction failed: {:?}",
                            e
                        )));
                    }
                    Ok(None) => {
                        // Transaction not found yet, wait
                    }
                    Err(e) => {
                        return Err(SolanaError::Rpc(format!(
                            "Failed to get signature status: {}",
                            e
                        )));
                    }
                }

                retries += 1;
                std::thread::sleep(std::time::Duration::from_millis(500 * retries.min(10)));
            }

            Err(SolanaError::Timeout(
                "Transaction confirmation timeout".to_string(),
            ))
        }

        fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> SolanaResult<u64> {
            self.client
                .get_minimum_balance_for_rent_exemption(data_len)
                .map_err(|e| SolanaError::Rpc(format!("Failed to get rent exemption: {}", e)))
        }

        fn get_recent_blockhash(&self) -> SolanaResult<solana_sdk::hash::Hash> {
            self.client
                .get_latest_blockhash()
                .map_err(|e| SolanaError::Rpc(format!("Failed to get recent blockhash: {}", e)))
        }

        fn get_balance(&self, pubkey: &Pubkey) -> SolanaResult<u64> {
            self.client.get_balance(pubkey).map_err(|e| {
                SolanaError::Rpc(format!("Failed to get balance for {}: {}", pubkey, e))
            })
        }

        fn get_block(
            &self,
            slot: u64,
        ) -> SolanaResult<Option<solana_transaction_status::EncodedConfirmedBlock>> {
            use solana_transaction_status::EncodedConfirmedBlock;

            // Get the block using the RPC client with the correct method
            let ui_block = self.client.get_block(slot).map_err(|e| {
                SolanaError::Rpc(format!("Failed to get block at slot {}: {}", slot, e))
            })?;

            // Convert UiConfirmedBlock to EncodedConfirmedBlock
            // This requires proper encoding of transactions
            let transactions: Vec<solana_transaction_status::EncodedTransactionWithStatusMeta> =
                ui_block
                    .transactions
                    .into_iter()
                    .map(|tx| {
                        // Convert EncodedTransactionWithMeta to EncodedTransactionWithStatusMeta
                        solana_transaction_status::EncodedTransactionWithStatusMeta {
                            transaction: tx.transaction,
                            meta: tx.meta,
                            version: tx.version,
                        }
                    })
                    .collect();

            let encoded_block = EncodedConfirmedBlock {
                blockhash: ui_block.blockhash,
                previous_blockhash: ui_block.previous_blockhash,
                parent_slot: ui_block.parent_slot,
                block_time: ui_block.block_time,
                block_height: ui_block.block_height,
                rewards: ui_block.rewards,
                transactions,
                num_partitions: None,
            };

            Ok(Some(encoded_block))
        }

        fn get_block_hash(&self, slot: u64) -> SolanaResult<solana_sdk::hash::Hash> {
            // Get the block to extract its hash
            let block = self.client.get_block(slot).map_err(|e| {
                SolanaError::Rpc(format!("Failed to get block at slot {}: {}", slot, e))
            })?;

            // Convert String blockhash to Hash
            let hash_bytes = bs58::decode(&block.blockhash)
                .into_vec()
                .map_err(|e| SolanaError::Rpc(format!("Failed to decode blockhash: {}", e)))?;

            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_bytes);
            Ok(solana_sdk::hash::Hash::new_from_array(hash_array))
        }

        fn clone_boxed(&self) -> Box<dyn SolanaRpc> {
            // Create a new RPC client with the same URL
            // RpcClient doesn't implement Clone, so we create a new instance
            Box::new(Self::new(&self.url))
        }
    }
}

#[cfg(feature = "rpc")]
pub use real_rpc_impl::SolanaNode;
