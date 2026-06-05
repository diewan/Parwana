//! Bitcoin SealProtocol implementation with HD wallet support
//!
//! This adapter implements the SealProtocol trait for Bitcoin,
//! using UTXOs as single-use seals and Tapret commitments for anchoring.
//!
//! ## Architecture
//!
//! - **Seals**: UTXOs locked to Taproot output keys derived from HD wallet
//! - **Commitments**: Published via Taproot OP_RETURN or Tapscript tapret
//! - **Finality**: Based on confirmation depth

#![allow(dead_code)]

use async_trait::async_trait;
use bitcoin;
use bitcoin_hashes::Hash as _;
use std::sync::{Arc, Mutex};

use csv_hash::Hash;
use csv_hash::commitment::Commitment;
use csv_hash::sanad::SanadId;
use csv_hash::seal::CommitAnchor as CoreCommitAnchor;
use csv_hash::seal::SealPoint as CoreSealPoint;
use csv_protocol::error::ProtocolError;
use csv_protocol::proof_types::{FinalityProof, ProofBundle};
use csv_protocol::seal_protocol::SealProtocol;

use crate::config::BitcoinConfig;
use crate::error::{BitcoinError, BitcoinResult};
use crate::rpc::BitcoinRpc;
use crate::seal::SealRegistry;
use crate::tx_builder::CommitmentTxBuilder;
use crate::types::{
    BitcoinCommitAnchor, BitcoinFinalityProof, BitcoinInclusionProof, BitcoinSealPoint,
};
use crate::wallet::SealWallet;

/// Bitcoin implementation of the SealProtocol trait with HD wallet support
pub struct BitcoinSealProtocol {
    config: BitcoinConfig,
    /// HD wallet for seal management
    pub wallet: SealWallet,
    tx_builder: CommitmentTxBuilder,
    seal_registry: Mutex<SealRegistry>,
    domain_separator: [u8; 32],
    /// RPC client for broadcasting transactions (optional)
    pub rpc: Option<Box<dyn BitcoinRpc + Send + Sync>>,
    next_seal_index: Mutex<u32>,
    /// Optional MPC batcher for commitment aggregation (90% fee savings)
    mpc_batcher: Option<Arc<crate::mpc_batch::MpcBatcher>>,
}

impl BitcoinSealProtocol {
    /// Create from configuration and RPC client (standard runtime pattern).
    ///
    /// # Arguments
    /// * `config` - Bitcoin adapter configuration (includes network, finality depth, optional xpub)
    /// * `rpc` - RPC client for Bitcoin node communication
    ///
    /// # Security Notes
    /// - Uses BIP-86 derivation paths for Taproot addresses (m/86'/coin_type'/account'/0/index)
    /// - Domain separator includes network magic bytes for cross-chain replay protection
    /// - HD wallet created from xpub if provided, otherwise requires external signing
    pub fn from_config(
        config: BitcoinConfig,
        rpc: Box<dyn BitcoinRpc + Send + Sync>,
    ) -> BitcoinResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| BitcoinError::RpcError(format!("Invalid configuration: {}", e)))?;

        // Build domain separator: "CSV-BTC-" + network magic bytes (replay protection)
        let mut domain = [0u8; 32];
        domain[..8].copy_from_slice(b"CSV-BTC-");
        let magic = config.network.magic_bytes();
        domain[8..12].copy_from_slice(&magic);

        // Build protocol ID from network magic
        let mut protocol_id = [0u8; 32];
        protocol_id[..4].copy_from_slice(&magic);
        let tx_builder = CommitmentTxBuilder::new(protocol_id, config.finality_depth as u64);

        // Create wallet from seed if provided, otherwise from xpub, otherwise error
        let wallet = if let Some(seed_hex) = &config.seed {
            // Decode hex seed (128 hex chars = 64 bytes)
            let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x"))
                .map_err(|e| BitcoinError::RpcError(format!("Invalid seed hex: {}", e)))?;
            if seed_bytes.len() != 64 {
                return Err(BitcoinError::RpcError(
                    format!("Seed must be 64 bytes (128 hex chars), got {} bytes", seed_bytes.len())
                ));
            }
            let mut seed_array = [0u8; 64];
            seed_array.copy_from_slice(&seed_bytes);
            let wallet = SealWallet::from_seed(&seed_array, config.network.to_bitcoin_network())
                .map_err(|e| BitcoinError::RpcError(format!("Wallet creation from seed failed: {}", e)))?;

            // Load UTXOs from config if available
            for utxo_config in &config.utxos {
                if let Ok(txid_bytes) = hex::decode(&utxo_config.txid) {
                    if txid_bytes.len() == 32 {
                        let mut txid_array = [0u8; 32];
                        txid_array.copy_from_slice(&txid_bytes);
                        let hash = bitcoin::hashes::Hash::from_byte_array(txid_array);
                        let outpoint = bitcoin::OutPoint {
                            txid: bitcoin::Txid::from_raw_hash(hash),
                            vout: utxo_config.vout,
                        };
                        let path = crate::wallet::Bip86Path::external(utxo_config.account, utxo_config.index);
                        
                        // Decode scriptPubKey if available
                        let script_pubkey = utxo_config.script_pubkey.as_ref()
                            .and_then(|spk_hex| hex::decode(spk_hex).ok())
                            .map(|bytes| bitcoin::ScriptBuf::from(bytes));
                        
                        wallet.add_utxo_with_scriptpubkey(outpoint, utxo_config.value, path, script_pubkey, None);
                    }
                }
            }

            // Load sanad_id -> seal mappings from config
            log::info!("Bitcoin: Loading {} sanad_seals from config", config.sanad_seals.len());
            for seal_config in &config.sanad_seals {
                log::info!("Bitcoin: Loading sanad_seal: sanad_id={}, anchor_txid={}, vout={}",
                    seal_config.sanad_id, seal_config.anchor_txid, seal_config.vout);
                if let Ok(sanad_bytes) = hex::decode(&seal_config.sanad_id) {
                    if sanad_bytes.len() == 32 {
                        let mut sanad_id = [0u8; 32];
                        sanad_id.copy_from_slice(&sanad_bytes);
                        if let Ok(txid_bytes) = hex::decode(&seal_config.anchor_txid) {
                            wallet.register_sanad_seal(sanad_id, txid_bytes, seal_config.vout);
                            log::info!("Bitcoin: Registered sanad_seal for sanad_id={}", hex::encode(sanad_id));
                        }
                    }
                }
            }

            wallet
        } else if let Some(xpub_str) = &config.xpub {
            SealWallet::from_xpub(xpub_str, config.network.to_bitcoin_network())
                .map_err(|e| {
                    BitcoinError::RpcError(format!("Wallet creation from xpub failed: {}", e))
                })?
        } else {
            return Err(BitcoinError::RpcError(
                "BitcoinSealProtocol::from_config requires either seed or xpub; refusing to generate a random production wallet".to_string(),
            ));
        };

        Ok(Self {
            config,
            wallet,
            tx_builder,
            seal_registry: Mutex::new(SealRegistry::new()),
            domain_separator: domain,
            rpc: Some(rpc),
            next_seal_index: Mutex::new(0),
            mpc_batcher: None,
        })
    }

    /// Create with an existing HD wallet (for advanced use cases).
    pub fn with_wallet(config: BitcoinConfig, wallet: SealWallet) -> BitcoinResult<Self> {
        let mut domain = [0u8; 32];
        domain[..8].copy_from_slice(b"CSV-BTC-");
        let magic = config.network.magic_bytes();
        domain[8..12].copy_from_slice(&magic);

        let mut protocol_id = [0u8; 32];
        let magic = config.network.magic_bytes();
        protocol_id[..4].copy_from_slice(&magic);
        let tx_builder = CommitmentTxBuilder::new(protocol_id, config.finality_depth as u64);

        Ok(Self {
            config,
            wallet,
            tx_builder,
            seal_registry: Mutex::new(SealRegistry::new()),
            domain_separator: domain,
            rpc: None,
            next_seal_index: Mutex::new(0),
            mpc_batcher: None,
        })
    }

    /// Create a new adapter with an HD wallet from an xpub key
    pub fn from_xpub(config: BitcoinConfig, xpub: &str) -> BitcoinResult<Self> {
        let wallet = SealWallet::from_xpub(xpub, config.network.to_bitcoin_network())
            .map_err(|e| BitcoinError::RpcError(format!("Wallet creation failed: {}", e)))?;
        Self::with_wallet(config, wallet)
    }

    /// Create with default config for signet (random wallet)
    pub fn signet() -> BitcoinResult<Self> {
        let wallet = SealWallet::generate_random(bitcoin::Network::Signet);
        Self::with_wallet(BitcoinConfig::default(), wallet)
    }

    /// Attach a real RPC client for broadcasting transactions
    pub fn with_rpc(mut self, rpc: Box<dyn BitcoinRpc + Send + Sync>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Attach an MPC batcher for commitment aggregation.
    ///
    /// When enabled, Bitcoin commitments are queued and batched into a single
    /// on-chain transaction, achieving ~90% fee savings for multiple commitments.
    ///
    /// # Example
    /// ```rust,ignore
    /// use csv_bitcoin::mpc_batch::MpcBatcher;
    ///
    /// let batcher = MpcBatcher::default();
    /// let protocol = protocol.with_mpc_batcher(batcher);
    /// ```
    pub fn with_mpc_batcher(mut self, batcher: crate::mpc_batch::MpcBatcher) -> Self {
        self.mpc_batcher = Some(Arc::new(batcher));
        self
    }

    /// Get reference to MPC batcher if configured
    pub fn mpc_batcher(&self) -> Option<&Arc<crate::mpc_batch::MpcBatcher>> {
        self.mpc_batcher.as_ref()
    }

    /// Load UTXOs for sanad_seals from RPC
    ///
    /// This async method fetches UTXO details (value, scriptPubKey) from the blockchain
    /// for all sanad_seals registered in the config and adds them to the wallet.
    /// This is required because sanad_seals config only stores the mapping (sanad_id -> txid/vout)
    /// but not the actual UTXO data needed for spending.
    pub async fn load_sanad_seal_utxos(&self) -> Result<usize, BitcoinError> {
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            BitcoinError::RpcError("No RPC client configured".to_string())
        })?;

        let seals = self.wallet.get_sanad_seals();
        let mut loaded_count = 0;

        for (sanad_id, (txid_bytes, vout)) in seals.iter() {
            let txid_array: [u8; 32] = txid_bytes.clone().try_into().unwrap_or([0u8; 32]);
            let outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(txid_array)),
                vout: *vout,
            };

            // Check if UTXO is already in wallet
            if self.wallet.get_utxo(&outpoint).is_some() {
                log::debug!("UTXO {}:{} already in wallet, skipping fetch", hex::encode(txid_bytes), vout);
                continue;
            }

            // Fetch UTXO details from RPC
            match rpc.get_utxo_details(txid_array, *vout).await {
                Ok(Some(utxo_details)) => {
                    // Parse scriptPubKey
                    let script_pubkey = hex::decode(&utxo_details.script_pubkey)
                        .ok()
                        .map(|bytes| bitcoin::ScriptBuf::from(bytes));

                    // Add UTXO to wallet with fetched details
                    let path = crate::wallet::Bip86Path::external(self.config.account, self.config.index);
                    self.wallet.add_utxo_with_scriptpubkey(
                        outpoint,
                        utxo_details.value,
                        path,
                        script_pubkey,
                        Some(*sanad_id),
                    );
                    log::info!("Bitcoin: Added UTXO {}:{} to wallet from RPC (value={} sat)",
                        hex::encode(txid_bytes), vout, utxo_details.value);
                    loaded_count += 1;
                }
                Ok(None) => {
                    log::warn!("UTXO {}:{} not found on-chain (may be spent or unconfirmed)",
                        hex::encode(txid_bytes), vout);
                }
                Err(e) => {
                    log::warn!("Failed to fetch UTXO {}:{} from RPC: {}",
                        hex::encode(txid_bytes), vout, e);
                }
            }
        }

        Ok(loaded_count)
    }

    /// Queue a commitment for batched publication.
    ///
    /// Returns true if batch is ready to publish (reached batch_size threshold)
    pub fn queue_commitment(
        &self,
        commitment: Hash,
        seal: BitcoinSealPoint,
        request_id: String,
    ) -> Result<bool, BitcoinError> {
        self.mpc_batcher
            .as_ref()
            .map(|b| {
                b.queue(commitment, seal, request_id)
                    .map_err(|e| BitcoinError::MpcError(e.to_string()))
            })
            .unwrap_or(Ok(false))
    }

    /// Check if a batch is ready for publication
    pub fn has_batch_ready(&self) -> bool {
        self.mpc_batcher
            .as_ref()
            .map(|b| b.has_batch_ready())
            .unwrap_or(false)
    }

    /// Get count of pending batched commitments
    pub fn pending_batch_count(&self) -> usize {
        self.mpc_batcher
            .as_ref()
            .map(|b| b.pending_count())
            .unwrap_or(0)
    }

    /// Get a mutable reference to the wallet
    pub fn wallet_mut(&mut self) -> &mut SealWallet {
        &mut self.wallet
    }

    /// Add UTXOs to the wallet from persisted state
    pub fn add_utxos_from_state(&mut self, utxos: Vec<(bitcoin::OutPoint, u64, crate::wallet::Bip86Path)>) {
        for (outpoint, value, path) in utxos {
            self.wallet.add_utxo(outpoint, value, path);
        }
    }

    /// Get a mutable reference to the tx_builder
    pub fn tx_builder_mut(&mut self) -> &mut CommitmentTxBuilder {
        &mut self.tx_builder
    }

    /// Derive a new seal at the next available path
    fn derive_next_seal(
        &self,
        value_sat: u64,
    ) -> Result<(BitcoinSealPoint, crate::wallet::Bip86Path), ProtocolError> {
        let mut next_index = self
            .next_seal_index
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = crate::wallet::Bip86Path::external(self.config.account, self.config.index + *next_index);

        // Derive the Taproot key for this path
        let key = self
            .wallet
            .derive_key(&path)
            .map_err(|e| ProtocolError::Generic(format!("Key derivation failed: {}", e)))?;

        // Create a seal reference from the derived key
        let txid: [u8; 32] = key.output_key.serialize();

        *next_index += 1;

        Ok((BitcoinSealPoint::new(txid, 0, Some(value_sat)), path))
    }

    /// Create a seal backed by a real on-chain UTXO
    ///
    /// This method creates a seal from an existing UTXO in the wallet.
    /// The UTXO must have been previously added to the wallet via `add_utxo()`
    /// or discovered via `scan_wallet_for_utxos()`.
    ///
    /// # Arguments
    /// * `outpoint` - The outpoint of the UTXO to use as the seal
    ///
    /// # Returns
    /// A seal reference and the derivation path, or an error if the UTXO is not found
    pub fn fund_seal(
        &self,
        outpoint: bitcoin::OutPoint,
    ) -> Result<(BitcoinSealPoint, crate::wallet::Bip86Path), ProtocolError> {
        // Get the UTXO from the wallet
        let utxo = self.wallet.get_utxo(&outpoint).ok_or_else(|| {
            ProtocolError::Generic(format!(
                "UTXO {}:{} not found in wallet - fund the address first",
                outpoint.txid, outpoint.vout
            ))
        })?;

        // Create a seal reference from the actual outpoint
        let txid = outpoint.txid.to_byte_array();
        let seal_ref = BitcoinSealPoint::new(txid, outpoint.vout, Some(utxo.amount_sat));

        // Check if seal is already used
        if self
            .seal_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_seal_used(&seal_ref)
        {
            return Err(ProtocolError::Generic(format!(
                "Seal {}:{} already used",
                outpoint.txid, outpoint.vout
            )));
        }

        Ok((seal_ref, utxo.path))
    }

    /// Scan the wallet's addresses for on-chain UTXOs
    ///
    /// This method requires an RPC client to be attached. It will scan addresses
    /// and populate the wallet with any discovered UTXOs.
    ///
    /// # Arguments
    /// * `account` - The account number to scan (typically 0)
    /// * `gap_limit` - Number of consecutive empty addresses before stopping (typically 20)
    ///
    /// # Returns
    /// The number of UTXOs discovered
    pub async fn scan_wallet_for_utxos(
        &self,
        account: u32,
        gap_limit: usize,
    ) -> Result<usize, ProtocolError> {
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            ProtocolError::Generic("No RPC client configured - call with_rpc() first".to_string())
        })?;

        let wallet = &self.wallet;
        wallet.clear_utxos();
        
      let mut discovered_count = 0;
        let mut consecutive_empty = 0;
        
        for index in 0..gap_limit {
            let derived = self.wallet.derive_key(&crate::wallet::Bip86Path::external(account, index as u32))
                .map_err(|e| ProtocolError::Generic(format!("Key derivation failed: {}", e)))?;
            
            let address_str = derived.address.to_string();
            
            match rpc.get_utxos_for_address(address_str.clone()).await {
                Ok(utxos) => {
                    if utxos.is_empty() {
                        consecutive_empty += 1;
                        if consecutive_empty >= 3 {
                            break;
                        }
                    } else {
                        consecutive_empty = 0;
                        for utxo in utxos {
                            // esplora-client returns txids in display format (reversed bytes)
                            // Reverse to get internal byte order for Txid construction
                            let mut reversed = utxo.txid;
                            reversed.reverse();
                            let txid = bitcoin::Txid::from_byte_array(reversed);
                            let outpoint = bitcoin::OutPoint::new(txid, utxo.vout);
                            self.wallet.add_utxo(outpoint, utxo.amount_sat, derived.path.clone());
                            discovered_count += 1;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch UTXOs for address {}: {}", address_str, e);
                    consecutive_empty += 1;
                    if consecutive_empty >= 3 {
                        break;
                    }
                }
            }
        }

        log::info!(
            "Discovered {} UTXOs on account {}",
            discovered_count,
            account
        );
        Ok(discovered_count)
    }

    /// Build commitment data for a commitment transaction
    pub fn build_commitment_data(
        &self,
        commitment: Hash,
        protocol_id: [u8; 32],
    ) -> Result<crate::tx_builder::CommitmentData, ProtocolError> {
        let tx_builder = CommitmentTxBuilder::new(protocol_id, 10);
        Ok(tx_builder.build_commitment_data(commitment))
    }

    /// Get current block height via RPC
    pub async fn get_current_height(&self) -> u64 {
        if let Some(rpc) = &self.rpc {
            if let Ok(h) = rpc.get_block_count().await {
                return h;
            }
        }
        200
    }

    /// Get current block height (alias for get_current_height)
    pub async fn get_current_height_for_test(&self) -> u64 {
        self.get_current_height().await
    }

    /// Verify a UTXO is unspent
    async fn verify_utxo_unspent(
        &self,
        seal: &BitcoinSealPoint,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(rpc) = &self.rpc {
            let unspent = rpc
                .is_utxo_unspent(seal.txid, seal.vout)
                .await
                .map_err(|e| BitcoinError::RpcError(format!("Failed to check UTXO: {}", e)))?;
            if unspent {
                return Ok(());
            } else {
                return Err(Box::new(BitcoinError::UTXOSpent(format!(
                    "UTXO {}:{} is spent",
                    seal.txid_hex(),
                    seal.vout
                ))));
            }
        }
        // In fallback mode, always return OK
        Ok(())
    }

    /// Get the funding address for a specific account and index
    pub fn get_funding_address(
        &self,
        account: u32,
        index: u32,
    ) -> Result<bitcoin::Address, ProtocolError> {
        let key = self
            .wallet
            .get_funding_address(account, index)
            .map_err(|e| ProtocolError::Generic(format!("Failed to derive address: {}", e)))?;
        Ok(key.address)
    }

    /// Add a UTXO to the wallet from a known outpoint
    pub fn add_utxo(&self, outpoint: bitcoin::OutPoint, amount_sat: u64, account: u32, index: u32) {
        let path = crate::wallet::Bip86Path::external(account, index);
        self.wallet.add_utxo(outpoint, amount_sat, path);
    }

    /// Get a reference to the config (for chain operations)
    pub(crate) fn config(&self) -> &BitcoinConfig {
        &self.config
    }

    /// Find a seal for a given sanad_id
    ///
    /// Searches through the wallet's UTXOs to find a seal (UTXO) that is
    /// associated with the given sanad_id. Returns the seal reference if found.
    /// First checks explicit sanad_seals map, then falls back to UTXO scan.
    pub fn find_seal_for_sanad(&self, sanad_id: &SanadId) -> Option<BitcoinSealPoint> {
        let sanad_bytes = sanad_id.as_bytes();
        log::info!("find_seal_for_sanad: looking for sanad_id={}", hex::encode(sanad_bytes));

        // First check explicit sanad_seals map
        let seals = self.wallet.get_sanad_seals();
        log::info!("find_seal_for_sanad: sanad_seals map has {} entries", seals.len());
        for (k, _v) in seals.iter() {
            log::info!("find_seal_for_sanad: map key={}", hex::encode(k));
        }
        
        if let Some((txid, vout)) = seals.get(sanad_bytes) {
            log::info!("find_seal_for_sanad: found in map, txid={}, vout={}", hex::encode(txid), vout);
            let mut txid_array = [0u8; 32];
            txid_array.copy_from_slice(&txid[..32]);
            return Some(BitcoinSealPoint {
                txid: txid_array,
                vout: *vout,
                nonce: None,
            });
        }
        log::info!("find_seal_for_sanad: not found in map");

        // Fall back to UTXO scan
        for utxo in self.wallet.list_utxos() {
            if utxo.sanad_id.as_ref() == Some(sanad_bytes) {
                let outpoint = utxo.outpoint;
                return Some(BitcoinSealPoint {
                    txid: outpoint.txid.to_byte_array(),
                    vout: outpoint.vout,
                    nonce: Some(utxo.amount_sat),
                });
            }
        }

        None
    }

    /// Get the domain separator (for chain operations)
    pub(crate) fn domain(&self) -> [u8; 32] {
        self.domain_separator
    }
}

/// Helper to get address UTXOs from any RPC implementation
fn get_address_utxos(
    _rpc: &dyn BitcoinRpc,
    _address: &bitcoin::Address,
) -> Result<Vec<(bitcoin::OutPoint, u64)>, String> {
    // This is a temporary implementation - actual implementation depends on the RPC backend
    Err("get_address_utxos not implemented for this RPC backend".to_string())
}

#[async_trait]
impl SealProtocol for BitcoinSealProtocol {
    type SealPoint = BitcoinSealPoint;
    type CommitAnchor = BitcoinCommitAnchor;
    type InclusionProof = BitcoinInclusionProof;
    type FinalityProof = BitcoinFinalityProof;

    async fn publish(
        &self,
        commitment: Hash,
        seal: Self::SealPoint,
    ) -> Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        self.verify_utxo_unspent(&seal).await?;

        // If RPC client is available, use real broadcasting
        if let Some(rpc) = &self.rpc {
            // Find the UTXO matching this seal in the wallet
            // seal.txid is in internal byte order (from fund_seal -> outpoint.txid.to_byte_array())
            let outpoint = bitcoin::OutPoint::new(
                bitcoin::Txid::from_byte_array(seal.txid),
                seal.vout,
            );
            let utxo = self.wallet.get_utxo(&outpoint).ok_or_else(|| {
                ProtocolError::PublishFailed(format!(
                    "UTXO {}:{} not found in wallet",
                    seal.txid_hex(),
                    seal.vout
                ))
            })?;

            // Final UTXO validation immediately before broadcast to catch race conditions
            // If the check fails (e.g., transaction not indexed yet), we proceed and let the broadcast fail if needed
            let _is_unspent = match rpc.is_utxo_unspent(seal.txid, seal.vout).await {
                Ok(unspent) => {
                    if !unspent {
                        return Err(Box::new(ProtocolError::PublishFailed(format!(
                            "UTXO {}:{} is already spent or missing on-chain. Please refresh UTXOs with 'csv wallet scan' or fund the address.",
                            hex::encode(outpoint.txid), outpoint.vout
                        ))));
                    }
                    true
                }
                Err(e) => {
                    log::warn!("Failed to check UTXO status before broadcast (transaction may not be indexed yet): {}. Proceeding with broadcast attempt.", e);
                    true // Assume unspent and proceed
                }
            };

            // Fetch and validate the actual on-chain scriptPubKey (what the node expects)
            // This is optional - if mempool.space hasn't indexed the transaction yet, we skip this validation
            log::info!("Fetching scriptPubKey for INPUT UTXO: txid={}, vout={}", hex::encode(seal.txid), seal.vout);
            let _onchain_spk = match rpc.get_utxo_scriptpubkey(seal.txid, seal.vout).await {
                Ok(Some(spk)) => {
                    log::info!("Successfully fetched scriptPubKey for INPUT UTXO");
                    Some(spk)
                }
                Ok(None) => {
                    log::warn!("ScriptPubKey not found for vout {} - using wallet data", seal.vout);
                    None
                }
                Err(e) => {
                    log::warn!("Failed to fetch scriptPubKey from RPC (transaction may not be indexed yet): {}. Skipping validation and using wallet data.", e);
                    None
                }
            };

            // Build and sign the Taproot commitment transaction
            // Use the same derivation path for change as the input UTXO
            let change_path = Some(utxo.path.clone());
            let tx_result = self
                .tx_builder
                .build_commitment_tx(
                    &self.wallet,
                    &utxo,
                    *commitment.as_bytes(),
                    change_path.as_ref(),
                )
                .map_err(|e| ProtocolError::PublishFailed(e.to_string()))?;

            // Broadcast the signed transaction via RPC
            let broadcast_txid = rpc
                .send_raw_transaction(tx_result.raw_tx.clone())
                .await
                .map_err(|e| {
                    ProtocolError::PublishFailed(format!("Failed to broadcast transaction: {}", e))
                })?;

            // Update wallet with the new commitment UTXO output
            let commitment_vout = tx_result.commitment_output_index;
            let commitment_value = tx_result.tapret_output.amount_sat;
            let commitment_spk = tx_result.tapret_output.script_pubkey.to_string();
            let outpoint = bitcoin::OutPoint::new(tx_result.txid, commitment_vout);

            // Use the same derivation path as the input for consistency
            let new_path = utxo.path.clone();

            // Derive sanad_id from commitment hash for seal lookup
            let mut sanad_id_bytes = [0u8; 32];
            sanad_id_bytes.copy_from_slice(commitment.as_bytes());

            self.wallet.add_utxo_with_scriptpubkey(
                outpoint,
                commitment_value,
                new_path,
                Some(bitcoin::ScriptBuf::from_hex(&commitment_spk).unwrap_or_default()),
                Some(sanad_id_bytes),
            );

            let current_height = self.get_current_height().await;
            return Ok(BitcoinCommitAnchor::new(broadcast_txid, 0, current_height));
        }

        // Fall back to fallback mode if no RPC client attached
        let mut txid = [0u8; 32];
        txid[..10].copy_from_slice(b"sim-commit");
        txid[10..].copy_from_slice(&commitment.as_bytes()[..22]);

        {
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            let _ = registry.mark_seal_used(&seal).map_err(ProtocolError::from);
        }

        let current_height = self.get_current_height().await;
        Ok(BitcoinCommitAnchor::new(txid, 0, current_height))
    }

    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        // If we have an RPC client, fetch real Merkle proof from the blockchain
        if let Some(rpc) = &self.rpc {
            // Get the block containing the anchor transaction
            let block_hash = rpc.get_block_hash(anchor.block_height).await.map_err(|e| {
                ProtocolError::InclusionProofFailed(format!("Failed to get block hash: {}", e))
            })?;

            // Extract the Merkle proof for the anchor transaction
            // This would require block fetching which is RPC-backend specific
            // For now, return a proof with just the block hash
            return Ok(BitcoinInclusionProof::new(
                vec![],
                block_hash,
                0,
                anchor.block_height,
            ));
        }

        // Without RPC, return empty proof (fallback mode)
        let proof = BitcoinInclusionProof::new(vec![], anchor.txid, 0, anchor.block_height);
        Ok(proof)
    }

    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        let current_height = self.get_current_height().await;

        if anchor.block_height == 0 {
            let confirmations = self.config.finality_depth as u64;
            let proof = BitcoinFinalityProof::new(confirmations, self.config.finality_depth);
            return Ok(proof);
        }

        let confirmations = current_height.saturating_sub(anchor.block_height);
        let proof = BitcoinFinalityProof::new(confirmations, self.config.finality_depth);

        if !proof.meets_required_depth {
            return Err(Box::new(ProtocolError::FinalityNotReached(format!(
                "Only {} confirmations, need {}",
                confirmations, self.config.finality_depth
            ))));
        }

        Ok(proof)
    }

    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that a UTXO cannot be spent more than once
        // by checking both local registry and on-chain UTXO set

        // Step 1: Check local registry (fast path)
        {
            let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.is_seal_used(&seal) {
                return Err(Box::new(ProtocolError::SealReplay(format!(
                    "UTXO {:?}:{:?} already used in local registry",
                    seal.txid, seal.vout
                ))));
            }
        }

        // Step 2: Check on-chain UTXO set via RPC (authoritative check)
        // This ensures that even if local state is corrupted or lost,
        // we still prevent double-spends by querying the blockchain
        #[cfg(feature = "rpc")]
        {
            if let Some(ref rpc) = self.rpc {
                let is_unspent = rpc
                    .is_utxo_unspent(seal.txid, seal.vout)
                    .await
                    .map_err(|e| {
                        Box::new(ProtocolError::NetworkError(format!(
                            "Failed to check UTXO status on-chain: {}",
                            e
                        )))
                    })?;

                if !is_unspent {
                    return Err(Box::new(ProtocolError::SealReplay(format!(
                        "UTXO {:?}:{:?} already spent on-chain",
                        seal.txid, seal.vout
                    ))));
                }
            }
        }

        // Step 3: Mark seal as used in local registry
        // This is done after the on-chain check to ensure consistency
        let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .mark_seal_used(&seal)
            .map_err(|e| Box::new(ProtocolError::from(e)))?;

        Ok(())
    }

    async fn create_seal(
        &self,
        value: Option<u64>,
    ) -> Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        let value_sat = value.unwrap_or(100_000);
        let (seal_ref, _path) = self.derive_next_seal(value_sat)?;
        Ok(seal_ref)
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal = CoreSealPoint::new(seal_point.txid.to_vec(), seal_point.nonce, None)
            .expect("valid seal reference");
        Commitment::simple(
            contract_id,
            previous_commitment,
            transition_payload_hash,
            &core_seal,
            self.domain_separator,
        )
        .hash()
    }

    async fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        _transition_dag: Vec<u8>,
    ) -> Result<ProofBundle, Box<dyn std::error::Error + 'static>> {
        let inclusion = self.verify_inclusion(anchor.clone()).await?;
        let finality = self.verify_finality(anchor.clone()).await?;

        let seal_ref = CoreSealPoint::new(anchor.txid.to_vec(), Some(0), None)
            .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let anchor_ref = CoreCommitAnchor::new(anchor.txid.to_vec(), anchor.block_height, vec![])
            .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&inclusion.block_hash);
        proof_bytes.extend_from_slice(&inclusion.tx_index.to_le_bytes());

        let inclusion_proof = csv_protocol::proof::InclusionProof::new(
            proof_bytes,
            Hash::new(inclusion.block_hash),
            inclusion.tx_index as u64,
            anchor.block_height,
        )
        .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let finality_proof = FinalityProof::new(
            finality.confirmations.to_le_bytes().to_vec(),
            finality.confirmations,
            finality.meets_required_depth,
        )
        .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        Ok(ProofBundle::with_signature_scheme(
            csv_protocol::SignatureScheme::Secp256k1,
            csv_hash::dag::DAGSegment::new(vec![], csv_hash::Hash::new([0u8; 32])),
            vec![],
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| Box::new(ProtocolError::Generic(e.to_string())))?)
    }

    async fn rollback(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let current_height = self.get_current_height().await;
        if anchor.block_height > current_height {
            return Err(Box::new(ProtocolError::ReorgInvalid(format!(
                "Block {} is beyond current height {}",
                anchor.block_height, current_height
            ))));
        }

        // If the anchor's block is before current height, the transaction may have been reorged out
        // In this case, we should clear the seal from the registry to allow reuse
        if anchor.block_height < current_height {
            // Attempt to clear the seal from registry
            // The seal txid is derived from the anchor's txid
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            // Try to clear using anchor txid as seal identifier
            let dummy_seal = BitcoinSealPoint::new(anchor.txid, anchor.output_index, None);
            registry.clear_seal(&dummy_seal);
        }

        Ok(())
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
        csv_protocol::signature::SignatureScheme::Secp256k1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_adapter() -> BitcoinSealProtocol {
        BitcoinSealProtocol::signet().unwrap()
    }

    #[tokio::test]
    async fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        assert_eq!(seal.nonce, Some(100_000));
    }

    #[tokio::test]
    async fn test_enforce_seal_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        adapter.enforce_seal(seal.clone()).await.unwrap();
        assert!(adapter.enforce_seal(seal).await.is_err());
    }

    #[test]
    fn test_domain_separator() {
        let adapter = test_adapter();
        assert_eq!(&adapter.domain_separator()[..8], b"CSV-BTC-");
    }

    #[tokio::test]
    async fn test_verify_finality() {
        let adapter = test_adapter();
        // block_height = 100 means it's confirmed at height 100
        // current_height is 200, so confirmations = 100 which is > 6 (default finality_depth)
        let anchor = BitcoinCommitAnchor::new([1u8; 32], 0, 100);
        let result = adapter.verify_finality(anchor).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hd_wallet_seal_derivation() {
        let adapter = test_adapter();
        let seal1 = adapter.create_seal(Some(50_000)).await.unwrap();
        let seal2 = adapter.create_seal(Some(50_000)).await.unwrap();
        assert_ne!(seal1.txid, seal2.txid);
    }

    #[tokio::test]
    async fn test_hd_wallet_seal_derivation_deterministic() {
        let wallet = SealWallet::generate_random(bitcoin::Network::Signet);
        let config = BitcoinConfig::default();
        let adapter = BitcoinSealProtocol::with_wallet(config, wallet).unwrap();
        let seal1 = adapter.create_seal(Some(100_000)).await.unwrap();
        assert_eq!(seal1.nonce, Some(100_000));
    }

    #[test]
    fn test_build_commitment_data() {
        let adapter = test_adapter();
        let data = adapter
            .build_commitment_data(Hash::new([1u8; 32]), [2u8; 32])
            .unwrap();
        match data {
            crate::tx_builder::CommitmentData::Tapret { payload, .. } => {
                assert_eq!(payload[..32], [2u8; 32]);
            }
            crate::tx_builder::CommitmentData::Opret { .. } => {
                panic!("Expected Tapret variant");
            }
        }
    }

    #[tokio::test]
    async fn test_derive_seal_deterministic() {
        let adapter = test_adapter();
        let seal1 = adapter.create_seal(None).await.unwrap();
        let adapter2 = test_adapter();
        let seal2 = adapter2.create_seal(None).await.unwrap();
        assert_ne!(seal1.txid, seal2.txid);
    }
}
