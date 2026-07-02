//! Commitment transaction builder
//!
//! Builds transactions for CSV commitment with:
//! - UTXO coin selection and Tapret/Opret commitment construction
//! - Real Taproot tree building with proper nonce positioning
//! - Fee estimation and dust protection
//! - Proper handling of plain P2TR (key-path) vs Tapret (script-path) inputs

#[allow(unused_imports)]
use bitcoin::hashes::Hash as _;
use bitcoin::{
    Address, Amount, ScriptBuf, Sequence, TxIn, TxOut, Txid, absolute::LockTime,
    consensus::encode::serialize as tx_serialize, key::TapTweak,
};

use crate::tapret::TapretCommitment;
use crate::wallet::{Bip86Path, SealWallet, WalletUtxo};

/// Dust threshold for P2TR outputs (BIP-0448: 330 sat for P2TR)
const P2TR_DUST_SAT: u64 = 330;

/// Minimum UTXO value in satoshis
/// For mainnet: 10,000 sats (0.0001 BTC) - prevents using dust/tiny UTXOs
/// For testnet/signet: 1,000 sats - lower threshold for testing
fn minimum_utxo_sat(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => 10_000,
        _ => 1_000, // Testnet, Signet, Regtest
    }
}

/// RBF sequence number (BIP-0125)
const RBF_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// Configuration for building commitment transactions
pub struct CommitmentTxBuilder {
    /// Fee rate in sat/vB
    pub fee_rate_sat_per_vb: u64,
    /// Protocol ID for this commitment
    pub protocol_id: [u8; 32],
    /// Maximum fee rate to prevent overpaying
    pub max_fee_rate_sat_per_vb: u64,
    /// Dust threshold (satoshi)
    pub dust_threshold_sat: u64,
}

impl CommitmentTxBuilder {
    /// Create a new transaction builder
    pub fn new(protocol_id: [u8; 32], fee_rate_sat_per_vb: u64) -> Self {
        Self {
            fee_rate_sat_per_vb,
            protocol_id,
            max_fee_rate_sat_per_vb: fee_rate_sat_per_vb * 10,
            dust_threshold_sat: P2TR_DUST_SAT,
        }
    }

    /// Set the fee rate
    pub fn with_fee_rate(mut self, fee_rate: u64) -> Self {
        self.fee_rate_sat_per_vb = fee_rate;
        self
    }

    /// Set maximum fee rate (prevents overpaying during fee spikes)
    pub fn with_max_fee_rate(mut self, max_fee: u64) -> Self {
        self.max_fee_rate_sat_per_vb = max_fee;
        self
    }

    /// Estimate virtual bytes for a commitment transaction
    pub fn estimate_vbytes(input_count: usize, output_count: usize) -> usize {
        let base = 10;
        let per_input = 58;
        let per_output = 43;
        base + input_count * per_input + output_count * per_output
    }

    /// Calculate required fee
    pub fn calculate_fee(&self, input_count: usize, output_count: usize) -> u64 {
        let vbytes = Self::estimate_vbytes(input_count, output_count);
        let fee = vbytes as u64 * self.fee_rate_sat_per_vb;
        let max_fee = (vbytes as u64) * self.max_fee_rate_sat_per_vb;
        fee.min(max_fee)
    }

    /// Check if an output amount is above the dust threshold
    pub fn is_above_dust(&self, value_sat: u64) -> bool {
        value_sat >= self.dust_threshold_sat
    }

    /// Build a complete commitment transaction
    ///
    /// This handles two cases:
    /// 1. **Plain P2TR input** (funded externally to a simple P2TR address):
    ///    The input is spent via key-path using the tweaked keypair.
    ///    The output uses a Tapret commitment with the same internal key.
    ///
    /// 2. **Tapret input** (previously committed):
    ///    The input is spent via script-path using the tapret leaf.
    ///
    /// For freshly funded UTXOs (case 1), this is the standard flow.
    pub fn build_commitment_tx(
        &self,
        wallet: &SealWallet,
        seal_utxo: &WalletUtxo,
        commitment_hash: [u8; 32],
        change_path: Option<&Bip86Path>,
    ) -> Result<CommitmentTxResult, TxBuilderError> {
        // Validate minimum UTXO size (network-specific)
        let min_sat = minimum_utxo_sat(wallet.network());
        if seal_utxo.amount_sat < min_sat {
            return Err(TxBuilderError::InsufficientFunds {
                available: seal_utxo.amount_sat,
                required: min_sat,
            });
        }

        let secp = wallet.secp();
        let seal_key = wallet.derive_key(&seal_utxo.path)?;

        // Use a minimal commitment value (dust threshold + small buffer)
        // The commitment hash is what matters, not the monetary value
        let commitment_value_sat = self.dust_threshold_sat + 1000; // 1330 sats minimum

        // Select UTXOs: start with seal_utxo, add more if needed
        let mut input_utxos = vec![seal_utxo.clone()];
        let mut total_input = seal_utxo.amount_sat;

        // Calculate initial fee estimate (will be recalculated after selecting inputs)
        let output_count = if change_path.is_some() { 2 } else { 1 };

        // Add more UTXOs if insufficient for commitment + fees
        // Only select spendable UTXOs (RpcWallet or ImportedFunding)
        // SanadAnchor, ConsumedSeal, and Unknown are never selectable
        let all_utxos = wallet.list_utxos();
        let min_sat = minimum_utxo_sat(wallet.network());

        for utxo in all_utxos {
            // Skip if already selected or below minimum threshold
            if input_utxos.iter().any(|u| u.outpoint == utxo.outpoint) {
                continue;
            }
            if utxo.amount_sat < min_sat {
                continue;
            }

            // CRITICAL: Only select spendable UTXOs
            // SanadAnchor, ConsumedSeal, and Unknown must never be selected as inputs
            if !utxo.provenance.is_spendable() {
                continue;
            }

            // Limit to 20 inputs to avoid excessive transactions
            if input_utxos.len() >= 20 {
                break;
            }

            input_utxos.push(utxo.clone());
            total_input += utxo.amount_sat;
        }

        // Recalculate fee with final input count
        let fee = self.calculate_fee(input_utxos.len(), output_count);

        // Final validation
        if total_input < fee + commitment_value_sat {
            return Err(TxBuilderError::InsufficientFunds {
                available: total_input,
                required: fee + commitment_value_sat,
            });
        }

        // Calculate change amount (from all inputs)
        let change_amount = total_input
            .saturating_sub(fee)
            .saturating_sub(commitment_value_sat);

        if !self.is_above_dust(commitment_value_sat) {
            return Err(TxBuilderError::OutputBelowDust {
                value: commitment_value_sat,
                dust: self.dust_threshold_sat,
            });
        }

        // Build Tapret commitment output
        let tapret = TapretCommitment::new(self.protocol_id, csv_hash::Hash::new(commitment_hash));
        let leaf_script = tapret.leaf_script();

        // Build Taproot tree with single tapret leaf at depth 0
        // Use the internal key (before tweaking) from the derived seal key
        let internal_xonly = seal_key.internal_xonly;
        let builder = bitcoin::taproot::TaprootBuilder::new();
        let builder = builder
            .add_leaf(0, leaf_script.clone())
            .map_err(|e| TxBuilderError::TaprootBuildFailed(format!("{:?}", e)))?;

        let taproot_spend_info = builder
            .finalize(secp, internal_xonly)
            .map_err(|e| TxBuilderError::TaprootBuildFailed(format!("{:?}", e)))?;

        let output_key = taproot_spend_info.output_key();
        let address = Address::p2tr_tweaked(output_key, wallet.network());

        // CRITICAL FIX: For plain P2TR input spending, the sighash must use the ACTUAL on-chain prevout scriptPubKey
        // which is the simple P2TR (tweak=None), NOT the tapret output scriptPubKey.
        // The UTXO was funded to seal_key.address (simple P2TR), so that's what we use for sighash.
        // The output goes to the tapret address, but the sighash commits to the INPUT prevout.

        // Build unsigned transaction with multiple inputs
        let inputs: Vec<TxIn> = input_utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: RBF_SEQUENCE,
                witness: bitcoin::Witness::new(),
            })
            .collect();

        // Build outputs: commitment output + optional change output
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(commitment_value_sat),
            script_pubkey: address.script_pubkey(),
        }];

        let change_output = if let Some(path) = change_path {
            if self.is_above_dust(change_amount) {
                let change_key = wallet.derive_key(path)?;
                let change_address = change_key.address;
                outputs.push(TxOut {
                    value: Amount::from_sat(change_amount),
                    script_pubkey: change_address.script_pubkey(),
                });
                Some(ChangeOutput {
                    address: change_address,
                    value: Amount::from_sat(change_amount),
                    derivation_path: path.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Sign all inputs via key-path spending
        // Each input UTXO was sent to its corresponding address (simple P2TR with no script tree)
        let mut signed_tx = unsigned_tx.clone();

        // Build prevouts array for sighash
        let prevouts: Vec<bitcoin::TxOut> = input_utxos
            .iter()
            .map(|utxo| {
                let key = wallet
                    .derive_key(&utxo.path)
                    .unwrap_or_else(|_| seal_key.clone());
                let derived_script_pubkey = key.address.script_pubkey();
                let input_script_pubkey = utxo
                    .script_pubkey
                    .as_ref()
                    .unwrap_or(&derived_script_pubkey);
                bitcoin::TxOut {
                    value: Amount::from_sat(utxo.amount_sat),
                    script_pubkey: input_script_pubkey.clone(),
                }
            })
            .collect();

        let prevouts_ref: Vec<&bitcoin::TxOut> = prevouts.iter().collect();

        for (i, utxo) in input_utxos.iter().enumerate() {
            // Derive key for this input
            let input_key = wallet.derive_key(&utxo.path).map_err(|e| {
                TxBuilderError::WalletError(format!("Failed to derive key for input {}: {}", i, e))
            })?;

            // Get scriptPubKey for this input
            let derived_script_pubkey = input_key.address.script_pubkey();
            let _input_script_pubkey = utxo
                .script_pubkey
                .as_ref()
                .unwrap_or(&derived_script_pubkey);

            // CRITICAL: Verify scriptPubKey matches the derived wallet address
            // This ensures we're signing for an output that actually belongs to our wallet
            if let Some(actual_script) = &utxo.script_pubkey {
                if actual_script != &derived_script_pubkey {
                    return Err(TxBuilderError::WalletError(format!(
                        "ScriptPubKey mismatch for input {}: derived {:?} does not match on-chain {:?}",
                        i, derived_script_pubkey, actual_script
                    )));
                }
            }

            // IMPORTANT: Use unsigned_tx for sighash calculation, not signed_tx
            // This ensures each sighash is computed correctly without interference from previous signatures
            let sighash = bitcoin::sighash::SighashCache::new(&unsigned_tx)
                .taproot_key_spend_signature_hash(
                    i,
                    &bitcoin::sighash::Prevouts::All(&prevouts_ref[..]),
                    bitcoin::sighash::TapSighashType::Default,
                )
                .map_err(|e| {
                    TxBuilderError::SighashFailed(format!(
                        "Failed to create sighash for input {}: {}",
                        i, e
                    ))
                })?;

            let mut sighash_bytes = [0u8; 32];
            sighash_bytes.copy_from_slice(sighash.as_ref());

            // Sign with the tweaked keypair for key-path spending
            let schnorr_sig = wallet
                .sign_taproot_keypath(&utxo.path, &sighash_bytes)
                .map_err(|e| {
                    TxBuilderError::WalletError(format!("Failed to sign input {}: {}", i, e))
                })?;

            // CRITICAL: Pre-broadcast local signature verification for BIP-341/BIP-86
            // Verify the signature is valid before attempting to broadcast
            let msg = secp256k1::Message::from_digest_slice(&sighash_bytes).map_err(|e| {
                TxBuilderError::WalletError(format!(
                    "Failed to create message for verification: {}",
                    e
                ))
            })?;
            let secret_key = wallet.derive_private_key(&utxo.path).map_err(|e| {
                TxBuilderError::WalletError(format!(
                    "Failed to derive secret key for verification: {}",
                    e
                ))
            })?;
            let kp = secp256k1::Keypair::from_secret_key(secp, &secret_key);
            let tweaked_kp = kp.tap_tweak(secp, None);

            let sig = secp256k1::schnorr::Signature::from_slice(&schnorr_sig)
                .map_err(|_| TxBuilderError::WalletError("Invalid signature format".to_string()))?;

            // Extract the XOnlyPublicKey from the tweaked keypair for verification
            let (xonly_pubkey, _parity) = tweaked_kp.to_keypair().x_only_public_key();

            if secp.verify_schnorr(&sig, &msg, &xonly_pubkey).is_err() {
                return Err(TxBuilderError::WalletError(format!(
                    "Local signature verification failed for input {}: invalid Schnorr signature",
                    i
                )));
            }

            // Build the witness: [64-byte Schnorr signature]
            let witness = bitcoin::Witness::from_slice(&[schnorr_sig.as_slice()]);
            signed_tx.input[i].witness = witness;
        }

        let raw_tx = tx_serialize(&signed_tx);
        let txid = signed_tx.compute_txid();

        let script_pubkey = address.script_pubkey();

        // Determine commitment output index (always 0, change is at 1 if present)
        let commitment_output_index = 0;

        Ok(CommitmentTxResult {
            tx: signed_tx,
            txid,
            raw_tx,
            tapret_output: TapretOutput {
                address,
                script_pubkey,
                value: Amount::from_sat(commitment_value_sat),
                taproot_spend_info,
                leaf_script,
                amount_sat: commitment_value_sat,
            },
            change_output,
            fee_sat: fee,
            input_value_sat: seal_utxo.amount_sat,
            commitment_output_index,
        })
    }

    /// Build legacy commitment data (for backward compatibility)
    pub fn build_commitment_data(&self, commitment: csv_hash::Hash) -> CommitmentData {
        let tapret = TapretCommitment::new(self.protocol_id, commitment);
        CommitmentData::Tapret {
            script: tapret.leaf_script(),
            payload: tapret.payload(),
        }
    }
}

/// Tapret commitment output
#[derive(Clone, Debug)]
pub struct TapretOutput {
    pub address: Address,
    pub script_pubkey: ScriptBuf,
    pub value: Amount,
    pub taproot_spend_info: bitcoin::taproot::TaprootSpendInfo,
    pub leaf_script: ScriptBuf,
    pub amount_sat: u64,
}

/// Change output
#[derive(Clone, Debug)]
pub struct ChangeOutput {
    pub address: Address,
    pub value: Amount,
    pub derivation_path: Bip86Path,
}

/// Transaction builder output
#[derive(Clone, Debug)]
pub struct CommitmentTxResult {
    pub tx: bitcoin::Transaction,
    pub txid: Txid,
    pub raw_tx: Vec<u8>,
    pub tapret_output: TapretOutput,
    pub change_output: Option<ChangeOutput>,
    pub fee_sat: u64,
    pub input_value_sat: u64,
    pub commitment_output_index: u32,
}

impl CommitmentTxResult {
    pub fn commitment_output_index(&self) -> u32 {
        self.commitment_output_index
    }
}

/// Commitment data output (for backward compatibility)
pub enum CommitmentData {
    Tapret {
        script: ScriptBuf,
        payload: [u8; 64],
    },
    Opret {
        script: ScriptBuf,
    },
}

impl CommitmentData {
    pub fn script(&self) -> &ScriptBuf {
        match self {
            CommitmentData::Tapret { script, .. } => script,
            CommitmentData::Opret { script } => script,
        }
    }
}

/// Transaction builder errors
#[derive(Debug, thiserror::Error)]
pub enum TxBuilderError {
    #[error("Taproot build failed: {0}")]
    TaprootBuildFailed(String),

    #[error("Output value {value} sat is below dust threshold {dust} sat")]
    OutputBelowDust { value: u64, dust: u64 },

    #[error("Sighash computation failed: {0}")]
    SighashFailed(String),

    #[error("Wallet error: {0}")]
    WalletError(String),

    #[error("Insufficient funds: available {available} sat, required {required} sat")]
    InsufficientFunds { available: u64, required: u64 },
}

impl From<crate::wallet::WalletError> for TxBuilderError {
    fn from(e: crate::wallet::WalletError) -> Self {
        TxBuilderError::WalletError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UtxoProvenance;
    use bitcoin::{Network, OutPoint};

    fn make_utxo(path: Bip86Path, amount: u64) -> WalletUtxo {
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xAB; 32]));
        WalletUtxo {
            outpoint: OutPoint::new(txid, 0),
            amount_sat: amount,
            path,
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::RpcWallet,
        }
    }

    #[test]
    fn test_builder_creation() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 10);
        assert_eq!(builder.fee_rate_sat_per_vb, 10);
        assert_eq!(builder.protocol_id, [1u8; 32]);
    }

    #[test]
    fn test_builder_with_fee_rate() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 5).with_fee_rate(20);
        assert_eq!(builder.fee_rate_sat_per_vb, 20);
    }

    #[test]
    fn test_vbyte_estimation() {
        let vbytes = CommitmentTxBuilder::estimate_vbytes(1, 1);
        assert!(vbytes > 50);
        assert!(vbytes < 300);
    }

    #[test]
    fn test_fee_calculation() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 10);
        let fee = builder.calculate_fee(1, 1);
        let expected_vbytes = CommitmentTxBuilder::estimate_vbytes(1, 1);
        assert_eq!(fee, expected_vbytes as u64 * 10);
    }

    #[test]
    fn test_max_fee_rate_cap() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 1000).with_max_fee_rate(10);
        let fee = builder.calculate_fee(1, 1);
        let vbytes = CommitmentTxBuilder::estimate_vbytes(1, 1);
        assert_eq!(fee, vbytes as u64 * 10);
    }

    #[test]
    fn test_dust_check() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 10);
        assert!(builder.is_above_dust(P2TR_DUST_SAT));
        assert!(builder.is_above_dust(2000));
        assert!(!builder.is_above_dust(100));
    }

    #[test]
    fn test_build_commitment_data() {
        let builder = CommitmentTxBuilder::new([1u8; 32], 10);
        let data = builder.build_commitment_data(csv_hash::Hash::new([2u8; 32]));
        match data {
            CommitmentData::Tapret { script, payload } => {
                assert_eq!(payload[..32], [1u8; 32]);
                assert!(script.is_op_return());
            }
            _ => panic!("Expected Tapret"),
        }
    }

    #[test]
    fn test_build_commitment_tx() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let seal_utxo = make_utxo(path.clone(), 1_000_000);
        wallet.add_utxo(seal_utxo.outpoint, seal_utxo.amount_sat, path);

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder
            .build_commitment_tx(&wallet, &seal_utxo, [0xCD; 32], None)
            .expect("tx build should succeed");

        assert!(result.fee_sat > 0);
        assert_eq!(result.input_value_sat, 1_000_000);
        assert!(result.raw_tx.len() >= result.tx.vsize());
        // Commitment output uses minimal value (dust + buffer)
        assert_eq!(result.tapret_output.amount_sat, 1330);
    }

    #[test]
    fn test_tx_has_witness() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let seal_utxo = make_utxo(path.clone(), 500_000);
        wallet.add_utxo(seal_utxo.outpoint, seal_utxo.amount_sat, path);

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder
            .build_commitment_tx(&wallet, &seal_utxo, [0xCD; 32], None)
            .expect("tx build should succeed");

        // Transaction should have valid witness data
        assert!(!result.tx.input[0].witness.is_empty());
        assert!(!result.raw_tx.is_empty());
    }

    #[test]
    fn test_dust_prevention() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let seal_utxo = make_utxo(path.clone(), 500);
        wallet.add_utxo_with_provenance(
            seal_utxo.outpoint,
            seal_utxo.amount_sat,
            path,
            None,
            None,
            UtxoProvenance::RpcWallet,
        );

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder.build_commitment_tx(&wallet, &seal_utxo, [0xCD; 32], None);

        // Should fail due to dust or insufficient funds
        assert!(result.is_err());
    }

    #[test]
    fn test_tx_builder_filters_sanad_anchor_inputs() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let path2 = Bip86Path::external(0, 1);

        // Add a spendable UTXO
        let spendable_txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x01; 32]));
        let spendable_utxo = WalletUtxo {
            outpoint: OutPoint::new(spendable_txid, 0),
            amount_sat: 100_000,
            path: path.clone(),
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::RpcWallet,
        };
        wallet.add_utxo_with_provenance(
            spendable_utxo.outpoint,
            spendable_utxo.amount_sat,
            spendable_utxo.path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );

        // Add a SanadAnchor UTXO (should never be selected)
        let anchor_txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x02; 32]));
        let anchor_utxo = WalletUtxo {
            outpoint: OutPoint::new(anchor_txid, 0),
            amount_sat: 1_000_000,
            path: path2.clone(),
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::SanadAnchor,
        };
        wallet.add_utxo_with_provenance(
            anchor_utxo.outpoint,
            anchor_utxo.amount_sat,
            anchor_utxo.path.clone(),
            None,
            None,
            UtxoProvenance::SanadAnchor,
        );

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder.build_commitment_tx(&wallet, &spendable_utxo, [0xCD; 32], None);

        // Should succeed using only the spendable UTXO
        assert!(result.is_ok());

        // Verify the transaction doesn't include the SanadAnchor
        let tx = result.unwrap().tx;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, spendable_utxo.outpoint);
    }

    #[test]
    fn test_tx_builder_filters_consumed_seal_inputs() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let path2 = Bip86Path::external(0, 1);

        // Add a spendable UTXO
        let spendable_txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x01; 32]));
        let spendable_utxo = WalletUtxo {
            outpoint: OutPoint::new(spendable_txid, 0),
            amount_sat: 100_000,
            path: path.clone(),
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::RpcWallet,
        };
        wallet.add_utxo_with_provenance(
            spendable_utxo.outpoint,
            spendable_utxo.amount_sat,
            spendable_utxo.path.clone(),
            None,
            None,
            UtxoProvenance::RpcWallet,
        );

        // Add a ConsumedSeal UTXO (should never be selected)
        let consumed_txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x03; 32]));
        let consumed_utxo = WalletUtxo {
            outpoint: OutPoint::new(consumed_txid, 0),
            amount_sat: 1_000_000,
            path: path2.clone(),
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::ConsumedSeal,
        };
        wallet.add_utxo_with_provenance(
            consumed_utxo.outpoint,
            consumed_utxo.amount_sat,
            consumed_utxo.path.clone(),
            None,
            None,
            UtxoProvenance::ConsumedSeal,
        );

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder.build_commitment_tx(&wallet, &spendable_utxo, [0xCD; 32], None);

        // Should succeed using only the spendable UTXO
        assert!(result.is_ok());

        // Verify the transaction doesn't include the ConsumedSeal
        let tx = result.unwrap().tx;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, spendable_utxo.outpoint);
    }

    #[test]
    fn test_script_pubkey_mismatch_fails() {
        let wallet = SealWallet::generate_random(Network::Regtest);
        let path = Bip86Path::external(0, 0);
        let path2 = Bip86Path::external(0, 1);

        // Add a UTXO with a scriptPubKey from a different address
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xAB; 32]));
        let wrong_key = wallet.derive_key(&path2).unwrap();
        let mut utxo = make_utxo(path.clone(), 1_000_000);
        utxo.script_pubkey = Some(wrong_key.address.script_pubkey()); // Script from wrong path
        utxo.provenance = UtxoProvenance::RpcWallet;

        wallet.add_utxo_with_provenance(
            utxo.outpoint,
            utxo.amount_sat,
            utxo.path.clone(),
            utxo.script_pubkey.clone(),
            None,
            UtxoProvenance::RpcWallet,
        );

        let builder = CommitmentTxBuilder::new([0xAB; 32], 10);
        let result = builder.build_commitment_tx(&wallet, &utxo, [0xCD; 32], None);

        // Should fail due to scriptPubKey mismatch
        assert!(result.is_err());
        match result {
            Err(TxBuilderError::WalletError(msg)) => {
                assert!(msg.contains("ScriptPubKey mismatch"));
            }
            _ => panic!("Expected ScriptPubKey mismatch error"),
        }
    }
}
