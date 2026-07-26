//! Deterministic Bitcoin source-seal closure construction.
//!
//! A closure is a real signed transaction spending the named source outpoint.
//! The successor commitment is bound into the Taproot output tree; a local
//! replay entry or tagged hash is never returned as closure evidence.

use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};

use crate::tx_builder::{CommitmentTxBuilder, TxBuilderError};
use crate::wallet::{Bip86Path, SealWallet, WalletUtxo};

/// Material an isolated recipient needs before inclusion/finality verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinClosureArtifact {
    /// Network on which the transaction is valid.
    pub network: String,
    /// Exact source outpoint consumed by this closure.
    pub source_outpoint: bitcoin::OutPoint,
    /// Consensus-encoded signed transaction.
    pub transaction: Vec<u8>,
    /// Transaction identity derived from `transaction`.
    pub txid: [u8; 32],
    /// Successor transition commitment bound into the Taproot tree.
    pub successor_commitment: [u8; 32],
    /// Protocol-id || successor-commitment payload committed by the leaf.
    pub commitment_payload: Vec<u8>,
    /// Taproot leaf script used to derive the commitment output key.
    pub commitment_leaf_script: Vec<u8>,
    /// Untweaked x-only key needed to independently derive the output key.
    pub internal_key: [u8; 32],
    /// ScriptPubKey of the commitment-carrying successor output.
    pub commitment_output_script: Vec<u8>,
    /// Index of the commitment-carrying successor output.
    pub commitment_output_index: u32,
}

impl BitcoinClosureArtifact {
    /// Check deterministic structural bindings before persistence or broadcast.
    pub fn validate(&self) -> Result<(), BitcoinClosureError> {
        let transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(&self.transaction)
            .map_err(|error| BitcoinClosureError::InvalidTransaction(error.to_string()))?;
        if transaction.compute_txid().to_byte_array() != self.txid {
            return Err(BitcoinClosureError::TransactionIdentityMismatch);
        }
        if transaction
            .input
            .iter()
            .filter(|input| input.previous_output == self.source_outpoint)
            .count()
            != 1
        {
            return Err(BitcoinClosureError::SourceOutpointNotConsumedExactlyOnce);
        }
        if self.commitment_payload[32..] != self.successor_commitment {
            return Err(BitcoinClosureError::SuccessorCommitmentMismatch);
        }
        let mut protocol_id = [0u8; 32];
        protocol_id.copy_from_slice(&self.commitment_payload[..32]);
        let expected_leaf = crate::TapretCommitment::new(
            protocol_id,
            csv_hash::Hash::new(self.successor_commitment),
        )
        .leaf_script();
        if expected_leaf.as_bytes() != self.commitment_leaf_script {
            return Err(BitcoinClosureError::CommitmentWitnessMismatch);
        }
        let internal_key = bitcoin::XOnlyPublicKey::from_slice(&self.internal_key)
            .map_err(|_| BitcoinClosureError::CommitmentWitnessMismatch)?;
        let spend_info = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, expected_leaf)
            .map_err(|_| BitcoinClosureError::CommitmentWitnessMismatch)?
            .finalize(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                internal_key,
            )
            .map_err(|_| BitcoinClosureError::CommitmentWitnessMismatch)?;
        let network = self
            .network
            .parse::<bitcoin::Network>()
            .map_err(|_| BitcoinClosureError::NetworkInvalid)?;
        let expected_output =
            bitcoin::Address::p2tr_tweaked(spend_info.output_key(), network).script_pubkey();
        let output = transaction
            .output
            .get(self.commitment_output_index as usize)
            .ok_or(BitcoinClosureError::CommitmentOutputMissing)?;
        if output.script_pubkey != expected_output
            || output.script_pubkey.as_bytes() != self.commitment_output_script
        {
            return Err(BitcoinClosureError::CommitmentOutputMismatch);
        }
        Ok(())
    }
}

/// Build and sign a Bitcoin closure artifact without broadcasting it.
///
/// Persist this artifact before submission. Rebuilding from the same wallet
/// seed, UTXO, commitment, fee policy, and change path produces identical bytes,
/// allowing retries to rebroadcast the same transaction rather than construct a
/// conflicting spend.
pub fn build_source_closure(
    builder: &CommitmentTxBuilder,
    wallet: &SealWallet,
    source_utxo: &WalletUtxo,
    successor_commitment: [u8; 32],
    change_path: Option<&Bip86Path>,
) -> Result<BitcoinClosureArtifact, BitcoinClosureError> {
    let result = builder
        .build_commitment_tx(wallet, source_utxo, successor_commitment, change_path)
        .map_err(BitcoinClosureError::Construction)?;
    let mut commitment_payload = [0u8; 64];
    commitment_payload[..32].copy_from_slice(&builder.protocol_id);
    commitment_payload[32..].copy_from_slice(&successor_commitment);
    let artifact = BitcoinClosureArtifact {
        network: wallet.network().to_string(),
        source_outpoint: source_utxo.outpoint,
        transaction: result.raw_tx,
        txid: result.txid.to_byte_array(),
        successor_commitment,
        commitment_payload: commitment_payload.to_vec(),
        commitment_leaf_script: result.tapret_output.leaf_script.into_bytes(),
        internal_key: result
            .tapret_output
            .taproot_spend_info
            .internal_key()
            .serialize(),
        commitment_output_script: result.tapret_output.script_pubkey.into_bytes(),
        commitment_output_index: result.commitment_output_index,
    };
    artifact.validate()?;
    Ok(artifact)
}

/// Source-closure construction failure.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinClosureError {
    /// Transaction construction or signing failed.
    #[error("Bitcoin closure construction failed: {0}")]
    Construction(#[source] TxBuilderError),
    /// Consensus transaction decoding failed.
    #[error("Bitcoin closure transaction is malformed: {0}")]
    InvalidTransaction(String),
    /// Supplied txid does not identify the supplied transaction.
    #[error("Bitcoin closure transaction identity mismatch")]
    TransactionIdentityMismatch,
    /// The named source is absent or duplicated.
    #[error("Bitcoin closure must consume the source outpoint exactly once")]
    SourceOutpointNotConsumedExactlyOnce,
    /// Witness payload names another successor.
    #[error("Bitcoin closure payload does not bind the successor commitment")]
    SuccessorCommitmentMismatch,
    /// Leaf/internal-key witness does not derive the committed output.
    #[error("Bitcoin closure commitment witness is invalid")]
    CommitmentWitnessMismatch,
    /// Artifact names an unsupported Bitcoin network.
    #[error("Bitcoin closure network is invalid")]
    NetworkInvalid,
    /// Commitment output index is outside the transaction.
    #[error("Bitcoin closure commitment output is missing")]
    CommitmentOutputMissing,
    /// Transaction output does not match the supplied commitment witness.
    #[error("Bitcoin closure commitment output does not match its witness")]
    CommitmentOutputMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UtxoProvenance;
    fn fixture(commitment: [u8; 32]) -> BitcoinClosureArtifact {
        let seed = [7u8; 64];
        let wallet = SealWallet::from_seed(&seed, bitcoin::Network::Regtest).unwrap();
        let path = Bip86Path::external(0, 0);
        let outpoint = bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([9u8; 32]), 1);
        let source = WalletUtxo {
            outpoint,
            amount_sat: 100_000,
            path: path.clone(),
            reserved: false,
            reserved_for: None,
            script_pubkey: None,
            sanad_id: None,
            provenance: UtxoProvenance::RpcWallet,
        };
        wallet.add_utxo(outpoint, source.amount_sat, path);
        build_source_closure(
            &CommitmentTxBuilder::new([0x43; 32], 2),
            &wallet,
            &source,
            commitment,
            None,
        )
        .unwrap()
    }

    #[test]
    fn closure_consumes_source_and_binds_successor() {
        let artifact = fixture([3; 32]);
        artifact.validate().unwrap();
        assert_eq!(&artifact.commitment_payload[32..], &[3; 32]);
    }

    #[test]
    fn changing_successor_changes_transaction_and_witness() {
        let first = fixture([3; 32]);
        let second = fixture([4; 32]);
        assert_ne!(first.txid, second.txid);
        assert_ne!(first.commitment_payload, second.commitment_payload);
        assert_ne!(
            first.commitment_output_script,
            second.commitment_output_script
        );
    }

    #[test]
    fn restart_rebuild_is_byte_identical() {
        let first = fixture([3; 32]);
        let rebuilt = fixture([3; 32]);
        assert_eq!(first, rebuilt);
    }

    #[test]
    fn changing_named_source_fails_closed() {
        let mut artifact = fixture([3; 32]);
        artifact.source_outpoint.vout += 1;
        assert!(matches!(
            artifact.validate(),
            Err(BitcoinClosureError::SourceOutpointNotConsumedExactlyOnce)
        ));
    }
}
