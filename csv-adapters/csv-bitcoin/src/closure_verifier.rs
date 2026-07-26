//! Isolated cryptographic verification of Bitcoin source closure.

use bitcoin::hashes::Hash as _;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProofKind, ClosureTrustMode, ClosureVerificationResult,
    FinalityPolicy, FinalizedCheckpoint,
};

use crate::closure::{BitcoinClosureArtifact, BitcoinClosureError};
use crate::proofs::verify_merkle_proof;
use crate::types::BitcoinInclusionProof;

/// Inputs needed to verify closure against one explicit checkpoint.
pub struct BitcoinClosureVerificationInput<'a> {
    /// Delivered signed closure transaction and commitment witness.
    pub artifact: &'a BitcoinClosureArtifact,
    /// Transaction Merkle branch and inclusion coordinates.
    pub inclusion: &'a BitcoinInclusionProof,
    /// Consensus-encoded 80-byte checkpoint block header.
    pub block_header: &'a [u8],
    /// Exact checkpoint and finality policy being evaluated.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Observed best-chain height from the named provider.
    pub observed_tip_height: u64,
    /// Optional maximum checkpoint age in blocks.
    pub max_checkpoint_age: Option<u64>,
    /// Stable proof-material provider identifier.
    pub proof_provider_id: &'a str,
    /// Trust mode used to establish the header/checkpoint chain.
    pub trust_mode: ClosureTrustMode,
}

/// Verify exact consumption, successor binding, Merkle inclusion and checkpoint policy.
pub fn verify_bitcoin_closure(
    input: BitcoinClosureVerificationInput<'_>,
) -> Result<ClosureVerificationResult, BitcoinClosureVerificationError> {
    input.artifact.validate().map_err(map_artifact_error)?;
    if input.artifact.network != input.checkpoint.network_id
        || input.checkpoint.chain_id != "bitcoin"
    {
        return Err(BitcoinClosureVerificationError::WrongNetwork);
    }
    if input.inclusion.block_height != input.checkpoint.block_height {
        return Err(BitcoinClosureVerificationError::WrongCheckpoint);
    }
    let header: bitcoin::block::Header = bitcoin::consensus::deserialize(input.block_header)
        .map_err(|_| BitcoinClosureVerificationError::MalformedBlockHeader)?;
    let block_hash = header.block_hash().to_byte_array();
    if input.inclusion.block_hash != block_hash
        || input.checkpoint.block_id.as_slice() != block_hash
    {
        return Err(BitcoinClosureVerificationError::WrongBlockHeader);
    }
    if !verify_merkle_proof(
        &input.artifact.txid,
        &header.merkle_root.to_byte_array(),
        input.inclusion,
    ) {
        return Err(BitcoinClosureVerificationError::WrongMerklePath);
    }
    let required = match &input.checkpoint.finality_policy {
        FinalityPolicy::Confirmations(required) if *required > 0 => *required as u64,
        _ => return Err(BitcoinClosureVerificationError::UnsupportedFinalityPolicy),
    };
    let confirmations = input
        .observed_tip_height
        .checked_sub(input.checkpoint.block_height)
        .map(|depth| depth + 1)
        .unwrap_or(0);
    let finality = if confirmations >= required {
        ClosureDimensionStatus::Satisfied
    } else {
        ClosureDimensionStatus::Failed
    };
    let freshness = match input.max_checkpoint_age {
        Some(max_age)
            if input
                .observed_tip_height
                .saturating_sub(input.checkpoint.block_height)
                <= max_age =>
        {
            ClosureDimensionStatus::Satisfied
        }
        Some(_) => ClosureDimensionStatus::Failed,
        None => ClosureDimensionStatus::Indeterminate,
    };
    let closure = if finality == ClosureDimensionStatus::Satisfied {
        ClosureDimensionStatus::Satisfied
    } else {
        ClosureDimensionStatus::Indeterminate
    };
    let reason = if finality == ClosureDimensionStatus::Satisfied {
        "BITCOIN.CLOSURE.VERIFIED"
    } else {
        "BITCOIN.FINALITY.INSUFFICIENT_CONFIRMATIONS"
    };
    Ok(ClosureVerificationResult {
        chain_id: "bitcoin".into(),
        network_id: input.artifact.network.clone(),
        proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
        checkpoint: input.checkpoint.clone(),
        proof_validity: ClosureDimensionStatus::Satisfied,
        checkpoint_finality: finality,
        checkpoint_freshness: freshness,
        source_closure: closure,
        trust_mode: input.trust_mode,
        verifier_id: "parwana.csv-bitcoin.closure.v2".into(),
        proof_provider_id: input.proof_provider_id.into(),
        reason_codes: vec![reason.into()],
    })
}

fn map_artifact_error(error: BitcoinClosureError) -> BitcoinClosureVerificationError {
    match error {
        BitcoinClosureError::InvalidTransaction(_) => {
            BitcoinClosureVerificationError::MalformedTransaction
        }
        BitcoinClosureError::TransactionIdentityMismatch => {
            BitcoinClosureVerificationError::WrongTransaction
        }
        BitcoinClosureError::SourceOutpointNotConsumedExactlyOnce => {
            BitcoinClosureVerificationError::WrongOutpoint
        }
        BitcoinClosureError::SuccessorCommitmentMismatch
        | BitcoinClosureError::CommitmentWitnessMismatch
        | BitcoinClosureError::CommitmentOutputMissing
        | BitcoinClosureError::CommitmentOutputMismatch => {
            BitcoinClosureVerificationError::WrongSuccessorCommitment
        }
        BitcoinClosureError::NetworkInvalid => BitcoinClosureVerificationError::WrongNetwork,
        BitcoinClosureError::Construction(_) => {
            BitcoinClosureVerificationError::MalformedTransaction
        }
    }
}

/// Stable fail-closed Bitcoin closure reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitcoinClosureVerificationError {
    /// Raw transaction cannot be decoded.
    #[error("BITCOIN.CLOSURE.MALFORMED_TRANSACTION")]
    MalformedTransaction,
    /// Supplied identity names another transaction.
    #[error("BITCOIN.CLOSURE.WRONG_TRANSACTION")]
    WrongTransaction,
    /// Transaction does not consume the exact source.
    #[error("BITCOIN.CLOSURE.WRONG_OUTPOINT")]
    WrongOutpoint,
    /// Taproot witness does not bind the delivered successor.
    #[error("BITCOIN.CLOSURE.WRONG_SUCCESSOR_COMMITMENT")]
    WrongSuccessorCommitment,
    /// Artifact and checkpoint name different Bitcoin networks.
    #[error("BITCOIN.CLOSURE.WRONG_NETWORK")]
    WrongNetwork,
    /// Inclusion height does not identify the named checkpoint.
    #[error("BITCOIN.CLOSURE.WRONG_CHECKPOINT")]
    WrongCheckpoint,
    /// Block header is not consensus-decodable.
    #[error("BITCOIN.CLOSURE.MALFORMED_BLOCK_HEADER")]
    MalformedBlockHeader,
    /// Header identity differs from the proof/checkpoint.
    #[error("BITCOIN.CLOSURE.WRONG_BLOCK_HEADER")]
    WrongBlockHeader,
    /// Merkle branch does not include the transaction.
    #[error("BITCOIN.CLOSURE.WRONG_MERKLE_PATH")]
    WrongMerklePath,
    /// This verifier cannot interpret the requested finality rule.
    #[error("BITCOIN.CLOSURE.UNSUPPORTED_FINALITY_POLICY")]
    UnsupportedFinalityPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Bip86Path, CommitmentTxBuilder, SealWallet, WalletUtxo, build_source_closure,
        types::UtxoProvenance,
    };
    fn artifact() -> BitcoinClosureArtifact {
        let wallet = SealWallet::from_seed(&[7u8; 64], bitcoin::Network::Regtest).unwrap();
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
            [3; 32],
            None,
        )
        .unwrap()
    }

    fn fixture() -> (
        BitcoinClosureArtifact,
        BitcoinInclusionProof,
        Vec<u8>,
        FinalizedCheckpoint,
    ) {
        let artifact = artifact();
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([1; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(artifact.txid),
            time: 1_700_000_000,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 42,
        };
        let block_hash = header.block_hash().to_byte_array();
        let inclusion = BitcoinInclusionProof::new(vec![], block_hash, 0, 100);
        let checkpoint = FinalizedCheckpoint {
            chain_id: "bitcoin".into(),
            network_id: "regtest".into(),
            block_height: 100,
            block_id: block_hash.to_vec(),
            finality_policy: FinalityPolicy::Confirmations(6),
        };
        (
            artifact,
            inclusion,
            bitcoin::consensus::serialize(&header),
            checkpoint,
        )
    }

    #[test]
    fn valid_closure_satisfies_all_cryptographic_dimensions() {
        let (artifact, inclusion, header, checkpoint) = fixture();
        let result = verify_bitcoin_closure(BitcoinClosureVerificationInput {
            artifact: &artifact,
            inclusion: &inclusion,
            block_header: &header,
            checkpoint: &checkpoint,
            observed_tip_height: 105,
            max_checkpoint_age: Some(10),
            proof_provider_id: "fixture",
            trust_mode: ClosureTrustMode::LightClient,
        })
        .unwrap();
        assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
        assert_eq!(
            result.checkpoint_finality,
            ClosureDimensionStatus::Satisfied
        );
        assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    }

    #[test]
    fn valid_inclusion_with_insufficient_depth_is_not_invalid_proof() {
        let (artifact, inclusion, header, checkpoint) = fixture();
        let result = verify_bitcoin_closure(BitcoinClosureVerificationInput {
            artifact: &artifact,
            inclusion: &inclusion,
            block_header: &header,
            checkpoint: &checkpoint,
            observed_tip_height: 104,
            max_checkpoint_age: Some(10),
            proof_provider_id: "fixture",
            trust_mode: ClosureTrustMode::LightClient,
        })
        .unwrap();
        assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
        assert_eq!(result.checkpoint_finality, ClosureDimensionStatus::Failed);
        assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
    }

    #[test]
    fn wrong_outpoint_commitment_path_header_and_network_fail_distinctly() {
        let (artifact, inclusion, header, checkpoint) = fixture();
        let verify = |artifact: &BitcoinClosureArtifact,
                      inclusion: &BitcoinInclusionProof,
                      header: &[u8],
                      checkpoint: &FinalizedCheckpoint| {
            verify_bitcoin_closure(BitcoinClosureVerificationInput {
                artifact,
                inclusion,
                block_header: header,
                checkpoint,
                observed_tip_height: 105,
                max_checkpoint_age: Some(10),
                proof_provider_id: "fixture",
                trust_mode: ClosureTrustMode::LightClient,
            })
        };

        let mut wrong_outpoint = artifact.clone();
        wrong_outpoint.source_outpoint.vout += 1;
        assert_eq!(
            verify(&wrong_outpoint, &inclusion, &header, &checkpoint),
            Err(BitcoinClosureVerificationError::WrongOutpoint)
        );

        let mut wrong_commitment = artifact.clone();
        wrong_commitment.successor_commitment[0] ^= 1;
        assert_eq!(
            verify(&wrong_commitment, &inclusion, &header, &checkpoint),
            Err(BitcoinClosureVerificationError::WrongSuccessorCommitment)
        );

        let mut wrong_path = inclusion.clone();
        wrong_path.merkle_branch.push([8; 32]);
        assert_eq!(
            verify(&artifact, &wrong_path, &header, &checkpoint),
            Err(BitcoinClosureVerificationError::WrongMerklePath)
        );

        let mut wrong_header = header.clone();
        wrong_header[0] ^= 1;
        assert_eq!(
            verify(&artifact, &inclusion, &wrong_header, &checkpoint),
            Err(BitcoinClosureVerificationError::WrongBlockHeader)
        );

        let mut wrong_network = checkpoint.clone();
        wrong_network.network_id = "signet".into();
        assert_eq!(
            verify(&artifact, &inclusion, &header, &wrong_network),
            Err(BitcoinClosureVerificationError::WrongNetwork)
        );
    }
}
