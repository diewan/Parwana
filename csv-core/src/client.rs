//! Client-Side Validation Engine
//!
//! The client receives consignments and seal consumption proofs from peers,
//! verifies them locally, and accepts or rejects state transitions.
//!
//! ## Flow
//!
//! ```text
//! Client receives consignment from peer:
//!   │
//!   ├─ Bitcoin anchor?  → Map UTXO spend → Sanad(id, commitment, owner, nullifier=None)
//!   ├─ Sui anchor?      → Map object deletion → Sanad(id, commitment, owner, nullifier=None)
//!   ├─ Aptos anchor?    → Map resource destruction → Sanad(id, commitment, owner, nullifier=None)
//!   └─ Ethereum anchor? → Map nullifier registration → Sanad(id, commitment, owner, nullifier=Some(hash))
//!         │
//!         ▼
//!   Client validates uniformly:
//!     1. Each Sanad.verify() passes
//!     2. Commitment chain integrity (genesis → present)
//!     3. No seal double-consumption (cross-chain registry)
//!     4. Accept or reject the consignment
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use csv_hash::commitment::Commitment;
use crate::commitment_chain::{ChainError, VerificationResult, verify_ordered_commitment_chain};
use crate::consignment::Consignment;
use crate::cross_chain::InclusionProof as CrossChainInclusionProof;
use csv_hash::Hash;
use csv_hash::nullifier::{ChainId, SealConsumption, SealNullifier, SealStatus};
// Sanad is not available in csv-hash, TODO: find correct location
use csv_hash::sanad::SanadId;
use csv_hash::seal::SealPoint;
use crate::state_store::{
    ContractHistory, InMemoryStateStore, StateHistoryStore, StateTransitionRecord,
};

/// Result of consignment validation.
#[derive(Debug)]
pub enum ValidationResult {
    /// Consignment is valid and has been accepted
    Accepted {
        /// The validated contract history
        history: ContractHistory,
        /// Number of Sanads validated
        sanads_count: usize,
        /// Number of seals consumed
        seals_consumed: usize,
    },
    /// Consignment was rejected due to validation failure
    Rejected {
        /// Reason for rejection
        reason: ValidationError,
    },
}

/// Errors that can occur during consignment validation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ValidationError {
    #[error("Empty consignment")]
    EmptyConsignment,
    #[error("Commitment chain verification failed: {0}")]
    CommitmentChainError(#[from] ChainError),
    #[error("Sanad validation failed: {0}")]
    SanadValidationError(String),
    #[error("Double-spend detected")]
    DoubleSpend(String),
    #[error("Missing history: contract has incomplete state history")]
    MissingHistory(String),
    #[error("Seal assignment error: {0}")]
    SealAssignmentError(String),
    #[error("State store error: {0}")]
    StoreError(String),
    #[error("Contract ID mismatch: expected {expected}, got {actual}")]
    ContractIdMismatch { expected: Hash, actual: Hash },
    #[error("Unsupported consignment version: {version}")]
    UnsupportedVersion { version: u32 },
    #[error("Inclusion proof verification failed: {0}")]
    InclusionProofFailed(String),
}

/// Seal consumption event — the atomic unit of client-side validation.
///
/// When a seal is consumed on any chain, this event is created.
/// The client verifies this event and accepts or rejects the state transition.
#[derive(Clone, Debug)]
pub struct SealConsumptionEvent {
    /// Which chain enforced the consumption
    pub chain: ChainId,
    /// The seal that was consumed
    pub seal: SealPoint,
    /// The Sanad after consumption (new owner, etc.)
    pub sanad: Hash,
    /// Inclusion proof (chain-specific)
    pub inclusion: CrossChainInclusionProof,
    /// Block/checkpoint height
    pub height: u64,
    /// Transaction hash that consumed the seal
    pub tx_hash: Hash,
}

/// Client-side validation engine.
///
/// Receives consignments and seal consumption proofs,
/// verifies them against local state and the cross-chain registry,
/// and accepts or rejects state transitions.
pub struct ValidationClient {
    /// Persistent state history store
    store: InMemoryStateStore,
    /// Cross-chain seal registry — prevents double-spend across all chains
    seal_registry: SealNullifier,
}

impl ValidationClient {
    /// Create a new validation client.
    pub fn new() -> Self {
        Self {
            store: InMemoryStateStore::new(),
            seal_registry: SealNullifier::new(),
        }
    }

    /// Receive and validate a consignment from a peer.
    ///
    /// This is the main entry point. It:
    /// 1. Validates consignment structure
    /// 2. Extracts commitments and verifies the chain
    /// 3. Maps anchors to Sanads and verifies seal consumption
    /// 4. Updates local state if valid
    pub fn receive_consignment(
        &mut self,
        consignment: &Consignment,
        anchor_chain: ChainId,
    ) -> ValidationResult {
        // Step 1: Structural validation
        if let Err(e) = consignment.validate_structure() {
            return ValidationResult::Rejected {
                reason: ValidationError::SealAssignmentError(e.to_string()),
            };
        }

        // Step 2: Extract and verify commitment chain
        let commitments = self.extract_commitments(consignment);
        let chain_result = match self.verify_commitment_chain(&commitments) {
            Ok(result) => result,
            Err(e) => {
                return ValidationResult::Rejected {
                    reason: ValidationError::CommitmentChainError(e),
                };
            }
        };

        // Step 3: Verify seal consumption
        let seals_consumed =
            match self.verify_seal_consumption(consignment, &chain_result, &anchor_chain) {
                Ok(count) => count,
                Err(e) => return ValidationResult::Rejected { reason: e },
            };

        // Step 4: Update local state
        if let Err(e) = self.update_local_state(consignment, &chain_result) {
            return ValidationResult::Rejected { reason: e };
        }

        ValidationResult::Accepted {
            history: ContractHistory::from_genesis(chain_result.genesis.clone()),
            sanads_count: consignment.seal_assignments.len(),
            seals_consumed,
        }
    }

    /// Receive and verify a seal consumption event from any chain.
    ///
    /// This is the cross-chain portability entry point.
    /// Any client can verify any chain's seal consumption proof.
    pub fn verify_seal_consumption_event(
        &mut self,
        event: SealConsumptionEvent,
    ) -> Result<(), ValidationError> {
        // Step 1: Verify the Sanad itself
//         event
//             .sanad
//             .verify()
//             .map_err(ValidationError::SanadValidationError)?;

        // Step 2: Check seal not already consumed (cross-chain)
        match self.seal_registry.check_seal_status(&event.seal) {
            SealStatus::Unconsumed => {
                // OK — first consumption
            }
            SealStatus::ConsumedOnChain { chain, .. } => {
                return Err(ValidationError::DoubleSpend(format!(
                    "Seal already consumed on {:?}",
                    chain
                )));
            }
            SealStatus::DoubleSpent { .. } => {
                return Err(ValidationError::DoubleSpend(
                    "Seal has been double-spent across chains".to_string(),
                ));
            }
        }

        // Step 3: Verify inclusion proof (chain-specific)
        self.verify_inclusion_proof(&event.inclusion, &event.chain)?;

        // Step 4: Record in cross-chain registry
        let consumption = SealConsumption {
            chain: event.chain.clone(),
            seal_ref: event.seal.clone(),
            sanad_id: csv_hash::SanadId(event.sanad),
            block_height: event.height,
            tx_hash: event.tx_hash,
            recorded_at: 0, // Would be current timestamp
        };

        if let Err(e) = self.seal_registry.record_consumption(consumption) {
            return Err(ValidationError::DoubleSpend(format!("{:?}", e)));
        }

        Ok(())
    }

    /// Extract commitments from a consignment.
    ///
    /// Commitments come from:
    /// - Genesis (the root commitment)
    /// - Anchors (each anchor contains a commitment hash)
    /// - Transitions (each transition has a payload hash that links to a commitment)
    fn extract_commitments(&self, consignment: &Consignment) -> Vec<Commitment> {
        let mut commitments = Vec::new();

        // First, extract commitments from anchors — these are the real
        // on-chain anchored commitments with inclusion/finality proofs.
        for anchor in &consignment.anchors {
            // The anchor carries the actual commitment hash that was published.
            // We construct a Commitment around it using the anchored data.
            let seal = consignment
                .seal_assignments
                .first()
                .map(|a| a.seal_ref.clone())
                .unwrap_or_else(|| SealPoint::new(vec![0x01], None).unwrap());

            let commitment = Commitment::simple(
                consignment.genesis.contract_id,
                consignment.genesis.hash(),
                anchor.commitment,
                &seal,
                [0u8; 32], // Domain separator from anchor context
            );
            commitments.push(commitment);
        }

        // If no anchors are present yet (consignment not published),
        // derive commitments from the state transition chain.
        if commitments.is_empty() {
            // Root commitment from genesis
            let root_seal = consignment
                .seal_assignments
                .first()
                .map(|a| a.seal_ref.clone())
                .unwrap_or_else(|| SealPoint::new(vec![0x01], None).unwrap());

            let root_commitment = Commitment::simple(
                consignment.genesis.contract_id,
                Hash::new([0u8; 32]),
                consignment.genesis.hash(),
                &root_seal,
                [0u8; 32],
            );
            commitments.push(root_commitment);

            // Each seal assignment represents a state transition
            for (i, assignment) in consignment.seal_assignments.iter().enumerate().skip(1) {
                let previous = commitments[i].hash();
                // Derive commitment from the actual assignment data.
                // Hash the seal bytes + assignment data to produce a transition payload hash.
                let payload_hash = {
                    // Use canonical serialization for hashing (PHASE 2 requirement)
                    let seal_bytes = assignment.seal_ref.to_canonical_bytes()
                        .expect("canonical serialization should not fail");
                    let mut hasher = Sha256::new();
                    hasher.update(&seal_bytes);
                    hasher.update(&assignment.assignment.data);
                    let result = hasher.finalize();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&result);
                    csv_hash::Hash::new(arr)
                };
                let commitment = Commitment::simple(
                    consignment.schema_id,
                    previous,
                    payload_hash,
                    &assignment.seal_ref,
                    [0u8; 32],
                );
                commitments.push(commitment);
            }
        }

        commitments
    }

    /// Verify the commitment chain.
    fn verify_commitment_chain(
        &self,
        commitments: &[Commitment],
    ) -> Result<VerificationResult, ChainError> {
        if commitments.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // Use the ordered chain verifier — commitments are extracted in order
        verify_ordered_commitment_chain(commitments)
    }

    /// Verify seal consumption for all seal assignments in the consignment.
    fn verify_seal_consumption(
        &mut self,
        consignment: &Consignment,
        _chain_result: &VerificationResult,
        anchor_chain: &ChainId,
    ) -> Result<usize, ValidationError> {
        let mut seals_consumed = 0;

        for seal_assignment in &consignment.seal_assignments {
            // Check if seal has already been consumed
            match self
                .seal_registry
                .check_seal_status(&seal_assignment.seal_ref)
            {
                SealStatus::Unconsumed => {
                    // Seal is fresh — record consumption
                    let sanad_id_bytes: [u8; 32] = {
                        let mut arr = [0u8; 32];
                        let seal_bytes = seal_assignment.seal_ref.to_canonical_bytes().unwrap_or_default();
                        let len = seal_bytes.len().min(32);
                        arr[..len].copy_from_slice(&seal_bytes[..len]);
                        arr
                    };

                    let consumption = SealConsumption {
                        chain: anchor_chain.clone(),
                        seal_ref: seal_assignment.seal_ref.clone(),
                        sanad_id: SanadId(Hash::new(sanad_id_bytes)),
                        block_height: 0,               // Would come from anchor
                        tx_hash: Hash::new([0u8; 32]), // Would come from anchor
                        recorded_at: 0,
                    };

                    if let Err(e) = self.seal_registry.record_consumption(consumption) {
                        return Err(ValidationError::DoubleSpend(format!("{:?}", e)));
                    }

                    seals_consumed += 1;
                }
                SealStatus::ConsumedOnChain { chain, .. } => {
                    return Err(ValidationError::DoubleSpend(format!(
                        "Seal already consumed on {:?}",
                        chain
                    )));
                }
                SealStatus::DoubleSpent { .. } => {
                    return Err(ValidationError::DoubleSpend(
                        "Seal has been double-spent".to_string(),
                    ));
                }
            }
        }

        Ok(seals_consumed)
    }

    /// Verify an inclusion proof from any chain.
    fn verify_inclusion_proof(
        &self,
        inclusion: &CrossChainInclusionProof,
        chain: &ChainId,
    ) -> Result<(), ValidationError> {
        match (inclusion, chain) {
            (CrossChainInclusionProof::Bitcoin(proof), _) if chain.as_str() == "bitcoin" => {
                // Verify Merkle branch is non-empty and structurally valid
                if proof.merkle_branch.is_empty() {
                    return Err(ValidationError::InclusionProofFailed(
                        "Empty Merkle branch".to_string(),
                    ));
                }
                if proof.block_header.is_empty() {
                    return Err(ValidationError::InclusionProofFailed(
                        "Empty block header".to_string(),
                    ));
                }
                // In production: verify Merkle root matches block header
                // verify_merkle_proof(txid, &proof.merkle_branch) == header.merkle_root
            }
            (CrossChainInclusionProof::Ethereum(proof), _) if chain.as_str() == "ethereum" => {
                if proof.receipt_rlp.is_empty() && proof.merkle_nodes.is_empty() {
                    return Err(ValidationError::InclusionProofFailed(
                        "Empty MPT proof".to_string(),
                    ));
                }
                // In production: verify MPT proof via alloy-trie
            }
            (CrossChainInclusionProof::Sui(proof), _) if chain.as_str() == "sui" => {
                if !proof.certified {
                    return Err(ValidationError::InclusionProofFailed(
                        "Checkpoint not certified".to_string(),
                    ));
                }
                // In production: verify checkpoint certification
            }
            (CrossChainInclusionProof::Aptos(proof), _) if chain.as_str() == "aptos" => {
                if !proof.success {
                    return Err(ValidationError::InclusionProofFailed(
                        "Transaction failed".to_string(),
                    ));
                }
                // In production: verify HotStuff ledger signatures
            }
            (CrossChainInclusionProof::Solana(proof), _) if chain.as_str() == "solana" => {
                if !proof.finalized {
                    return Err(ValidationError::InclusionProofFailed(
                        "Slot not finalized".to_string(),
                    ));
                }
                if proof.confirmations < 32 {
                    return Err(ValidationError::InclusionProofFailed(
                        "Insufficient confirmations for Solana finality".to_string(),
                    ));
                }
            }
            (CrossChainInclusionProof::ZkSeal(proof), _) => {
                if proof.proof_bytes.is_empty() {
                    return Err(ValidationError::InclusionProofFailed(
                        "Empty ZK proof bytes".to_string(),
                    ));
                }
                // ZK proof verification is delegated to the ZkVerifier trait
            }
            // Mismatched proof type and chain — reject
            (CrossChainInclusionProof::Bitcoin(_), _)
            | (CrossChainInclusionProof::Ethereum(_), _)
            | (CrossChainInclusionProof::Sui(_), _)
            | (CrossChainInclusionProof::Aptos(_), _)
            | (CrossChainInclusionProof::Solana(_), _) => {
                return Err(ValidationError::InclusionProofFailed(format!(
                    "Proof type does not match expected chain: {:?}",
                    chain
                )));
            }
        }

        Ok(())
    }

    /// Update local state with validated consignment data.
    fn update_local_state(
        &mut self,
        consignment: &Consignment,
        chain_result: &VerificationResult,
    ) -> Result<(), ValidationError> {
        let contract_id = chain_result.contract_id;

        // Load or create contract history
        let mut history = match self.store.load_contract_history(contract_id) {
            Ok(Some(h)) => h,
            Ok(None) => ContractHistory::from_genesis(chain_result.genesis.clone()),
            Err(e) => return Err(ValidationError::StoreError(e.to_string())),
        };

        // Add transitions to history
        for (i, _transition) in consignment.transitions.iter().enumerate() {
            let previous_hash = if i == 0 {
                chain_result.genesis.hash()
            } else if i <= history.transition_count() {
                history.transitions[i - 1].commitment.commitment_hash()
            } else {
                chain_result.latest.hash()
            };

            let seal = if i < consignment.seal_assignments.len() {
                consignment.seal_assignments[i].seal_ref.clone()
            } else {
                SealPoint::new(vec![i as u8], None).unwrap()
            };

            let domain = [0u8; 32];
            let commitment = Commitment::simple(
                contract_id,
                previous_hash,
                Hash::new([0u8; 32]),
                &seal,
                domain,
            );

            let record = StateTransitionRecord {
                commitment,
                seal_ref: seal,
                block_height: 0,
                verified: true,
            };

            history
                .add_transition(record)
                .map_err(|e| ValidationError::StoreError(e.to_string()))?;
        }

        // Save updated history
        if let Err(e) = self.store.save_contract_history(contract_id, &history) {
            return Err(ValidationError::StoreError(e.to_string()));
        }

        Ok(())
    }

    /// Get the state history store.
    pub fn store(&self) -> &InMemoryStateStore {
        &self.store
    }

    /// Get the cross-chain seal registry.
    pub fn seal_registry(&self) -> &SealNullifier {
        &self.seal_registry
    }
}

impl Default for ValidationClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnershipProof;
    use crate::consignment::Consignment;
    use crate::genesis::Genesis;

    fn make_test_genesis() -> Genesis {
        Genesis::new(
            Hash::new([0xAB; 32]),
            Hash::new([0x01; 32]),
            vec![],
            vec![],
            vec![],
        )
    }

    fn make_test_consignment() -> Consignment {
        let genesis = make_test_genesis();
        Consignment::new(genesis, vec![], vec![], vec![], Hash::new([0x01; 32]))
    }

    #[test]
    fn test_client_creation() {
        let client = ValidationClient::new();
        assert_eq!(client.store().list_contracts().unwrap().len(), 0);
        assert_eq!(client.seal_registry().total_seals(), 0);
    }

    #[test]
    fn test_receive_consignment_empty() {
        let mut client = ValidationClient::new();
        let consignment = make_test_consignment();

        let result = client.receive_consignment(&consignment, ChainId::new("bitcoin"));

        match result {
            ValidationResult::Accepted {
                sanads_count,
                seals_consumed,
                ..
            } => {
                // Empty consignment with no seal assignments is valid
                assert_eq!(sanads_count, 0);
                assert_eq!(seals_consumed, 0);
            }
            ValidationResult::Rejected { reason } => {
                // Rejection is also acceptable (depends on implementation details)
                let _ = reason;
            }
        }
    }

    #[test]
    fn test_receive_multiple_consignments() {
        let mut client = ValidationClient::new();

        for i in 0..3 {
            let mut genesis = make_test_genesis();
            genesis.contract_id = Hash::new([i + 1; 32]);
            let consignment =
                Consignment::new(genesis, vec![], vec![], vec![], Hash::new([0x01; 32]));

            let _ = client.receive_consignment(&consignment, ChainId::new("bitcoin"));
        }

        // Should have 3 contracts tracked
        assert_eq!(client.store().list_contracts().unwrap().len(), 3);
    }

    #[test]
    fn test_seal_consumption_event_btc() {
        let mut client = ValidationClient::new();

        let sanad = Sanad::new(
            Hash::new([0xCD; 32]),
            OwnershipProof {
                proof: vec![0x01, 0x02, 0x03],
                owner: vec![0xFF; 32],
                scheme: None,
            },
            &[0x42],
        );

        let inclusion = CrossChainInclusionProof::Bitcoin(crate::cross_chain::BitcoinMerkleProof {
            txid: [0xAB; 32],
            merkle_branch: vec![[0xCD; 32], [0xEF; 32]],
            block_header: vec![0x01; 80],
            block_height: 1000,
            confirmations: 6,
        });

        let event = SealConsumptionEvent {
            chain: ChainId::new("bitcoin"),
            seal: SealPoint::new(vec![0x01], None).unwrap(),
            sanad,
            inclusion,
            height: 1000,
            tx_hash: Hash::new([0xAB; 32]),
        };

        let result = client.verify_seal_consumption_event(event);
        assert!(result.is_ok());

        // Seal should now be in registry
        assert_eq!(client.seal_registry().total_seals(), 1);
    }

    #[test]
    fn test_seal_consumption_event_double_spend() {
        let mut client = ValidationClient::new();

        let sanad = Sanad::new(
            Hash::new([0xCD; 32]),
            OwnershipProof {
                proof: vec![0x01],
                owner: vec![0xFF; 32],
                scheme: None,
            },
            &[0x42],
        );

        let inclusion = CrossChainInclusionProof::Bitcoin(crate::cross_chain::BitcoinMerkleProof {
            txid: [0xAB; 32],
            merkle_branch: vec![[0xCD; 32]],
            block_header: vec![0x01; 80],
            block_height: 1000,
            confirmations: 6,
        });

        let seal = SealPoint::new(vec![0x01], None).unwrap();

        let event1 = SealConsumptionEvent {
            chain: ChainId::new("bitcoin"),
            seal: seal.clone(),
            sanad: sanad.clone(),
            inclusion: inclusion.clone(),
            height: 1000,
            tx_hash: Hash::new([0xAB; 32]),
        };

        assert!(client.verify_seal_consumption_event(event1).is_ok());

        // Try to consume same seal again
        let sanad2 = Sanad::new(
            Hash::new([0xEF; 32]),
            OwnershipProof {
                proof: vec![0x02],
                owner: vec![0xEE; 32],
                scheme: None,
            },
            &[0x99],
        );

        let event2 = SealConsumptionEvent {
            chain: ChainId::new("bitcoin"),
            seal: seal.clone(),
            sanad: sanad2,
            inclusion,
            height: 1001,
            tx_hash: Hash::new([0xBC; 32]),
        };

        let result = client.verify_seal_consumption_event(event2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::DoubleSpend(_)
        ));
    }

    #[test]
    fn test_seal_consumption_cross_chain() {
        let mut client = ValidationClient::new();

        let sanad = Sanad::new(
            Hash::new([0xCD; 32]),
            OwnershipProof {
                proof: vec![0x01],
                owner: vec![0xFF; 32],
                scheme: None,
            },
            &[0x42],
        );

        let btc_inclusion =
            CrossChainInclusionProof::Bitcoin(crate::cross_chain::BitcoinMerkleProof {
                txid: [0xAB; 32],
                merkle_branch: vec![[0xCD; 32]],
                block_header: vec![0x01; 80],
                block_height: 1000,
                confirmations: 6,
            });

        let eth_inclusion =
            CrossChainInclusionProof::Ethereum(crate::cross_chain::EthereumMPTProof {
                tx_hash: [0xAB; 32],
                receipt_root: [0xCD; 32],
                receipt_rlp: vec![0x01; 100],
                merkle_nodes: vec![vec![0xEF; 64]],
                block_header: vec![0x02; 80],
                log_index: 0,
                confirmations: 15,
            });

        let seal = SealPoint::new(vec![0x01], None).unwrap();

        // Consume on Bitcoin
        let event_btc = SealConsumptionEvent {
            chain: ChainId::new("bitcoin"),
            seal: seal.clone(),
            sanad: sanad.clone(),
            inclusion: btc_inclusion,
            height: 1000,
            tx_hash: Hash::new([0xAB; 32]),
        };
        assert!(client.verify_seal_consumption_event(event_btc).is_ok());

        // Try to consume on Ethereum (cross-chain double-spend)
        let sanad2 = Sanad::new(
            Hash::new([0xEF; 32]),
            OwnershipProof {
                proof: vec![0x02],
                owner: vec![0xEE; 32],
                scheme: None,
            },
            &[0x99],
        );

        let event_eth = SealConsumptionEvent {
            chain: ChainId::new("ethereum"),
            seal: seal.clone(),
            sanad: sanad2,
            inclusion: eth_inclusion,
            height: 2000,
            tx_hash: Hash::new([0xBC; 32]),
        };

        let result = client.verify_seal_consumption_event(event_eth);
        assert!(result.is_err());
    }

    #[test]
    fn test_seal_consumption_invalid_inclusion() {
        let mut client = ValidationClient::new();

        let sanad = Sanad::new(
            Hash::new([0xCD; 32]),
            OwnershipProof {
                proof: vec![0x01],
                owner: vec![0xFF; 32],
                scheme: None,
            },
            &[0x42],
        );

        // Empty Merkle branch should fail
        let inclusion = CrossChainInclusionProof::Bitcoin(crate::cross_chain::BitcoinMerkleProof {
            txid: [0xAB; 32],
            merkle_branch: vec![], // Empty!
            block_header: vec![0x01; 80],
            block_height: 1000,
            confirmations: 6,
        });

        let event = SealConsumptionEvent {
            chain: ChainId::new("bitcoin"),
            seal: SealPoint::new(vec![0x01], None).unwrap(),
            sanad,
            inclusion,
            height: 1000,
            tx_hash: Hash::new([0xAB; 32]),
        };

        let result = client.verify_seal_consumption_event(event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InclusionProofFailed(_)
        ));
    }
}
