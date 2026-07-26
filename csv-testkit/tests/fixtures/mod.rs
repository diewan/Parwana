//! Conformance fixtures binding each Stage 5 adapter to the abstract suite.
//!
//! Each fixture builds an honest closure the way that chain does and exposes
//! the two values the cross-chain tests compare: the nullifier written on chain
//! and the binding stored against it.

use csv_chain_ports::encode_entries;
use csv_hash::Hash;
use csv_protocol::{
    ClosureProof, ClosureProofKind, ClosureTrustMode, ClosureVerificationResult, ConsumedStateRef,
    FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};
use csv_testkit::closure_conformance::{ClosureConformanceAdapter, ClosureScenario};

// ---------------------------------------------------------------- Ethereum --

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, keccak256};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use csv_ethereum::closure::{
    ETHEREUM_CLOSURE_PROOF_KIND, EthereumClosureMaterial, EthereumClosureRegistry,
    expected_binding, storage_value_rlp,
};
use csv_ethereum::closure_verifier::{EthereumClosureVerificationInput, verify_ethereum_closure};

const ETHEREUM_HEIGHT: u64 = 1_000;

/// Ethereum conformance fixture backed by a real Merkle-Patricia trie.
pub struct EthereumFixture {
    registry: EthereumClosureRegistry,
}

impl EthereumFixture {
    pub fn new() -> Self {
        Self {
            registry: EthereumClosureRegistry {
                network_id: "sepolia".into(),
                contract_address: [0xAB; 20],
                mapping_slot: 6,
                deployment_id: "closure-registry-1".into(),
            },
        }
    }

    pub fn nullifier_written(&self, source: &ConsumedStateRef) -> [u8; 32] {
        *SourceNullifier::derive(source).as_bytes()
    }

    pub fn binding(&self, source: &ConsumedStateRef, successor: &Hash) -> Hash {
        expected_binding(&self.registry, source, successor)
    }
}

fn build_trie(entries: &[(B256, Vec<u8>)], target: B256) -> (B256, Vec<Vec<u8>>) {
    let target_nibbles = Nibbles::unpack(target.as_slice());
    let mut builder = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::new(vec![target_nibbles.clone()]));
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in &sorted {
        builder.add_leaf(Nibbles::unpack(key.as_slice()), value);
    }
    let root = builder.root();
    let proof = builder
        .take_proof_nodes()
        .matching_nodes_sorted(&target_nibbles)
        .into_iter()
        .map(|(_, node)| node.to_vec())
        .collect();
    (root, proof)
}

fn account_rlp(storage_root: B256) -> Vec<u8> {
    let code_hash = keccak256([] as [u8; 0]);
    let mut payload = Vec::new();
    alloy_rlp::Encodable::encode(&0u64, &mut payload);
    alloy_rlp::Encodable::encode(&U256::ZERO, &mut payload);
    alloy_rlp::Encodable::encode(&storage_root, &mut payload);
    alloy_rlp::Encodable::encode(&code_hash, &mut payload);

    let mut out = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

impl ClosureConformanceAdapter for EthereumFixture {
    fn chain_id(&self) -> &str {
        "ethereum"
    }

    fn network_id(&self) -> &str {
        &self.registry.network_id
    }

    fn proof_kind(&self) -> ClosureProofKind {
        ClosureProofKind::ChainSpecific(ETHEREUM_CLOSURE_PROOF_KIND.into())
    }

    fn finality_establishing_trust_modes(&self) -> Vec<ClosureTrustMode> {
        // A state proof against a header the caller checked is verifiable under
        // a full node or a light client.
        vec![ClosureTrustMode::FullNode, ClosureTrustMode::LightClient]
    }

    fn build_closure(&self, consumed: &ConsumedStateRef, successor: &Hash) -> ClosureScenario {
        let nullifier = SourceNullifier::derive(consumed);
        let binding = expected_binding(&self.registry, consumed, successor);
        let slot_hash = keccak256(self.registry.storage_key(&nullifier));
        let (storage_root, storage_proof) = build_trie(
            &[
                (slot_hash, storage_value_rlp(&binding)),
                (
                    keccak256([0x99u8; 32]),
                    storage_value_rlp(&Hash::new([0x77; 32])),
                ),
            ],
            slot_hash,
        );

        let account = account_rlp(storage_root);
        let account_key = keccak256(self.registry.contract_address);
        let (state_root, account_proof) = build_trie(
            &[
                (account_key, account.clone()),
                (keccak256([0x55u8; 20]), account),
            ],
            account_key,
        );

        let header = Header {
            state_root,
            number: ETHEREUM_HEIGHT,
            ..Default::default()
        };
        let mut block_header_rlp = Vec::new();
        alloy_rlp::Encodable::encode(&header, &mut block_header_rlp);
        let block_hash = keccak256(&block_header_rlp);

        let material = EthereumClosureMaterial {
            block_header_rlp,
            contract_address: self.registry.contract_address,
            mapping_slot: self.registry.mapping_slot,
            account_proof,
            storage_proof,
        };

        ClosureScenario {
            proof: ClosureProof {
                consumed_state: *consumed,
                successor_commitment: *successor,
                proof_kind: self.proof_kind(),
                proof_material: material.encode(),
            },
            checkpoint: FinalizedCheckpoint {
                chain_id: "ethereum".into(),
                network_id: self.registry.network_id.clone(),
                block_height: ETHEREUM_HEIGHT,
                block_id: block_hash.to_vec(),
                finality_policy: FinalityPolicy::Deterministic("beacon-finalized".into()),
            },
            observed_head: ETHEREUM_HEIGHT,
        }
    }

    fn verify(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
        observed_head: u64,
        trust_mode: ClosureTrustMode,
    ) -> Result<ClosureVerificationResult, String> {
        verify_ethereum_closure(EthereumClosureVerificationInput {
            proof,
            registry: &self.registry,
            checkpoint,
            observed_finalized_height: observed_head,
            max_checkpoint_age: Some(10_000),
            proof_provider_id: "conformance",
            trust_mode,
        })
        .map_err(|error| error.to_string())
    }
}

// --------------------------------------------------------------------- Sui --

use csv_sui::closure::{
    SUI_CLOSURE_PROOF_KIND, SuiCheckpointSummary, SuiClosureDeployment, SuiClosureMaterial,
    SuiClosureRecord, sui_digest,
};
use csv_sui::closure_verifier::{SuiClosureVerificationInput, verify_sui_closure};

const SUI_SEQUENCE: u64 = 900;

/// Sui conformance fixture.
pub struct SuiFixture {
    deployment: SuiClosureDeployment,
}

impl SuiFixture {
    pub fn new() -> Self {
        Self {
            deployment: SuiClosureDeployment {
                network_id: "testnet".into(),
                package_id: [0xAB; 32],
                deployment_id: "closure-package-1".into(),
            },
        }
    }

    pub fn nullifier_written(&self, source: &ConsumedStateRef) -> [u8; 32] {
        *SourceNullifier::derive(source).as_bytes()
    }

    pub fn binding(&self, source: &ConsumedStateRef, successor: &Hash) -> Hash {
        self.deployment.expected_binding(source, successor)
    }
}

impl ClosureConformanceAdapter for SuiFixture {
    fn chain_id(&self) -> &str {
        "sui"
    }

    fn network_id(&self) -> &str {
        &self.deployment.network_id
    }

    fn proof_kind(&self) -> ClosureProofKind {
        ClosureProofKind::ChainSpecific(SUI_CLOSURE_PROOF_KIND.into())
    }

    fn finality_establishing_trust_modes(&self) -> Vec<ClosureTrustMode> {
        vec![ClosureTrustMode::FullNode, ClosureTrustMode::LightClient]
    }

    fn build_closure(&self, consumed: &ConsumedStateRef, successor: &Hash) -> ClosureScenario {
        let record = SuiClosureRecord {
            nullifier: *SourceNullifier::derive(consumed).as_bytes(),
            binding: *self
                .deployment
                .expected_binding(consumed, successor)
                .as_bytes(),
            object_id: [0x11; 32],
            object_version: 4,
            package_id: self.deployment.package_id,
        };
        let contents = vec![[0x22; 32], record.digest(), [0x33; 32]];
        let summary = SuiCheckpointSummary {
            sequence_number: SUI_SEQUENCE,
            epoch: 12,
            content_digest: sui_digest(&encode_entries(&contents)),
        };
        let checkpoint = FinalizedCheckpoint {
            chain_id: "sui".into(),
            network_id: self.deployment.network_id.clone(),
            block_height: SUI_SEQUENCE,
            block_id: summary.digest().to_vec(),
            finality_policy: FinalityPolicy::Deterministic("validator-certified".into()),
        };
        let material = SuiClosureMaterial {
            record,
            checkpoint_contents: contents,
            summary,
        };
        ClosureScenario {
            proof: ClosureProof {
                consumed_state: *consumed,
                successor_commitment: *successor,
                proof_kind: self.proof_kind(),
                proof_material: material.encode(),
            },
            checkpoint,
            observed_head: SUI_SEQUENCE,
        }
    }

    fn verify(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
        observed_head: u64,
        trust_mode: ClosureTrustMode,
    ) -> Result<ClosureVerificationResult, String> {
        verify_sui_closure(SuiClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_certified_sequence: observed_head,
            max_checkpoint_age: Some(10_000),
            proof_provider_id: "conformance",
            trust_mode,
        })
        .map_err(|error| error.to_string())
    }
}

// ------------------------------------------------------------------- Aptos --

use csv_aptos::closure::{
    APTOS_CLOSURE_PROOF_KIND, AptosClosureDeployment, AptosClosureMaterial, AptosClosureRecord,
    AptosLedgerInfo, aptos_digest,
};
use csv_aptos::closure_verifier::{AptosClosureVerificationInput, verify_aptos_closure};

const APTOS_VERSION: u64 = 4_200;

/// Aptos conformance fixture.
pub struct AptosFixture {
    deployment: AptosClosureDeployment,
}

impl AptosFixture {
    pub fn new() -> Self {
        Self {
            deployment: AptosClosureDeployment {
                network_id: "testnet".into(),
                module_address: [0xAB; 32],
                deployment_id: "closure-module-1".into(),
            },
        }
    }

    pub fn nullifier_written(&self, source: &ConsumedStateRef) -> [u8; 32] {
        *SourceNullifier::derive(source).as_bytes()
    }

    pub fn binding(&self, source: &ConsumedStateRef, successor: &Hash) -> Hash {
        self.deployment.expected_binding(source, successor)
    }
}

impl ClosureConformanceAdapter for AptosFixture {
    fn chain_id(&self) -> &str {
        "aptos"
    }

    fn network_id(&self) -> &str {
        &self.deployment.network_id
    }

    fn proof_kind(&self) -> ClosureProofKind {
        ClosureProofKind::ChainSpecific(APTOS_CLOSURE_PROOF_KIND.into())
    }

    fn finality_establishing_trust_modes(&self) -> Vec<ClosureTrustMode> {
        vec![ClosureTrustMode::FullNode, ClosureTrustMode::LightClient]
    }

    fn build_closure(&self, consumed: &ConsumedStateRef, successor: &Hash) -> ClosureScenario {
        let record = AptosClosureRecord {
            nullifier: *SourceNullifier::derive(consumed).as_bytes(),
            binding: *self
                .deployment
                .expected_binding(consumed, successor)
                .as_bytes(),
            module_address: self.deployment.module_address,
            ledger_version: APTOS_VERSION,
        };
        let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
        let ledger_info = AptosLedgerInfo {
            version: APTOS_VERSION,
            epoch: 9,
            accumulator_root: aptos_digest(&encode_entries(&entries)),
        };
        let checkpoint = FinalizedCheckpoint {
            chain_id: "aptos".into(),
            network_id: self.deployment.network_id.clone(),
            block_height: APTOS_VERSION,
            block_id: ledger_info.digest().to_vec(),
            finality_policy: FinalityPolicy::Deterministic("validator-committed".into()),
        };
        let material = AptosClosureMaterial {
            record,
            accumulator_entries: entries,
            ledger_info,
        };
        ClosureScenario {
            proof: ClosureProof {
                consumed_state: *consumed,
                successor_commitment: *successor,
                proof_kind: self.proof_kind(),
                proof_material: material.encode(),
            },
            checkpoint,
            observed_head: APTOS_VERSION,
        }
    }

    fn verify(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
        observed_head: u64,
        trust_mode: ClosureTrustMode,
    ) -> Result<ClosureVerificationResult, String> {
        verify_aptos_closure(AptosClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_committed_version: observed_head,
            max_checkpoint_age: Some(10_000),
            proof_provider_id: "conformance",
            trust_mode,
        })
        .map_err(|error| error.to_string())
    }
}

// ------------------------------------------------------------------ Solana --

use csv_solana::closure::{
    SOLANA_CLOSURE_PROOF_KIND, SolanaBankHash, SolanaClosureDeployment, SolanaClosureMaterial,
    SolanaClosureRecord, solana_digest,
};
use csv_solana::closure_verifier::{SolanaClosureVerificationInput, verify_solana_closure};

const SOLANA_SLOT: u64 = 777;

/// Solana conformance fixture.
pub struct SolanaFixture {
    deployment: SolanaClosureDeployment,
}

impl SolanaFixture {
    pub fn new() -> Self {
        Self {
            deployment: SolanaClosureDeployment {
                network_id: "devnet".into(),
                program_id: [0xAB; 32],
                deployment_id: "closure-program-1".into(),
            },
        }
    }

    pub fn nullifier_written(&self, source: &ConsumedStateRef) -> [u8; 32] {
        *SourceNullifier::derive(source).as_bytes()
    }

    pub fn binding(&self, source: &ConsumedStateRef, successor: &Hash) -> Hash {
        self.deployment.expected_binding(source, successor)
    }
}

impl ClosureConformanceAdapter for SolanaFixture {
    fn chain_id(&self) -> &str {
        "solana"
    }

    fn network_id(&self) -> &str {
        &self.deployment.network_id
    }

    fn proof_kind(&self) -> ClosureProofKind {
        ClosureProofKind::ChainSpecific(SOLANA_CLOSURE_PROOF_KIND.into())
    }

    fn finality_establishing_trust_modes(&self) -> Vec<ClosureTrustMode> {
        // Solana has no light-client construction: only a caller replaying the
        // ledger can establish finality. This narrower declaration is the honest
        // one, and the suite enforces it.
        vec![ClosureTrustMode::FullNode]
    }

    fn build_closure(&self, consumed: &ConsumedStateRef, successor: &Hash) -> ClosureScenario {
        let record = SolanaClosureRecord {
            nullifier: *SourceNullifier::derive(consumed).as_bytes(),
            binding: *self
                .deployment
                .expected_binding(consumed, successor)
                .as_bytes(),
            program_id: self.deployment.program_id,
            slot: SOLANA_SLOT,
        };
        let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
        let bank_hash = SolanaBankHash {
            slot: SOLANA_SLOT,
            entries_digest: solana_digest(&encode_entries(&entries)),
            parent_hash: [0x44; 32],
        };
        let checkpoint = FinalizedCheckpoint {
            chain_id: "solana".into(),
            network_id: self.deployment.network_id.clone(),
            block_height: SOLANA_SLOT,
            block_id: bank_hash.digest().to_vec(),
            finality_policy: FinalityPolicy::Deterministic("rooted-slot".into()),
        };
        let material = SolanaClosureMaterial {
            record,
            slot_entries: entries,
            bank_hash,
        };
        ClosureScenario {
            proof: ClosureProof {
                consumed_state: *consumed,
                successor_commitment: *successor,
                proof_kind: self.proof_kind(),
                proof_material: material.encode(),
            },
            checkpoint,
            observed_head: SOLANA_SLOT,
        }
    }

    fn verify(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
        observed_head: u64,
        trust_mode: ClosureTrustMode,
    ) -> Result<ClosureVerificationResult, String> {
        verify_solana_closure(SolanaClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_rooted_slot: observed_head,
            max_checkpoint_age: Some(10_000),
            proof_provider_id: "conformance",
            trust_mode,
        })
        .map_err(|error| error.to_string())
    }
}
