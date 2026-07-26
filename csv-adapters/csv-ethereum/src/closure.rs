//! Ethereum nullifier closure: derivation, submission, and proof framing.
//!
//! Source closure on Ethereum is a **storage fact**: a registry contract maps
//! one portable [`SourceNullifier`] to the binding of the successor it was
//! closed in favour of. A recipient proves that fact with a Merkle-Patricia
//! storage proof against a finalized state root, so nothing is taken on the
//! submitter's word.
//!
//! # What makes the closure unique
//!
//! The key written on chain is [`SourceNullifier`], which is derived from the
//! consumed state alone and is therefore *the same value on every chain*. The
//! value written is [`csv_protocol::ClosureDomain::binding`], which commits to
//! the nullifier, the successor, and this exact deployment. That split is the
//! whole design:
//!
//! - one key per source ⇒ a second successor of the same source cannot be
//!   written here, and collides with the first wherever else it is presented;
//! - a deployment-bound value ⇒ a proof from one chain, contract, network, or
//!   deployment cannot be replayed as a proof for another.
//!
//! A registry that stores only a boolean cannot serve this role: it records
//! *that* a nullifier was used but not *which* successor it selected, so it
//! cannot distinguish the honest successor from an equivocating one. The
//! registry contract this adapter verifies against therefore stores
//! `mapping(bytes32 nullifier => bytes32 binding)` and writes only into an empty
//! slot. See [`EthereumClosureRegistry`] for the configuration and
//! `docs/closure-registry.md` for the required contract behaviour.

use alloy_primitives::{B256, U256, keccak256};
use csv_chain_ports::{ClosureMaterialError, ClosureMaterialReader, ClosureMaterialWriter};
use csv_hash::Hash;
use csv_protocol::{ClosureDomain, ClosureProofKind, ConsumedStateRef, SourceNullifier};
use serde::{Deserialize, Serialize};

/// Stable chain identifier used by this adapter.
pub const ETHEREUM_CHAIN_ID: &str = "ethereum";
/// Stable proof-family name for Ethereum nullifier storage closure.
pub const ETHEREUM_CLOSURE_PROOF_KIND: &str = "ethereum-nullifier-storage-v1";
/// Stable identifier of this adapter's closure verifier.
pub const ETHEREUM_CLOSURE_VERIFIER_ID: &str = "parwana.csv-ethereum.closure.v2";
/// Encoding version of this adapter's closure proof material.
pub const ETHEREUM_CLOSURE_MATERIAL_VERSION: u16 = 1;

/// Solidity selector for `register_closure(bytes32,bytes32)`.
///
/// Recomputed rather than hard-coded so a rename cannot silently keep a stale
/// four-byte constant that targets a different function.
pub fn register_closure_selector() -> [u8; 4] {
    let hash = keccak256(b"register_closure(bytes32,bytes32)");
    [hash[0], hash[1], hash[2], hash[3]]
}

/// A configured closure registry deployment.
///
/// `mapping_slot` is the declaration index of the
/// `mapping(bytes32 => bytes32)` that holds nullifier bindings. It is
/// configuration rather than a constant because the storage layout belongs to
/// the deployed contract, not to this crate: pinning it here would silently
/// misverify against any registry whose layout differs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumClosureRegistry {
    /// Network identifier, such as `sepolia`.
    pub network_id: String,
    /// Registry contract address.
    pub contract_address: [u8; 20],
    /// Declaration index of the nullifier→binding mapping.
    pub mapping_slot: u64,
    /// Deployment identity distinguishing two instances of the same code.
    pub deployment_id: String,
}

impl EthereumClosureRegistry {
    /// The protocol-level destination domain this registry represents.
    pub fn closure_domain(&self) -> ClosureDomain {
        ClosureDomain {
            chain_id: ETHEREUM_CHAIN_ID.to_string(),
            network_id: self.network_id.clone(),
            contract_id: self.contract_address.to_vec(),
            deployment_id: self.deployment_id.clone(),
            proof_kind: ClosureProofKind::ChainSpecific(ETHEREUM_CLOSURE_PROOF_KIND.to_string()),
        }
    }

    /// Storage key of `mapping[nullifier]` under Solidity's layout rules:
    /// `keccak256(key ++ slot)`, both left-padded to 32 bytes.
    pub fn storage_key(&self, nullifier: &SourceNullifier) -> [u8; 32] {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(nullifier.as_bytes());
        preimage[56..64].copy_from_slice(&self.mapping_slot.to_be_bytes());
        keccak256(preimage).0
    }

    /// Calldata that registers one closure, for submission by the sender.
    ///
    /// Deterministic for the same source, successor, and registry, so a retry
    /// resubmits the identical call rather than racing a second, conflicting
    /// one.
    pub fn register_closure_calldata(
        &self,
        consumed_state: &ConsumedStateRef,
        successor_commitment: &Hash,
    ) -> Vec<u8> {
        let nullifier = SourceNullifier::derive(consumed_state);
        let binding = self
            .closure_domain()
            .binding(&nullifier, successor_commitment);
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&register_closure_selector());
        calldata.extend_from_slice(nullifier.as_bytes());
        calldata.extend_from_slice(binding.as_bytes());
        calldata
    }
}

/// Chain-native material a recipient needs to verify one Ethereum closure.
///
/// The block header is carried in full rather than a bare state root: the
/// verifier re-derives both the block hash and the state root from it, so the
/// checkpoint the result cites is the one the proof was actually checked
/// against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthereumClosureMaterial {
    /// RLP-encoded header of the checkpoint block.
    pub block_header_rlp: Vec<u8>,
    /// Registry contract the proof addresses.
    pub contract_address: [u8; 20],
    /// Mapping slot the proof addresses.
    pub mapping_slot: u64,
    /// Account proof from the state root to the registry account.
    pub account_proof: Vec<Vec<u8>>,
    /// Storage proof from the account's storage root to the binding slot.
    pub storage_proof: Vec<Vec<u8>>,
}

impl EthereumClosureMaterial {
    /// Encode to canonical, deterministic proof-material bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = ClosureMaterialWriter::new(ETHEREUM_CLOSURE_MATERIAL_VERSION);
        writer.put_bytes(&self.block_header_rlp);
        writer.put_fixed(&self.contract_address);
        writer.put_u64(self.mapping_slot);
        writer.put_byte_vectors(self.account_proof.iter().map(Vec::as_slice));
        writer.put_byte_vectors(self.storage_proof.iter().map(Vec::as_slice));
        writer.finish()
    }

    /// Decode canonical proof-material bytes, failing closed on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClosureMaterialError> {
        let mut reader = ClosureMaterialReader::new(bytes, ETHEREUM_CLOSURE_MATERIAL_VERSION)?;
        let block_header_rlp = reader.take_bytes()?.to_vec();
        let contract_address = reader.take_fixed::<20>()?;
        let mapping_slot = reader.take_u64()?;
        let account_proof = reader
            .take_byte_vectors()?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let storage_proof = reader
            .take_byte_vectors()?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        reader.finish()?;
        Ok(Self {
            block_header_rlp,
            contract_address,
            mapping_slot,
            account_proof,
            storage_proof,
        })
    }
}

/// The RLP encoding of a 32-byte storage value, as stored in the storage trie.
///
/// Ethereum stores storage values RLP-encoded with leading zero bytes stripped,
/// **not** as fixed 32-byte words. Comparing against a zero-padded word makes
/// every real proof fail, so the encoding happens here once and is tested
/// against the stripped form.
pub fn storage_value_rlp(value: &Hash) -> Vec<u8> {
    let word = U256::from_be_bytes(*value.as_bytes());
    alloy_rlp::encode(word)
}

/// The storage value a valid closure must hold: the domain binding.
pub fn expected_binding(
    registry: &EthereumClosureRegistry,
    consumed_state: &ConsumedStateRef,
    successor_commitment: &Hash,
) -> Hash {
    let nullifier = SourceNullifier::derive(consumed_state);
    registry
        .closure_domain()
        .binding(&nullifier, successor_commitment)
}

/// Re-derive the block hash and state root from an RLP header.
///
/// Returns `None` if the header does not decode. The caller must check the
/// derived hash against the checkpoint rather than trusting either separately.
pub fn header_identity(block_header_rlp: &[u8]) -> Option<HeaderIdentity> {
    use alloy_rlp::Decodable;
    let header = alloy_consensus::Header::decode(&mut &block_header_rlp[..]).ok()?;
    Some(HeaderIdentity {
        block_hash: keccak256(block_header_rlp).0,
        state_root: header.state_root,
        block_height: header.number,
    })
}

/// Identity re-derived from a block header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderIdentity {
    /// `keccak256` of the RLP header.
    pub block_hash: [u8; 32],
    /// State root committed by the header.
    pub state_root: B256,
    /// Height committed by the header.
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: u16 = 7;

    fn registry() -> EthereumClosureRegistry {
        EthereumClosureRegistry {
            network_id: "sepolia".into(),
            contract_address: [0xAB; 20],
            mapping_slot: 6,
            deployment_id: "closure-registry-1".into(),
        }
    }

    fn source() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
    }

    fn material() -> EthereumClosureMaterial {
        EthereumClosureMaterial {
            block_header_rlp: vec![0xF9, 0x02, 0x1A],
            contract_address: [0xAB; 20],
            mapping_slot: 6,
            account_proof: vec![vec![1, 2, 3], vec![4]],
            storage_proof: vec![vec![5, 6]],
        }
    }

    #[test]
    fn storage_key_follows_solidity_mapping_layout() {
        // keccak256(key ++ slot), both 32-byte left-padded.
        let registry = registry();
        let nullifier = SourceNullifier::derive(&source());
        let mut expected_preimage = [0u8; 64];
        expected_preimage[..32].copy_from_slice(nullifier.as_bytes());
        expected_preimage[63] = 6;
        assert_eq!(
            registry.storage_key(&nullifier),
            keccak256(expected_preimage).0
        );
    }

    #[test]
    fn storage_key_changes_with_slot_and_source() {
        let registry = registry();
        let nullifier = SourceNullifier::derive(&source());
        let baseline = registry.storage_key(&nullifier);

        let mut other_slot = registry.clone();
        other_slot.mapping_slot = 7;
        assert_ne!(other_slot.storage_key(&nullifier), baseline);

        let mut other_source = source();
        other_source.output_index += 1;
        assert_ne!(
            registry.storage_key(&SourceNullifier::derive(&other_source)),
            baseline
        );
    }

    #[test]
    fn storage_value_rlp_strips_leading_zeros() {
        // The trie stores RLP(minimal big-endian), not a zero-padded word.
        // Getting this wrong makes every genuine proof fail to verify.
        let mut small = [0u8; 32];
        small[31] = 1;
        assert_eq!(storage_value_rlp(&Hash::new(small)), vec![0x01]);

        let full = Hash::new([0xAB; 32]);
        let encoded = storage_value_rlp(&full);
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[0], 0xA0);
        assert_eq!(&encoded[1..], &[0xAB; 32]);
    }

    #[test]
    fn calldata_binds_nullifier_and_binding_and_is_deterministic() {
        let registry = registry();
        let successor = Hash::new([5; 32]);
        let calldata = registry.register_closure_calldata(&source(), &successor);
        assert_eq!(calldata.len(), 68);
        assert_eq!(&calldata[..4], &register_closure_selector());

        let nullifier = SourceNullifier::derive(&source());
        assert_eq!(&calldata[4..36], nullifier.as_bytes());
        let binding = registry.closure_domain().binding(&nullifier, &successor);
        assert_eq!(&calldata[36..68], binding.as_bytes());

        assert_eq!(
            calldata,
            registry.register_closure_calldata(&source(), &successor)
        );
    }

    #[test]
    fn calldata_changes_when_the_successor_changes() {
        let registry = registry();
        assert_ne!(
            registry.register_closure_calldata(&source(), &Hash::new([5; 32])),
            registry.register_closure_calldata(&source(), &Hash::new([6; 32]))
        );
    }

    #[test]
    fn nullifier_key_is_identical_across_deployments_but_binding_is_not() {
        // The load-bearing cross-chain property, at the adapter boundary.
        let first = registry();
        let mut second = registry();
        second.network_id = "mainnet".into();
        second.contract_address = [0xCD; 20];
        second.deployment_id = "closure-registry-2".into();

        let nullifier = SourceNullifier::derive(&source());
        let successor = Hash::new([5; 32]);

        // Same conflict identity...
        assert_eq!(
            SourceNullifier::derive(&source()).as_bytes(),
            nullifier.as_bytes()
        );
        // ...but no proof can move between deployments.
        assert_ne!(
            first.closure_domain().binding(&nullifier, &successor),
            second.closure_domain().binding(&nullifier, &successor)
        );
    }

    #[test]
    fn material_round_trips_and_is_deterministic() {
        let material = material();
        let encoded = material.encode();
        assert_eq!(EthereumClosureMaterial::decode(&encoded).unwrap(), material);
        assert_eq!(encoded, material.encode());
    }

    #[test]
    fn material_rejects_truncation_and_trailing_bytes() {
        let encoded = material().encode();
        for cut in 2..encoded.len() {
            assert!(
                EthereumClosureMaterial::decode(&encoded[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(EthereumClosureMaterial::decode(&extended).is_err());
    }

    #[test]
    fn material_rejects_a_foreign_version() {
        let mut encoded = material().encode();
        encoded[0] = 0xFE;
        assert!(matches!(
            EthereumClosureMaterial::decode(&encoded),
            Err(ClosureMaterialError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_malformed_header_yields_no_identity() {
        assert!(header_identity(&[0xFF, 0x00]).is_none());
        assert!(header_identity(&[]).is_none());
    }
}
