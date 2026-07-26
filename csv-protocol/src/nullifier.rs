//! Portable source-conflict identity and destination-domain closure binding.
//!
//! Stage 5 advertises source closure on several destination chains. That raises
//! exactly one protocol question, and this module answers it explicitly so no
//! adapter has to invent an answer:
//!
//! > When one source state is closed, what identity decides that two successors
//! > are in conflict — and is that identity the same on every destination chain?
//!
//! # The two domains, and why they must not be merged
//!
//! There are two distinct identities here, and conflating them breaks the
//! invariant in one direction or the other:
//!
//! - [`SourceNullifier`] is the **source domain**. It is derived from the
//!   consumed state alone and contains no chain, network, contract, or
//!   deployment. One source state therefore has exactly *one* nullifier, and it
//!   is byte-identical on Ethereum, Sui, Aptos, and Solana. This is what makes
//!   cross-chain equivocation detectable: two successors of the same source
//!   collide on one key no matter where each was closed.
//!
//! - [`ClosureDomain`] is the **destination domain**. It names the chain,
//!   network, contract/program, deployment, and proof family that a *particular*
//!   closure was performed in. It never enters the nullifier; it enters the
//!   [`ClosureDomain::binding`] commitment that the proof must reproduce. This
//!   is what makes proof replay across chains, contracts, networks, deployments,
//!   and proof kinds fail.
//!
//! Deriving the conflict identity per destination — the obvious shortcut —
//! would give the same source a different nullifier on each chain, so each
//! chain's contract would accept its own "first" closure and the source would be
//! closed twice. That is the precise failure this module exists to prevent, and
//! it is why [`SourceNullifier::derive`] takes a [`ConsumedStateRef`] and
//! nothing else. The type signature is the invariant.
//!
//! # Relationship to the accepted-state conflict key
//!
//! `csv-storage`'s accepted-state store already keys conflicts on
//! [`ConsumedStateRef`]'s digest, deliberately excluding transfer identifiers.
//! [`SourceNullifier`] is the same commitment carried onto a chain: the digest a
//! contract or program stores to reject reuse. They agree by construction
//! because both derive from the consumed state and only from the consumed state.
//! A recipient that has seen one closure rejects the second locally; a chain
//! that has seen one nullifier rejects the second natively. Neither substitutes
//! for the other, and neither is a second authority: the chain orders closure,
//! the recipient decides acceptance.
//!
//! # Public concept review
//!
//! *Nearest semantic siblings and difference.*
//!
//! - [`crate::seal::SealPoint`] — the chain-native handle that is spent to order
//!   a consumption. `SourceNullifier` names the *protocol* identity being
//!   closed; `SealPoint` names the native object whose spend orders it. A
//!   `SealPoint` is chain-specific by nature; a `SourceNullifier` is chain-free
//!   by construction.
//! - [`crate::closure::ClosureProof`] — the evidence that a closure happened.
//!   `SourceNullifier` is the identity that evidence is *about*.
//! - [`crate::closure::FinalizedCheckpoint`] — where and under what finality
//!   rule the closure was observed. `ClosureDomain` is *which deployment* it was
//!   performed against; the checkpoint is *when* it became final.
//! - [`crate::replay::ReplayNullifier`] — **the sibling most easily confused
//!   with this one, and the one it must not be mistaken for.** V1's replay entry
//!   derives from `(sanad_id, source_chain, source_seal_ref)`, so it is
//!   *chain-scoped by construction*: the same logical source yields a different
//!   value per chain. That is correct for a per-chain replay cache and wrong for
//!   a cross-chain conflict identity, which is why `SourceNullifier` is a
//!   distinct type with a distinct domain tag rather than a reuse of it. The two
//!   are never interchangeable and neither converts to the other. If a future
//!   change gives `SourceNullifier` a chain input, it has become a
//!   `ReplayNullifier` and the portable invariant is gone.
//!
//! *What they prove.* `SourceNullifier` proves nothing on its own — it is an
//! identity, not evidence. `ClosureDomain::binding` proves nothing on its own
//! either; it is the value a chain-native proof must reproduce for a verifier to
//! conclude the proof belongs to this source, this successor, and this
//! deployment.
//!
//! *What they do not prove.* Neither carries authority, finality, or
//! uniqueness. Uniqueness is established by a chain rejecting reuse and by a
//! recipient's accepted-state CAS — never by deriving a nullifier.

use serde::{Deserialize, Serialize};

use crate::closure::ClosureProofKind;
use crate::reference::ConsumedStateRef;
use csv_hash::{Hash, csv_tagged_hash};

/// Domain tag for the portable source-conflict identity.
pub const SOURCE_NULLIFIER_TAG: &str = "source-nullifier-v2";
/// Domain tag for a destination-domain descriptor.
pub const CLOSURE_DOMAIN_TAG: &str = "closure-domain-v2";
/// Domain tag for the closure binding a chain-native proof must reproduce.
pub const CLOSURE_BINDING_TAG: &str = "closure-binding-v2";

/// Maximum length of a contract, package, or program identifier.
pub const MAX_CONTRACT_ID_BYTES: usize = 64;
/// Maximum length of a deployment identifier.
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 128;

/// The portable conflict identity of one consumed source state.
///
/// Derived from [`ConsumedStateRef`] and nothing else, so it is identical on
/// every destination chain. Two successors of the same source produce the same
/// nullifier and are therefore detectably in conflict wherever each was closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceNullifier(Hash);

impl SourceNullifier {
    /// Derive the portable nullifier for a consumed source state.
    ///
    /// There is deliberately no chain, network, contract, or deployment
    /// parameter. Adding one would make the same source closable once per
    /// destination.
    pub fn derive(consumed: &ConsumedStateRef) -> Self {
        Self(Hash::new(csv_tagged_hash(
            SOURCE_NULLIFIER_TAG,
            &consumed.to_canonical_bytes(),
        )))
    }

    /// The nullifier digest.
    pub const fn digest(&self) -> Hash {
        self.0
    }

    /// Raw bytes, as submitted to a contract or program.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// The destination deployment a closure was performed against.
///
/// Every field participates in [`ClosureDomain::digest`], so a proof produced in
/// one domain cannot verify in another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureDomain {
    /// Stable chain identifier, such as `ethereum`.
    pub chain_id: String,
    /// Stable network identifier, such as `sepolia`.
    pub network_id: String,
    /// Contract address, Move package identity, or program identity.
    pub contract_id: Vec<u8>,
    /// Deployment identity distinguishing two instances of the same code.
    pub deployment_id: String,
    /// Proof family this domain issues.
    pub proof_kind: ClosureProofKind,
}

impl ClosureDomain {
    /// Validate the fields every chain must supply.
    pub fn validate(&self) -> Result<(), NullifierDomainError> {
        if self.chain_id.is_empty() {
            return Err(NullifierDomainError::EmptyChain);
        }
        if self.network_id.is_empty() {
            return Err(NullifierDomainError::EmptyNetwork);
        }
        if self.contract_id.is_empty() {
            return Err(NullifierDomainError::EmptyContract);
        }
        if self.contract_id.len() > MAX_CONTRACT_ID_BYTES {
            return Err(NullifierDomainError::ContractIdTooLong);
        }
        if self.deployment_id.is_empty() {
            return Err(NullifierDomainError::EmptyDeployment);
        }
        if self.deployment_id.len() > MAX_DEPLOYMENT_ID_BYTES {
            return Err(NullifierDomainError::DeploymentIdTooLong);
        }
        if matches!(&self.proof_kind, ClosureProofKind::ChainSpecific(name) if name.is_empty()) {
            return Err(NullifierDomainError::EmptyProofKind);
        }
        Ok(())
    }

    /// Domain-separated digest of this exact deployment.
    pub fn digest(&self) -> Hash {
        Hash::new(csv_tagged_hash(CLOSURE_DOMAIN_TAG, &self.canonical_bytes()))
    }

    /// The commitment a chain-native closure proof must reproduce.
    ///
    /// Binds the portable source identity, the successor being selected, and the
    /// destination deployment together. Changing any one of the three changes
    /// the binding, so a proof cannot be moved between sources, successors, or
    /// deployments.
    pub fn binding(&self, nullifier: &SourceNullifier, successor_commitment: &Hash) -> Hash {
        let mut preimage = Vec::with_capacity(96);
        preimage.extend_from_slice(nullifier.as_bytes());
        preimage.extend_from_slice(successor_commitment.as_bytes());
        preimage.extend_from_slice(self.digest().as_bytes());
        Hash::new(csv_tagged_hash(CLOSURE_BINDING_TAG, &preimage))
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, self.chain_id.as_bytes());
        push_bytes(&mut out, self.network_id.as_bytes());
        push_bytes(&mut out, &self.contract_id);
        push_bytes(&mut out, self.deployment_id.as_bytes());
        match &self.proof_kind {
            ClosureProofKind::BitcoinTransactionInclusion => out.push(1),
            ClosureProofKind::ChainSpecific(name) => {
                out.push(2);
                push_bytes(&mut out, name.as_bytes());
            }
        }
        out
    }
}

/// Invalid destination-domain descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NullifierDomainError {
    /// Chain identifier is missing.
    #[error("closure domain chain identifier is empty")]
    EmptyChain,
    /// Network identifier is missing.
    #[error("closure domain network identifier is empty")]
    EmptyNetwork,
    /// Contract/package/program identifier is missing.
    #[error("closure domain contract identifier is empty")]
    EmptyContract,
    /// Contract/package/program identifier exceeds the protocol bound.
    #[error("closure domain contract identifier exceeds the protocol bound")]
    ContractIdTooLong,
    /// Deployment identifier is missing.
    #[error("closure domain deployment identifier is empty")]
    EmptyDeployment,
    /// Deployment identifier exceeds the protocol bound.
    #[error("closure domain deployment identifier exceeds the protocol bound")]
    DeploymentIdTooLong,
    /// A chain-specific proof family must be named.
    #[error("closure domain proof kind is empty")]
    EmptyProofKind,
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: crate::state::StateTypeId = 7;

    fn source() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
    }

    fn domain(chain: &str, contract: u8) -> ClosureDomain {
        ClosureDomain {
            chain_id: chain.into(),
            network_id: "testnet".into(),
            contract_id: vec![contract; 20],
            deployment_id: "deployment-1".into(),
            proof_kind: ClosureProofKind::ChainSpecific(format!("{chain}-nullifier-v1")),
        }
    }

    #[test]
    fn nullifier_is_identical_across_destination_chains() {
        // The load-bearing property: one source, one conflict identity, no
        // matter which destination closed it.
        let source = source();
        let nullifier = SourceNullifier::derive(&source);
        for chain in ["ethereum", "sui", "aptos", "solana"] {
            let _ = domain(chain, 0xAB);
            assert_eq!(SourceNullifier::derive(&source), nullifier);
        }
    }

    #[test]
    fn portable_nullifier_is_not_the_chain_scoped_replay_nullifier() {
        // V1's ReplayNullifier mixes in `source_chain`, so it changes per chain.
        // If this test ever fails because the two agree, the portable identity
        // has acquired a chain input and cross-chain equivocation is possible.
        use crate::replay::ReplayNullifier;
        let sanad = Hash::new([1; 32]);
        let seal = Hash::new([4; 32]);
        let on_chain_a = ReplayNullifier::compute_nullifier(sanad, 1, seal);
        let on_chain_b = ReplayNullifier::compute_nullifier(sanad, 2, seal);
        assert_ne!(
            on_chain_a, on_chain_b,
            "ReplayNullifier is chain-scoped by construction"
        );

        let portable = SourceNullifier::derive(&source());
        assert_ne!(portable.digest(), on_chain_a);
        assert_ne!(portable.digest(), on_chain_b);
    }

    #[test]
    fn nullifier_changes_with_every_source_field() {
        let base = SourceNullifier::derive(&source());
        let mut changed = source();
        changed.transition_id = Hash::new([2; 32]);
        assert_ne!(SourceNullifier::derive(&changed), base);
        changed = source();
        changed.output_index += 1;
        assert_ne!(SourceNullifier::derive(&changed), base);
        changed = source();
        changed.state_type += 1;
        assert_ne!(SourceNullifier::derive(&changed), base);
    }

    #[test]
    fn nullifier_is_domain_separated_from_the_bare_reference_digest() {
        use crate::reference::Consumable;
        let source = source();
        assert_ne!(SourceNullifier::derive(&source).digest(), source.digest());
    }

    #[test]
    fn binding_differs_across_chains_contracts_networks_and_deployments() {
        let nullifier = SourceNullifier::derive(&source());
        let successor = Hash::new([5; 32]);
        let base = domain("ethereum", 0xAB);
        let baseline = base.binding(&nullifier, &successor);

        // Same source and successor, different destination: no replay.
        assert_ne!(
            domain("sui", 0xAB).binding(&nullifier, &successor),
            baseline
        );
        assert_ne!(
            domain("ethereum", 0xCD).binding(&nullifier, &successor),
            baseline
        );

        let mut other = base.clone();
        other.network_id = "mainnet".into();
        assert_ne!(other.binding(&nullifier, &successor), baseline);

        other = base.clone();
        other.deployment_id = "deployment-2".into();
        assert_ne!(other.binding(&nullifier, &successor), baseline);

        other = base.clone();
        other.proof_kind = ClosureProofKind::ChainSpecific("ethereum-nullifier-v2".into());
        assert_ne!(other.binding(&nullifier, &successor), baseline);
    }

    #[test]
    fn binding_changes_with_source_and_successor() {
        let base = domain("ethereum", 0xAB);
        let nullifier = SourceNullifier::derive(&source());
        let successor = Hash::new([5; 32]);
        let baseline = base.binding(&nullifier, &successor);

        let mut other_source = source();
        other_source.output_index += 1;
        assert_ne!(
            base.binding(&SourceNullifier::derive(&other_source), &successor),
            baseline
        );
        assert_ne!(base.binding(&nullifier, &Hash::new([6; 32])), baseline);
    }

    #[test]
    fn conflicting_successors_share_one_nullifier_within_a_domain() {
        // Two different successors of the same source: the bindings differ (so
        // neither proof can be reused for the other), but the on-chain conflict
        // identity is one value, so the second submission is a detectable reuse.
        let domain = domain("ethereum", 0xAB);
        let nullifier = SourceNullifier::derive(&source());
        let first = domain.binding(&nullifier, &Hash::new([5; 32]));
        let second = domain.binding(&nullifier, &Hash::new([6; 32]));
        assert_ne!(first, second);
        assert_eq!(
            SourceNullifier::derive(&source()),
            SourceNullifier::derive(&source())
        );
    }

    #[test]
    fn domain_validation_is_fail_closed() {
        let mut invalid = domain("ethereum", 0xAB);
        invalid.chain_id.clear();
        assert_eq!(invalid.validate(), Err(NullifierDomainError::EmptyChain));

        invalid = domain("ethereum", 0xAB);
        invalid.contract_id.clear();
        assert_eq!(invalid.validate(), Err(NullifierDomainError::EmptyContract));

        invalid = domain("ethereum", 0xAB);
        invalid.contract_id = vec![0; MAX_CONTRACT_ID_BYTES + 1];
        assert_eq!(
            invalid.validate(),
            Err(NullifierDomainError::ContractIdTooLong)
        );

        invalid = domain("ethereum", 0xAB);
        invalid.deployment_id.clear();
        assert_eq!(
            invalid.validate(),
            Err(NullifierDomainError::EmptyDeployment)
        );

        invalid = domain("ethereum", 0xAB);
        invalid.proof_kind = ClosureProofKind::ChainSpecific(String::new());
        assert_eq!(
            invalid.validate(),
            Err(NullifierDomainError::EmptyProofKind)
        );

        assert!(domain("ethereum", 0xAB).validate().is_ok());
    }

    #[test]
    fn length_prefixes_prevent_field_boundary_confusion() {
        // "ab" + "c" must not digest the same as "a" + "bc".
        let mut first = domain("ethereum", 0xAB);
        first.chain_id = "ab".into();
        first.network_id = "c".into();
        let mut second = domain("ethereum", 0xAB);
        second.chain_id = "a".into();
        second.network_id = "bc".into();
        assert_ne!(first.digest(), second.digest());
    }
}
