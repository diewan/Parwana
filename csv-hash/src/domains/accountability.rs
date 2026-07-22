//! Reserved Accountability Profile hash domains.

use crate::Domain;

macro_rules! accountability_domain {
    ($name:ident, $tag:literal, $description:literal) => {
        #[doc = $description]
        pub struct $name;

        impl Domain for $name {
            const DOMAIN: &'static [u8] = $tag;
        }
    };
}

accountability_domain!(
    ActionIntentDomain,
    b"csv.accountability.intent.v1",
    "Action-intent content domain."
);
accountability_domain!(
    ActionMandateDomain,
    b"csv.accountability.mandate.v1",
    "Action-mandate content domain."
);
accountability_domain!(
    ExecutionAttemptDomain,
    b"csv.accountability.attempt.v1",
    "Execution-attempt content domain."
);
accountability_domain!(
    ExecutionReceiptDomain,
    b"csv.accountability.receipt.v1",
    "Execution-receipt content domain."
);
accountability_domain!(
    EvidenceNodeDomain,
    b"csv.accountability.evidence.v1",
    "Evidence-node content domain."
);
accountability_domain!(
    DisputeBundleDomain,
    b"csv.accountability.bundle.v1",
    "Dispute-bundle manifest domain."
);
accountability_domain!(
    VerificationContextDomain,
    b"csv.accountability.verification-context.v1",
    "Verification-context content domain."
);
accountability_domain!(
    AssuranceProfileDomain,
    b"csv.accountability.assurance-profile.v1",
    "Assurance-profile content domain."
);
accountability_domain!(
    GateProfileDomain,
    b"csv.accountability.gate-profile.v1",
    "Gate-profile content domain."
);
accountability_domain!(
    DisclosureCommitmentDomain,
    b"csv.accountability.disclosure.v1",
    "Selective-disclosure commitment domain."
);
accountability_domain!(
    PreservationEnvelopeDomain,
    b"csv.accountability.preservation.v1",
    "Reserved preservation-envelope domain."
);
accountability_domain!(
    AuthorityReconstructionDomain,
    b"csv.accountability.authority-reconstruction.v1",
    "Historical authority-reconstruction content domain."
);

/// Complete v0.1 domain registry used by collision audits.
pub const ACCOUNTABILITY_DOMAIN_TAGS: &[&[u8]] = &[
    ActionIntentDomain::DOMAIN,
    ActionMandateDomain::DOMAIN,
    ExecutionAttemptDomain::DOMAIN,
    ExecutionReceiptDomain::DOMAIN,
    EvidenceNodeDomain::DOMAIN,
    DisputeBundleDomain::DOMAIN,
    VerificationContextDomain::DOMAIN,
    AssuranceProfileDomain::DOMAIN,
    GateProfileDomain::DOMAIN,
    DisclosureCommitmentDomain::DOMAIN,
    PreservationEnvelopeDomain::DOMAIN,
    AuthorityReconstructionDomain::DOMAIN,
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        AptosAnchorDomain, BitcoinSealDomain, DomainSeparatedHash, EthereumMintDomain,
        GenesisDomain, ProofBundleDomain, ReplayRegistryDomain, SanadIdDomain, SchemaDomain,
        TransferCommitmentDomain, TransitionDomain, tagged_hash_str,
    };

    #[test]
    fn accountability_domains_are_unique_and_well_formed() {
        let unique: HashSet<_> = ACCOUNTABILITY_DOMAIN_TAGS.iter().copied().collect();
        assert_eq!(unique.len(), ACCOUNTABILITY_DOMAIN_TAGS.len());
        for tag in ACCOUNTABILITY_DOMAIN_TAGS {
            let text = core::str::from_utf8(tag).expect("registered tags are ASCII");
            assert!(text.starts_with("csv.accountability."));
            assert!(text.ends_with(".v1"));
        }
    }

    #[test]
    fn accountability_domains_do_not_collide_with_existing_registry() {
        let existing: &[&[u8]] = &[
            AptosAnchorDomain::DOMAIN,
            BitcoinSealDomain::DOMAIN,
            EthereumMintDomain::DOMAIN,
            GenesisDomain::DOMAIN,
            ProofBundleDomain::DOMAIN,
            ReplayRegistryDomain::DOMAIN,
            SanadIdDomain::DOMAIN,
            SchemaDomain::DOMAIN,
            TransferCommitmentDomain::DOMAIN,
            TransitionDomain::DOMAIN,
        ];
        let mut unique: HashSet<&[u8]> = existing.iter().copied().collect();
        assert_eq!(unique.len(), existing.len());
        for tag in ACCOUNTABILITY_DOMAIN_TAGS {
            assert!(unique.insert(tag), "duplicate registered domain tag");
        }
    }

    #[test]
    fn same_payload_is_separated_across_every_accountability_domain() {
        let payload = b"diewan-accountability-vector-v1";
        let hashes: HashSet<_> = ACCOUNTABILITY_DOMAIN_TAGS
            .iter()
            .map(|tag| {
                let text = core::str::from_utf8(tag).expect("registered tags are ASCII");
                tagged_hash_str(&format!("urn:lnp-bp:csv:{text}"), payload)
            })
            .collect();
        assert_eq!(hashes.len(), ACCOUNTABILITY_DOMAIN_TAGS.len());
    }

    #[test]
    fn deterministic_domain_vectors_are_stable() {
        let payload = b"diewan-accountability-vector-v1";
        let vectors = [
            (
                DomainSeparatedHash::<ActionIntentDomain>::hash(payload),
                "52799357ccb6959bd550b7322842aafad40549e0b4e987022de3fb7bfdec426e",
            ),
            (
                DomainSeparatedHash::<ActionMandateDomain>::hash(payload),
                "3cb63104ebdb3a2f3d1f04c011907e74e845ba27f5ac7fedc6bced548571b25e",
            ),
            (
                DomainSeparatedHash::<ExecutionReceiptDomain>::hash(payload),
                "0141f4f84d432249c487a2207a34056a6bc752ab1bd93243fcce7c37025d5e1f",
            ),
            (
                DomainSeparatedHash::<DisputeBundleDomain>::hash(payload),
                "7ec1185501552761a84ecc6266a104c81e33e9e967b297e574514311463553d1",
            ),
            (
                DomainSeparatedHash::<VerificationContextDomain>::hash(payload),
                "e4b77dc5ebfe90af1e52f637bfbf078cabfcaf3d6f61c3a099b8c6a09769eb77",
            ),
        ];
        for (actual, expected) in vectors {
            assert_eq!(actual.to_hex(), expected);
        }
    }
}
