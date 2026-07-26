//! Protocol verification-assurance domains (PAR-VERIFY-001).
//!
//! A verifier report must echo the digest of the effective verification context
//! it ran under, so two verifiers can prove they evaluated the same rules and
//! inputs. These domains separate that digest — and the digest of the resulting
//! dimensioned report — from every other hash in the protocol.
//!
//! They are deliberately distinct from
//! [`VerificationContextDomain`](super::accountability::VerificationContextDomain),
//! which covers the *accountability* verification context. The two contexts
//! commit to different material and must never produce the same digest for the
//! same bytes.

use super::super::domain_hash::Domain;

/// Domain marker for the effective protocol verification context digest.
pub struct ProtocolVerificationContextDomain;

impl Domain for ProtocolVerificationContextDomain {
    const DOMAIN: &'static [u8] = b"csv.verification.context.v1";
}

/// Domain marker for the dimensioned protocol assurance report digest.
pub struct ProtocolAssuranceReportDomain;

impl Domain for ProtocolAssuranceReportDomain {
    const DOMAIN: &'static [u8] = b"csv.verification.assurance-report.v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_hash::DomainSeparatedHash;
    use crate::domains::accountability::VerificationContextDomain;
    use crate::domains::proof_bundle::ProofBundleDomain;

    #[test]
    fn protocol_verification_domains_are_distinct_from_neighbours() {
        let tags: [&[u8]; 4] = [
            ProtocolVerificationContextDomain::DOMAIN,
            ProtocolAssuranceReportDomain::DOMAIN,
            VerificationContextDomain::DOMAIN,
            ProofBundleDomain::DOMAIN,
        ];
        let unique: std::collections::HashSet<&[u8]> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len(), "domain tags must not collide");
    }

    #[test]
    fn identical_payloads_separate_across_the_two_new_domains() {
        let payload = b"parwana-assurance-vector-v1";
        assert_ne!(
            DomainSeparatedHash::<ProtocolVerificationContextDomain>::hash(payload),
            DomainSeparatedHash::<ProtocolAssuranceReportDomain>::hash(payload),
        );
        assert_ne!(
            DomainSeparatedHash::<ProtocolVerificationContextDomain>::hash(payload),
            DomainSeparatedHash::<VerificationContextDomain>::hash(payload),
        );
    }
}
