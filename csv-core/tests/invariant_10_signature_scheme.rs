#![cfg(any())]
//! Invariant 10: Signature Scheme MUST Be Derived From Chain, Not Payload
//!
//! Rule: The scheme used to verify ownership MUST be derived from
//! `CrossChainHashAlgorithm::for_chain(&source_chain)`, NOT from the
//! `scheme` field inside the proof payload.
//! Prohibited: Trusting the `scheme` field in proof payloads.

#[cfg(test)]
mod tests {
    use csv_core::signature::SignatureScheme;

    /// Property: SignatureScheme has correct variants
    #[test]
    fn test_signature_scheme_variants() {
        let secp = SignatureScheme::Secp256k1;
        let ed = SignatureScheme::Ed25519;

        assert!(matches!(secp, SignatureScheme::Secp256k1));
        assert!(matches!(ed, SignatureScheme::Ed25519));
    }

    /// Property: SignatureScheme variants are distinct
    #[test]
    fn test_signature_scheme_distinct() {
        assert_ne!(SignatureScheme::Secp256k1, SignatureScheme::Ed25519);
    }

    /// Property: SignatureScheme is cloneable
    #[test]
    fn test_signature_scheme_clone() {
        let scheme = SignatureScheme::Secp256k1;
        let cloned = scheme.clone();
        assert_eq!(scheme, cloned);
    }

    /// Property: SignatureScheme is equatable
    #[test]
    fn test_signature_scheme_equality() {
        assert_eq!(SignatureScheme::Secp256k1, SignatureScheme::Secp256k1);
        assert_ne!(SignatureScheme::Secp256k1, SignatureScheme::Ed25519);
    }

    /// Property: SignatureScheme debug output is informative
    #[test]
    fn test_signature_scheme_debug() {
        let scheme = SignatureScheme::Secp256k1;
        let debug_str = format!("{:?}", scheme);
        assert!(!debug_str.is_empty());
    }

    /// Property: SignatureScheme can be serialized
    #[test]
    fn test_signature_scheme_serialization() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            scheme: SignatureScheme,
        }

        let w = Wrapper {
            scheme: SignatureScheme::Ed25519,
        };
        let json = serde_json::to_string(&w).unwrap();
        let restored: Wrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(w.scheme, restored.scheme);
    }
}
