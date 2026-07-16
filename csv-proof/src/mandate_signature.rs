//! Cryptographic verification of detached action-mandate signatures.

use csv_accountability::{
    ActionMandate, ED25519_SIGNATURE_ALGORITHM, MandateError, MandateSignatureEnvelope,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// A mandate-signature verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandateSignatureError {
    /// The mandate or envelope is structurally invalid.
    InvalidEnvelope,
    /// The supplied verification key does not match the envelope key identifier.
    KeyIdMismatch,
    /// The verification key or signature encoding is malformed.
    MalformedCryptographicInput,
    /// The detached signature does not authenticate the mandate.
    InvalidSignature,
}

/// Verifies an Ed25519 envelope over the mandate's domain-separated identifier.
///
/// Key resolution and identity authorization remain external trust-context inputs;
/// this function checks that the resolved key matches the signed envelope and bytes.
pub fn verify_mandate_signature(
    mandate: &ActionMandate,
    envelope: &MandateSignatureEnvelope,
    resolved_key_id: &[u8],
    verifying_key: &[u8],
) -> Result<(), MandateSignatureError> {
    envelope.validate_for(mandate).map_err(map_mandate_error)?;
    if envelope.algorithm != ED25519_SIGNATURE_ALGORITHM {
        return Err(MandateSignatureError::InvalidEnvelope);
    }
    if envelope.key_id != resolved_key_id {
        return Err(MandateSignatureError::KeyIdMismatch);
    }
    let key_bytes: &[u8; 32] = verifying_key
        .try_into()
        .map_err(|_| MandateSignatureError::MalformedCryptographicInput)?;
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|_| MandateSignatureError::MalformedCryptographicInput)?;
    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|_| MandateSignatureError::MalformedCryptographicInput)?;
    key.verify(
        &mandate.signing_bytes().map_err(map_mandate_error)?,
        &signature,
    )
    .map_err(|_| MandateSignatureError::InvalidSignature)
}

fn map_mandate_error(_: MandateError) -> MandateSignatureError {
    MandateSignatureError::InvalidEnvelope
}

#[cfg(test)]
mod tests {
    use csv_accountability::{
        ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ExecutionPolicy, IntentId,
        MandateRequirement, MandateSubject, SignatureRequirements,
    };
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn mandate() -> ActionMandate {
        ActionMandate {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            mandate_version: ACCOUNTABILITY_OBJECT_VERSION,
            intent_id: IntentId::from_digest([1; 32]),
            issuer_identity: vec![2],
            subject: MandateSubject::Identity(vec![3]),
            authority_domain: vec![4],
            valid_from: 10,
            expires_at: 20,
            maximum_dispatches: 1,
            constraints: vec![],
            evidence_requirements: vec![MandateRequirement {
                registry_id: "org.diewan.evidence.github.v1".into(),
                parameters_digest: [5; 32],
            }],
            execution_policy: ExecutionPolicy {
                registry_id: "org.diewan.execution.once.v1".into(),
                parameters_digest: [6; 32],
            },
            parent_mandate: None,
            revocation_reference: None,
            issued_at: 9,
            nonce: [7; 32],
            signature_requirements: SignatureRequirements {
                algorithm: ED25519_SIGNATURE_ALGORITHM.into(),
                key_id: b"key-1".to_vec(),
            },
        }
    }

    fn signed(mandate: &ActionMandate, key: &SigningKey) -> MandateSignatureEnvelope {
        MandateSignatureEnvelope {
            version: ACCOUNTABILITY_OBJECT_VERSION,
            algorithm: ED25519_SIGNATURE_ALGORITHM.into(),
            key_id: b"key-1".to_vec(),
            signature: key
                .sign(&mandate.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        }
    }

    #[test]
    fn valid_signature_verifies_and_mutations_fail() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let mandate = mandate();
        let envelope = signed(&mandate, &key);
        assert_eq!(
            verify_mandate_signature(
                &mandate,
                &envelope,
                b"key-1",
                key.verifying_key().as_bytes()
            ),
            Ok(())
        );

        let mut changed = mandate.clone();
        changed.expires_at += 1;
        assert_eq!(
            verify_mandate_signature(
                &changed,
                &envelope,
                b"key-1",
                key.verifying_key().as_bytes()
            ),
            Err(MandateSignatureError::InvalidSignature)
        );
        assert_eq!(
            verify_mandate_signature(
                &mandate,
                &envelope,
                b"wrong",
                key.verifying_key().as_bytes()
            ),
            Err(MandateSignatureError::KeyIdMismatch)
        );
    }

    #[test]
    fn forged_and_malformed_signatures_fail_closed() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let mandate = mandate();
        let mut envelope = signed(&mandate, &key);
        envelope.signature[0] ^= 1;
        assert_eq!(
            verify_mandate_signature(
                &mandate,
                &envelope,
                b"key-1",
                key.verifying_key().as_bytes()
            ),
            Err(MandateSignatureError::InvalidSignature)
        );
        assert_eq!(
            verify_mandate_signature(&mandate, &envelope, b"key-1", &[0; 31]),
            Err(MandateSignatureError::MalformedCryptographicInput)
        );
    }
}
