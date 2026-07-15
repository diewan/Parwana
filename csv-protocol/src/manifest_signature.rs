//! Detached signing and fail-closed verification for the deployment manifest.
//!
//! The shipped `deployments/deployment-manifest.json` points every consumer
//! (explorer, Hemion, CLI) at the contracts/programs that hold protocol
//! authority. A checksum only detects corruption; it does not detect
//! substitution. This module adds a **detached signature** over the manifest so
//! a tampered or attacker-supplied registry is rejected at load time.
//!
//! ## What is signed
//!
//! The signature covers the **canonical CBOR** encoding of the parsed manifest
//! (via [`csv_codec::to_canonical_cbor`]), never the JSON text. Reformatting
//! the JSON (whitespace, key order, unicode escaping) does not change the signed
//! bytes; changing any value does. This reuses the workspace canonical
//! serialization — no new format is introduced.
//!
//! ## Trust anchor
//!
//! Verification public keys are pinned in [`TRUSTED_MANIFEST_SIGNERS`] — a
//! reviewable in-repo location. The sidecar names a `signer_id`; only a pinned
//! signer is accepted. The signing **private** key is an offline operator
//! credential and MUST NEVER appear in the repository, CI, or containers
//! (EXP-001 discipline). See `deployments/README.md` for the rotation procedure.
//!
//! ## Fail-closed
//!
//! A missing, malformed, wrong-signer, or invalid signature is an error, not a
//! warning. A development bypass exists behind an explicit `allow_unsigned` flag
//! but is compiled out of release builds (`debug_assertions`), so it can never
//! weaken a shipped binary.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::signature::{Signature, SignatureScheme};

/// A pinned manifest signer (verification key trust anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedSigner {
    /// Stable operator identity referenced by the signature sidecar.
    pub id: &'static str,
    /// Signature scheme this signer's key uses.
    pub scheme: ManifestSignatureScheme,
    /// Lowercase hex-encoded public key (32 bytes for Ed25519).
    pub public_key_hex: &'static str,
}

/// Signature schemes permitted for the deployment manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSignatureScheme {
    /// Ed25519 detached signature over the canonical CBOR bytes.
    Ed25519,
}

impl ManifestSignatureScheme {
    fn as_protocol_scheme(self) -> SignatureScheme {
        match self {
            ManifestSignatureScheme::Ed25519 => SignatureScheme::Ed25519,
        }
    }
}

/// Pinned verification keys for the deployment manifest.
///
/// Extending or rotating this set is a reviewable code change. The private keys
/// are held offline by the operator; see `deployments/README.md`.
pub const TRUSTED_MANIFEST_SIGNERS: &[TrustedSigner] = &[TrustedSigner {
    id: "csv-testnet-operator-2026-07",
    scheme: ManifestSignatureScheme::Ed25519,
    // Ed25519 public key of the offline testnet operator manifest-signing key.
    // Generated 2026-07-15 for RPC-006. Rotate per deployments/README.md.
    public_key_hex: "fe6d9c3c25f0ffde723f761131e7912dcc4c2fbdbf3f79009d225f1b29d9fe50",
}];

/// Detached signature sidecar stored next to the manifest.
///
/// Serialized as `deployment-manifest.sig.json`. The public key is intentionally
/// NOT trusted from this file — it is resolved from [`TRUSTED_MANIFEST_SIGNERS`]
/// by `signer_id`, so swapping the sidecar cannot swap the trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSignatureSidecar {
    /// Identity of the signer; must match a pinned [`TrustedSigner`].
    pub signer_id: String,
    /// Signature scheme used.
    pub scheme: ManifestSignatureScheme,
    /// Lowercase hex-encoded detached signature over the canonical CBOR bytes.
    pub signature: String,
    /// Optional ISO-8601 timestamp recording when the manifest was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// The canonical sidecar filename for a manifest at `<name>.json`.
fn sidecar_path_for(manifest_path: &Path) -> PathBuf {
    let mut path = manifest_path.to_path_buf();
    // deployment-manifest.json -> deployment-manifest.sig.json
    let file = manifest_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("deployment-manifest");
    path.set_file_name(format!("{file}.sig.json"));
    path
}

/// Errors distinguishing every fail-closed reason at manifest load.
#[derive(Debug, thiserror::Error)]
pub enum ManifestVerificationError {
    /// The manifest file could not be read.
    #[error("manifest read failed: {0}")]
    ManifestRead(String),
    /// The signature sidecar is absent.
    #[error("manifest signature sidecar is missing (fail-closed)")]
    MissingSignature,
    /// The sidecar exists but is not parseable.
    #[error("manifest signature sidecar is malformed: {0}")]
    MalformedSignature(String),
    /// The signature hex is not decodable.
    #[error("manifest signature is not valid hex: {0}")]
    MalformedSignatureBytes(String),
    /// The named signer is not in the pinned trust set.
    #[error("manifest signed by unknown signer '{0}' (not in the pinned trust set)")]
    UnknownSigner(String),
    /// The sidecar scheme does not match the pinned signer's scheme.
    #[error("manifest signer '{signer}' uses {expected:?}, sidecar claims {actual:?}")]
    SchemeMismatch {
        /// Signer id.
        signer: String,
        /// Scheme the pinned signer uses.
        expected: ManifestSignatureScheme,
        /// Scheme the sidecar claimed.
        actual: ManifestSignatureScheme,
    },
    /// Canonical encoding of the manifest failed.
    #[error("manifest canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    /// The pinned public key is not decodable (repo/config error).
    #[error("pinned public key for '{0}' is not valid hex")]
    MalformedTrustAnchor(String),
    /// The signature did not verify against the pinned key over the canonical bytes.
    #[error("manifest signature verification failed for signer '{0}'")]
    InvalidSignature(String),
}

/// Compute the canonical CBOR bytes that a signature covers.
///
/// The manifest JSON is parsed into a value and re-encoded with the workspace
/// canonical CBOR encoder, so the signed bytes are independent of JSON
/// formatting but bound to every value.
pub fn manifest_canonical_bytes(manifest_json: &str) -> Result<Vec<u8>, ManifestVerificationError> {
    let value: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| ManifestVerificationError::MalformedSignature(e.to_string()))?;
    csv_codec::to_canonical_cbor(&value)
        .map_err(|e| ManifestVerificationError::CanonicalEncoding(e.to_string()))
}

fn find_signer(signer_id: &str) -> Option<&'static TrustedSigner> {
    TRUSTED_MANIFEST_SIGNERS.iter().find(|s| s.id == signer_id)
}

/// Verify a manifest against a sidecar, returning the matched trusted signer.
///
/// Fails closed with a distinct error for every rejection reason.
pub fn verify_manifest(
    manifest_json: &str,
    sidecar: &ManifestSignatureSidecar,
) -> Result<&'static TrustedSigner, ManifestVerificationError> {
    let signer = find_signer(&sidecar.signer_id)
        .ok_or_else(|| ManifestVerificationError::UnknownSigner(sidecar.signer_id.clone()))?;
    if sidecar.scheme != signer.scheme {
        return Err(ManifestVerificationError::SchemeMismatch {
            signer: signer.id.to_string(),
            expected: signer.scheme,
            actual: sidecar.scheme,
        });
    }
    let message = manifest_canonical_bytes(manifest_json)?;
    let signature_bytes = hex::decode(sidecar.signature.trim())
        .map_err(|e| ManifestVerificationError::MalformedSignatureBytes(e.to_string()))?;
    let public_key = hex::decode(signer.public_key_hex)
        .map_err(|_| ManifestVerificationError::MalformedTrustAnchor(signer.id.to_string()))?;

    let sig = Signature::new(signature_bytes, public_key, message);
    sig.verify(signer.scheme.as_protocol_scheme())
        .map_err(|_| ManifestVerificationError::InvalidSignature(signer.id.to_string()))?;
    Ok(signer)
}

/// A manifest that passed load-time verification.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    /// Raw manifest JSON text (already verified).
    pub json: String,
    /// The trusted signer id that signed it, or `None` when loaded via the
    /// development unsigned bypass (never available in release builds).
    pub signer_id: Option<String>,
}

/// Load and verify the manifest and its sidecar from a directory.
///
/// `allow_unsigned` requests the development bypass for a missing sidecar. The
/// bypass is compiled out of release builds, so a shipped binary always fails
/// closed regardless of the flag.
pub fn load_verified_manifest_from_dir(
    dir: &Path,
    allow_unsigned: bool,
) -> Result<VerifiedManifest, ManifestVerificationError> {
    let manifest_path = dir.join("deployment-manifest.json");
    let json = std::fs::read_to_string(&manifest_path)
        .map_err(|e| ManifestVerificationError::ManifestRead(e.to_string()))?;
    let sidecar_path = sidecar_path_for(&manifest_path);

    let sidecar_text = match std::fs::read_to_string(&sidecar_path) {
        Ok(text) => text,
        Err(_) => {
            // No sidecar. Honor the development bypass only in debug builds.
            #[cfg(debug_assertions)]
            if allow_unsigned {
                eprintln!(
                    "WARNING: loading UNSIGNED deployment manifest via allow_unsigned \
                     development bypass — NEVER use this outside local development"
                );
                return Ok(VerifiedManifest {
                    json,
                    signer_id: None,
                });
            }
            let _ = allow_unsigned; // release builds: flag has no effect
            return Err(ManifestVerificationError::MissingSignature);
        }
    };

    let sidecar: ManifestSignatureSidecar = serde_json::from_str(&sidecar_text)
        .map_err(|e| ManifestVerificationError::MalformedSignature(e.to_string()))?;
    let signer = verify_manifest(&json, &sidecar)?;
    Ok(VerifiedManifest {
        json,
        signer_id: Some(signer.id.to_string()),
    })
}

/// Operator-side signing: produce a detached sidecar for a manifest.
///
/// `secret_key` is the raw 32-byte Ed25519 seed. It is a secret and must never
/// be committed. Used by the operator signing tool
/// (`examples/sign_deployment_manifest.rs`).
pub fn sign_manifest(
    manifest_json: &str,
    signer_id: &str,
    secret_key: &[u8],
    signed_at: Option<String>,
) -> Result<ManifestSignatureSidecar, ManifestVerificationError> {
    let message = manifest_canonical_bytes(manifest_json)?;
    let sig = Signature::sign(SignatureScheme::Ed25519, secret_key, &message)
        .map_err(|e| ManifestVerificationError::InvalidSignature(e.to_string()))?;
    Ok(ManifestSignatureSidecar {
        signer_id: signer_id.to_string(),
        scheme: ManifestSignatureScheme::Ed25519,
        signature: hex::encode(sig.signature),
        signed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    const MANIFEST: &str = r#"{
        "manifest_version": "2.1.0",
        "network": "testnet",
        "deployments": { "ethereum": { "network": "sepolia", "chain_id": 11155111 } }
    }"#;

    fn keypair(seed: [u8; 32]) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sidecar_for(signer_id: &str, sk: &SigningKey) -> ManifestSignatureSidecar {
        let message = manifest_canonical_bytes(MANIFEST).unwrap();
        let sig = sk.sign(&message);
        ManifestSignatureSidecar {
            signer_id: signer_id.to_string(),
            scheme: ManifestSignatureScheme::Ed25519,
            signature: hex::encode(sig.to_bytes()),
            signed_at: None,
        }
    }

    /// A verify path parameterized on the trust set for negative tests.
    fn verify_against(
        manifest: &str,
        sidecar: &ManifestSignatureSidecar,
        trusted: &[(String, VerifyingKey)],
    ) -> Result<(), ManifestVerificationError> {
        // Mirror verify_manifest but with an injected trust set.
        let (_, vk) = trusted
            .iter()
            .find(|(id, _)| id == &sidecar.signer_id)
            .ok_or_else(|| ManifestVerificationError::UnknownSigner(sidecar.signer_id.clone()))?;
        let message = manifest_canonical_bytes(manifest)?;
        let sig_bytes = hex::decode(sidecar.signature.trim())
            .map_err(|e| ManifestVerificationError::MalformedSignatureBytes(e.to_string()))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| ManifestVerificationError::InvalidSignature("test".into()))?;
        vk.verify_strict(&message, &sig)
            .map_err(|_| ManifestVerificationError::InvalidSignature("test".into()))
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, vk) = keypair([7u8; 32]);
        let sidecar = sidecar_for("op", &sk);
        let trust = vec![("op".to_string(), vk)];
        assert!(verify_against(MANIFEST, &sidecar, &trust).is_ok());
    }

    #[test]
    fn reformatting_json_does_not_break_verification() {
        let (sk, vk) = keypair([9u8; 32]);
        let sidecar = sidecar_for("op", &sk);
        let trust = vec![("op".to_string(), vk)];
        // Reformat: collapse whitespace and reorder keys.
        let reformatted = r#"{"deployments":{"ethereum":{"chain_id":11155111,"network":"sepolia"}},"network":"testnet","manifest_version":"2.1.0"}"#;
        assert!(
            verify_against(reformatted, &sidecar, &trust).is_ok(),
            "canonical CBOR must be independent of JSON formatting"
        );
    }

    #[test]
    fn changing_a_value_breaks_verification() {
        let (sk, vk) = keypair([11u8; 32]);
        let sidecar = sidecar_for("op", &sk);
        let trust = vec![("op".to_string(), vk)];
        let tampered = MANIFEST.replace("11155111", "1"); // wrong chain id
        assert!(matches!(
            verify_against(&tampered, &sidecar, &trust),
            Err(ManifestVerificationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn unknown_signer_fails_closed() {
        let (sk, _vk) = keypair([13u8; 32]);
        let sidecar = sidecar_for("attacker", &sk);
        let trust: Vec<(String, VerifyingKey)> = vec![];
        assert!(matches!(
            verify_against(MANIFEST, &sidecar, &trust),
            Err(ManifestVerificationError::UnknownSigner(_))
        ));
    }

    #[test]
    fn wrong_signer_key_fails_closed() {
        let (sk, _vk) = keypair([15u8; 32]);
        let (_sk2, vk2) = keypair([16u8; 32]);
        let sidecar = sidecar_for("op", &sk);
        let trust = vec![("op".to_string(), vk2)]; // pinned key differs from signer
        assert!(matches!(
            verify_against(MANIFEST, &sidecar, &trust),
            Err(ManifestVerificationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn missing_sidecar_fails_closed_without_bypass() {
        let dir = std::env::temp_dir().join(format!("csv-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deployment-manifest.json"), MANIFEST).unwrap();
        let err = load_verified_manifest_from_dir(&dir, false).unwrap_err();
        assert!(matches!(err, ManifestVerificationError::MissingSignature));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sign_manifest_roundtrips_through_verify_manifest_helpers() {
        // Exercise the production sign_manifest + manifest_canonical_bytes paths.
        let (sk, vk) = keypair([21u8; 32]);
        let sidecar = sign_manifest(MANIFEST, "op", sk.to_bytes().as_slice(), None).unwrap();
        let trust = vec![("op".to_string(), vk)];
        assert!(verify_against(MANIFEST, &sidecar, &trust).is_ok());
    }
}
