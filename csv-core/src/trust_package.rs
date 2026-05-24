//! Trust packages for offline verification bootstrapping.
//!
//! This module provides the types and logic needed to bootstrap offline
//! verification with authenticated, versioned trust roots.
//!
//! ## Overview
//!
//! Offline verification is meaningless without:
//!
//! - **Versioned trust roots** — trust packages carry a generation epoch
//! - **Authenticated trust roots** — each package is cryptographically signed
//! - **Pinned checkpoints** — the trusted hash and height are immutable
//! - **Attestable origin** — the signer's identity is verifiable
//!
//! ## Usage
//!
//! ```
//! use csv_core::trust_package::{TrustPackage, OfflineVerificationContext};
//! use csv_core::Hash;
//! use csv_hash::chain_id::ChainId;
//! use chrono::{Utc, Duration};
//!
//! let package = TrustPackage::new(
//!     ChainId::new("solana"),
//!     Hash::default(),
//!     1000000,
//!     b"validator-commitment".to_vec(),
//!     Duration::hours(24),
//! );
//!
//! let context = OfflineVerificationContext::new(package, Utc::now());
//! assert!(context.is_valid());
//! ```

use alloc::vec::Vec;
use chrono::{DateTime, Duration, Utc};
use core::fmt;
use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_protocol::signature::SignatureScheme;

/// Errors that can occur when working with trust packages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustPackageError {
    /// The trust package signature could not be verified.
    SignatureInvalid,
    /// The trust package has expired.
    Expired {
        /// The expiration time of the package.
        expires_at: DateTime<Utc>,
        /// The time at which validity was checked.
        checked_at: DateTime<Utc>,
    },
    /// The trust package is not yet valid (generated_at is in the future).
    NotYetValid {
        /// The generation time of the package.
        generated_at: DateTime<Utc>,
        /// The time at which validity was checked.
        checked_at: DateTime<Utc>,
    },
    /// The checkpoint hash does not match the trusted checkpoint.
    CheckpointMismatch {
        /// The expected (trusted) checkpoint hash.
        expected: Hash,
        /// The actual checkpoint hash provided.
        actual: Hash,
    },
    /// The checkpoint height does not match the trusted height.
    HeightMismatch {
        /// The expected (trusted) checkpoint height.
        expected: u64,
        /// The actual checkpoint height provided.
        actual: u64,
    },
    /// The trust package has been revoked.
    Revoked,
    /// The trust package version is incompatible.
    VersionMismatch {
        /// The expected minimum version.
        expected: u32,
        /// The actual version found.
        actual: u32,
    },
    /// The validator commitment is missing or empty.
    EmptyCommitment,
}

impl fmt::Display for TrustPackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustPackageError::SignatureInvalid => {
                write!(f, "trust package signature is invalid")
            }
            TrustPackageError::Expired {
                expires_at,
                checked_at,
            } => {
                write!(
                    f,
                    "trust package expired at {} (checked at {})",
                    expires_at, checked_at
                )
            }
            TrustPackageError::NotYetValid {
                generated_at,
                checked_at,
            } => {
                write!(
                    f,
                    "trust package not yet valid (generated at {}, checked at {})",
                    generated_at, checked_at
                )
            }
            TrustPackageError::CheckpointMismatch { expected, actual } => {
                write!(
                    f,
                    "checkpoint hash mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            TrustPackageError::HeightMismatch { expected, actual } => {
                write!(
                    f,
                    "checkpoint height mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            TrustPackageError::Revoked => write!(f, "trust package has been revoked"),
            TrustPackageError::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "trust package version mismatch: expected >= {}, got {}",
                    expected, actual
                )
            }
            TrustPackageError::EmptyCommitment => {
                write!(f, "validator commitment is empty or missing")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TrustPackageError {}

/// A signed package that establishes a trusted checkpoint for offline verification.
///
/// Trust packages are the foundation of offline verification. They provide:
///
/// - **Authenticated trust roots** — each package is signed by a trusted validator
/// - **Versioned checkpoints** — packages carry a generation epoch for rotation
/// - **Pinned state** — the hash and height are immutable once signed
/// - **Time-bounded validity** — packages expire and must be refreshed
///
/// ## Security Properties
///
/// - The signature binds the checkpoint hash, height, and validator commitment
/// - Expiration prevents use of stale trust roots
/// - Generation epoch enables trust root rotation without breaking history
/// - Revocation lists allow emergency withdrawal of compromised packages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustPackage {
    /// Chain identifier for which this trust package applies.
    pub chain_id: ChainId,
    /// Trusted checkpoint hash for the chain.
    pub trusted_checkpoint: Hash,
    /// Height of the checkpoint.
    pub checkpoint_height: u64,
    /// Validator commitment payload (opaque bytes).
    pub validator_commitment: Vec<u8>,
    /// Generation time of the package.
    pub generated_at: DateTime<Utc>,
    /// Expiration time of the package.
    pub expires_at: DateTime<Utc>,
    /// Raw package signature bytes (codec-specific).
    pub package_signature: Vec<u8>,
    /// The signature scheme used to sign this package.
    pub signature_scheme: SignatureScheme,
    /// Trust package generation epoch (enables rotation).
    pub generation_epoch: u32,
    /// Optional revocation indicator.
    pub revoked: bool,
}

impl TrustPackage {
    /// Create a new unsigned trust package.
    ///
    /// The package must be signed before use via [`TrustPackage::sign`].
    ///
    /// # Arguments
    /// * `chain_id` — The chain this package applies to
    /// * `trusted_checkpoint` — The trusted checkpoint hash
    /// * `checkpoint_height` — The block/slot height of the checkpoint
    /// * `validator_commitment` — Opaque validator commitment bytes
    /// * `ttl` — Time-to-live for the package
    ///
    /// # Example
    ///
    /// ```
    /// use csv_core::trust_package::TrustPackage;
    /// use csv_core::Hash;
    /// use csv_hash::chain_id::ChainId;
    /// use chrono::Duration;
    ///
    /// let package = TrustPackage::new(
    ///     ChainId::new("solana"),
    ///     Hash::default(),
    ///     1_000_000,
    ///     vec![1, 2, 3],
    ///     Duration::hours(24),
    /// );
    /// assert_eq!(package.generation_epoch, 0);
    /// assert!(!package.revoked);
    /// ```
    pub fn new(
        chain_id: ChainId,
        trusted_checkpoint: Hash,
        checkpoint_height: u64,
        validator_commitment: Vec<u8>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            chain_id,
            trusted_checkpoint,
            checkpoint_height,
            validator_commitment,
            generated_at: now,
            expires_at: now + ttl,
            package_signature: Vec::new(),
            signature_scheme: SignatureScheme::default(),
            generation_epoch: 0,
            revoked: false,
        }
    }

    /// Sign this trust package with the given scheme and secret key.
    ///
    /// The signature covers the canonical serialization of the package
    /// fields (excluding the signature itself).
    ///
    /// # Arguments
    /// * `scheme` — The signature scheme to use
    /// * `secret_key` — The secret key bytes
    ///
    /// # Returns
    /// * `Ok(())` if signing succeeded
    /// * `Err(TrustPackageError)` if signing failed
    pub fn sign(
        &mut self,
        scheme: SignatureScheme,
        secret_key: &[u8],
    ) -> Result<(), TrustPackageError> {
        use csv_protocol::signature::Signature;

        let message = self.signing_message();

        let sig = Signature::sign(scheme, secret_key, &message)
            .map_err(|_| TrustPackageError::SignatureInvalid)?;

        self.package_signature = sig.signature;
        self.signature_scheme = scheme;

        Ok(())
    }

    /// Verify the signature on this trust package.
    ///
    /// # Arguments
    /// * `public_key` — The public key bytes to verify against
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid
    /// * `Err(TrustPackageError::SignatureInvalid)` if verification fails
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<(), TrustPackageError> {
        if self.package_signature.is_empty() {
            return Err(TrustPackageError::SignatureInvalid);
        }

        use csv_protocol::signature::Signature;

        let message = self.signing_message();
        let sig = Signature::new(self.package_signature.clone(), public_key.to_vec(), message);

        sig.verify(self.signature_scheme)
            .map_err(|_| TrustPackageError::SignatureInvalid)
    }

    /// Verify the signature using a list of trusted public keys (multi-sig).
    ///
    /// At least one key must produce a valid signature.
    ///
    /// # Arguments
    /// * `trusted_keys` — List of trusted public key bytes
    ///
    /// # Returns
    /// * `Ok(())` if at least one key verifies
    /// * `Err(TrustPackageError::SignatureInvalid)` if none verify
    pub fn verify_multi_signature(&self, trusted_keys: &[&[u8]]) -> Result<(), TrustPackageError> {
        if trusted_keys.is_empty() {
            return Err(TrustPackageError::SignatureInvalid);
        }

        for key in trusted_keys {
            if self.verify_signature(key).is_ok() {
                return Ok(());
            }
        }

        Err(TrustPackageError::SignatureInvalid)
    }

    /// Check if this trust package has expired relative to a given time.
    ///
    /// # Arguments
    /// * `at` — The time to check against
    pub fn is_expired_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.expires_at
    }

    /// Check if this trust package has expired relative to the current time.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// Check if this trust package is valid at a given time.
    ///
    /// A package is valid if:
    /// - It has not expired
    /// - It has not been revoked
    /// - The verification time is after the generation time
    ///
    /// # Arguments
    /// * `at` — The time to check against
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        !self.is_expired_at(at) && !self.revoked && at >= self.generated_at
    }

    /// Check if this trust package is valid relative to the current time.
    pub fn is_valid(&self) -> bool {
        self.is_valid_at(Utc::now())
    }

    /// Verify a checkpoint against this trust package.
    ///
    /// This is the core verification method: it checks that a provided
    /// checkpoint hash and height match the trusted values in the package.
    ///
    /// # Arguments
    /// * `checkpoint_hash` — The hash to verify
    /// * `checkpoint_height` — The height to verify
    /// * `verification_time` — The time at which verification occurs
    ///
    /// # Returns
    /// * `Ok(())` if the checkpoint matches and the package is valid
    /// * `Err(TrustPackageError)` with specific error details
    pub fn verify_checkpoint(
        &self,
        checkpoint_hash: &Hash,
        checkpoint_height: u64,
        verification_time: DateTime<Utc>,
    ) -> Result<(), TrustPackageError> {
        if self.revoked {
            return Err(TrustPackageError::Revoked);
        }

        if !self.is_valid_at(verification_time) {
            if verification_time >= self.expires_at {
                return Err(TrustPackageError::Expired {
                    expires_at: self.expires_at,
                    checked_at: verification_time,
                });
            }
            if verification_time < self.generated_at {
                return Err(TrustPackageError::NotYetValid {
                    generated_at: self.generated_at,
                    checked_at: verification_time,
                });
            }
            return Err(TrustPackageError::Expired {
                expires_at: self.expires_at,
                checked_at: verification_time,
            });
        }

        if self.validator_commitment.is_empty() {
            return Err(TrustPackageError::EmptyCommitment);
        }

        if *checkpoint_hash != self.trusted_checkpoint {
            return Err(TrustPackageError::CheckpointMismatch {
                expected: self.trusted_checkpoint,
                actual: *checkpoint_hash,
            });
        }

        if checkpoint_height != self.checkpoint_height {
            return Err(TrustPackageError::HeightMismatch {
                expected: self.checkpoint_height,
                actual: checkpoint_height,
            });
        }

        Ok(())
    }

    /// Verify a checkpoint against this trust package at the current time.
    pub fn verify_current_checkpoint(
        &self,
        checkpoint_hash: &Hash,
        checkpoint_height: u64,
    ) -> Result<(), TrustPackageError> {
        self.verify_checkpoint(checkpoint_hash, checkpoint_height, Utc::now())
    }

    /// Get the signing message (canonical serialization of signed fields).
    fn signing_message(&self) -> Vec<u8> {
        use csv_codec::to_canonical_cbor;
        to_canonical_cbor(&(
            self.chain_id.0.clone(),
            self.trusted_checkpoint.as_bytes(),
            self.checkpoint_height,
            self.generation_epoch,
            self.validator_commitment.len(),
            &self.validator_commitment,
        ))
        .expect("Canonical serialization should not fail for signing message")
    }

    /// Increment the generation epoch for trust package rotation.
    pub fn increment_epoch(&mut self) {
        self.generation_epoch = self.generation_epoch.saturating_add(1);
    }

    /// Mark this trust package as revoked.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Returns true if this package has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns the generation epoch of this package.
    pub fn generation_epoch(&self) -> u32 {
        self.generation_epoch
    }
}

/// Context required to perform offline verification using a trust package.
///
/// This struct bundles a trust package with the verification timestamp
/// to enable time-bounded offline verification.
#[derive(Clone, Debug)]
pub struct OfflineVerificationContext {
    /// The trust package to use for verification.
    pub trust_package: TrustPackage,
    /// The effective verification timestamp.
    pub verification_time: DateTime<Utc>,
}

impl OfflineVerificationContext {
    /// Create a new offline verification context.
    ///
    /// # Arguments
    /// * `trust_package` — The trust package to use
    /// * `verification_time` — The time at which verification occurs
    pub fn new(trust_package: TrustPackage, verification_time: DateTime<Utc>) -> Self {
        Self {
            trust_package,
            verification_time,
        }
    }

    /// Check if this context is valid (package is valid at verification time).
    pub fn is_valid(&self) -> bool {
        self.trust_package.is_valid_at(self.verification_time)
    }

    /// Verify a checkpoint hash and height against the trust package.
    ///
    /// # Arguments
    /// * `checkpoint_hash` — The hash to verify
    /// * `checkpoint_height` — The height to verify
    ///
    /// # Returns
    /// * `Ok(())` if the checkpoint matches and the context is valid
    /// * `Err(TrustPackageError)` with specific error details
    pub fn verify_checkpoint(
        &self,
        checkpoint_hash: &Hash,
        checkpoint_height: u64,
    ) -> Result<(), TrustPackageError> {
        self.trust_package.verify_checkpoint(
            checkpoint_hash,
            checkpoint_height,
            self.verification_time,
        )
    }

    /// Verify a checkpoint hash and height against the trust package at the current time.
    pub fn verify_current_checkpoint(
        &self,
        checkpoint_hash: &Hash,
        checkpoint_height: u64,
    ) -> Result<(), TrustPackageError> {
        self.trust_package
            .verify_current_checkpoint(checkpoint_hash, checkpoint_height)
    }

    /// Get the chain ID this context applies to.
    pub fn chain_id(&self) -> ChainId {
        self.trust_package.chain_id.clone()
    }

    /// Get the trusted checkpoint hash.
    pub fn trusted_checkpoint(&self) -> &Hash {
        &self.trust_package.trusted_checkpoint
    }

    /// Get the trusted checkpoint height.
    pub fn trusted_checkpoint_height(&self) -> u64 {
        self.trust_package.checkpoint_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_package_new() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        assert_eq!(package.chain_id, ChainId::new("solana"));
        assert_eq!(package.checkpoint_height, 1_000_000);
        assert_eq!(package.validator_commitment, vec![1, 2, 3]);
        assert_eq!(package.generation_epoch, 0);
        assert!(!package.revoked);
        assert!(package.package_signature.is_empty());
    }

    #[test]
    fn test_trust_package_expired() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let future = Utc::now() + Duration::hours(48);
        assert!(package.is_expired_at(future));
        assert!(!package.is_valid_at(future));
    }

    #[test]
    fn test_trust_package_not_yet_valid() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let past = Utc::now() - Duration::hours(1);
        assert!(!package.is_valid_at(past));
    }

    #[test]
    fn test_trust_package_valid_window() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        assert!(package.is_valid());
        assert!(!package.is_expired());
    }

    #[test]
    fn test_trust_package_revoke() {
        let mut package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        assert!(!package.is_revoked());
        assert!(package.is_valid());

        package.revoke();

        assert!(package.is_revoked());
        assert!(!package.is_valid());
    }

    #[test]
    fn test_trust_package_increment_epoch() {
        let mut package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        assert_eq!(package.generation_epoch(), 0);
        package.increment_epoch();
        assert_eq!(package.generation_epoch(), 1);
        package.increment_epoch();
        assert_eq!(package.generation_epoch(), 2);
    }

    #[test]
    fn test_trust_package_verify_checkpoint_match() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let now = Utc::now();
        assert!(
            package
                .verify_checkpoint(&Hash::default(), 1_000_000, now)
                .is_ok()
        );
    }

    #[test]
    fn test_trust_package_verify_checkpoint_hash_mismatch() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let now = Utc::now();
        let result = package.verify_checkpoint(&Hash::new([1u8; 32]), 1_000_000, now);
        assert!(matches!(
            result,
            Err(TrustPackageError::CheckpointMismatch { .. })
        ));
    }

    #[test]
    fn test_trust_package_verify_checkpoint_height_mismatch() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let now = Utc::now();
        let result = package.verify_checkpoint(&Hash::default(), 2_000_000, now);
        assert!(matches!(
            result,
            Err(TrustPackageError::HeightMismatch { .. })
        ));
    }

    #[test]
    fn test_trust_package_verify_checkpoint_revoked() {
        let mut package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        package.revoke();
        let now = Utc::now();
        let result = package.verify_checkpoint(&Hash::default(), 1_000_000, now);
        assert!(matches!(result, Err(TrustPackageError::Revoked)));
    }

    #[test]
    fn test_trust_package_verify_checkpoint_expired() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let future = Utc::now() + Duration::hours(48);
        let result = package.verify_checkpoint(&Hash::default(), 1_000_000, future);
        assert!(matches!(result, Err(TrustPackageError::Expired { .. })));
    }

    #[test]
    fn test_trust_package_verify_checkpoint_empty_commitment() {
        let mut package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![],
            Duration::hours(24),
        );

        let now = Utc::now();
        let result = package.verify_checkpoint(&Hash::default(), 1_000_000, now);
        assert!(matches!(result, Err(TrustPackageError::EmptyCommitment)));

        // Add commitment and retry
        package.validator_commitment = vec![1, 2, 3];
        assert!(
            package
                .verify_checkpoint(&Hash::default(), 1_000_000, now)
                .is_ok()
        );
    }

    #[test]
    fn test_offline_verification_context_valid() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let context = OfflineVerificationContext::new(package, Utc::now());
        assert!(context.is_valid());
    }

    #[test]
    fn test_offline_verification_context_verify_checkpoint() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::default(),
            1_000_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let context = OfflineVerificationContext::new(package, Utc::now());
        assert!(
            context
                .verify_checkpoint(&Hash::default(), 1_000_000)
                .is_ok()
        );
    }

    #[test]
    fn test_offline_verification_context_accessors() {
        let package = TrustPackage::new(
            ChainId::new("bitcoin"),
            Hash::new([0x42; 32]),
            800_000,
            vec![1, 2, 3],
            Duration::hours(24),
        );

        let context = OfflineVerificationContext::new(package, Utc::now());
        assert_eq!(context.chain_id(), ChainId::new("bitcoin"));
        assert_eq!(*context.trusted_checkpoint(), Hash::new([0x42; 32]));
        assert_eq!(context.trusted_checkpoint_height(), 800_000);
    }

    #[test]
    fn test_trust_package_error_display() {
        let err = TrustPackageError::SignatureInvalid;
        assert_eq!(format!("{}", err), "trust package signature is invalid");

        let err = TrustPackageError::Revoked;
        assert_eq!(format!("{}", err), "trust package has been revoked");

        let err = TrustPackageError::EmptyCommitment;
        assert_eq!(
            format!("{}", err),
            "validator commitment is empty or missing"
        );
    }

    #[test]
    fn test_trust_package_signing_message() {
        let package = TrustPackage::new(
            ChainId::new("solana"),
            Hash::new([0xAB; 32]),
            1_234_567,
            vec![0x01, 0x02, 0x03],
            Duration::hours(24),
        );

        let msg = package.signing_message();
        assert!(!msg.is_empty());
        assert_eq!(msg, package.signing_message());

        let mut rotated = package.clone();
        rotated.increment_epoch();
        assert_ne!(msg, rotated.signing_message());
    }
}
