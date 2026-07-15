//! Per-recipient key wrapping / envelope encryption (RPC-007).
//!
//! A single random **data key** (DEK) encrypts the payload with an AEAD
//! (XChaCha20-Poly1305, matching [`crate::encryption::EncryptionDescriptor`]).
//! The DEK is then **wrapped once per authorized recipient** against that
//! recipient's X25519 public key, producing a [`RecipientWrapSet`] carried
//! alongside the envelope. A recipient unwraps the DEK with their secret key; a
//! non-recipient holding the whole object cannot.
//!
//! Recipient-set changes are expressed as an explicit **re-encryption**
//! ([`SealedObject::reseal_for_recipients`]): a new DEK, new wraps, and a new
//! object that supersedes the old one. This is the only honest model —
//! removing a recipient produces a new object their key cannot open, but it
//! **cannot** claw back access to ciphertext they already hold. Nothing here is
//! named `revoke` for that reason.
//!
//! ## Access guarantee (read carefully)
//!
//! Re-encryption removes a recipient from **future** objects only. A party who
//! previously held the DEK (or cached the plaintext / prior ciphertext) may
//! retain access to that prior object forever. This is the "remove future
//! access" semantics of DESIGN_PLAN.md §10.3 — never "revoke" or "delete".
//!
//! ## WASM
//!
//! Every primitive here (`x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`) is
//! pure Rust and compiles for `wasm32`. The API takes an RNG by value, so no
//! native-only entropy source is pulled into the shared path.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encryption::EncryptionDescriptor;

/// Wrap-set format version. Unknown versions fail closed.
pub const WRAP_SET_VERSION: u16 = 1;
/// Wrap algorithm identity. Unknown algorithms fail closed.
pub const WRAP_ALGORITHM: &str = "x25519-hkdf-sha256+xchacha20poly1305";
/// Payload AEAD algorithm (matches `EncryptionDescriptor::algorithm`).
pub const PAYLOAD_ALGORITHM: &str = "XChaCha20-Poly1305";

const HKDF_INFO: &[u8] = b"csv-content/recipient-wrap/v1";
const DEK_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const X25519_LEN: usize = 32;

/// A recipient's X25519 public key (wrapping target).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecipientPublicKey(pub [u8; X25519_LEN]);

/// A recipient's X25519 secret key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecipientSecretKey([u8; X25519_LEN]);

impl RecipientSecretKey {
    /// Wrap raw secret-key bytes.
    pub fn from_bytes(bytes: [u8; X25519_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh recipient keypair from an RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, RecipientPublicKey) {
        let mut seed = [0u8; X25519_LEN];
        rng.fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        seed.zeroize();
        let public = RecipientPublicKey(PublicKey::from(&secret).to_bytes());
        (Self(secret.to_bytes()), public)
    }

    /// This secret key's public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        let secret = StaticSecret::from(self.0);
        RecipientPublicKey(PublicKey::from(&secret).to_bytes())
    }
}

/// The DEK. Zeroized on drop; never serialized.
#[derive(Clone, ZeroizeOnDrop)]
struct DataKey([u8; DEK_LEN]);

/// One recipient's wrapped copy of the DEK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Recipient X25519 public key this wrap is for (32 bytes).
    pub recipient: Vec<u8>,
    /// Ephemeral X25519 public key used for this wrap (32 bytes).
    pub ephemeral_public: Vec<u8>,
    /// XChaCha20-Poly1305 nonce for the wrap (24 bytes).
    pub nonce: Vec<u8>,
    /// Wrapped DEK: ciphertext ‖ tag.
    pub wrapped_dek: Vec<u8>,
}

/// The recipient-keyed wrap set carried alongside the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientWrapSet {
    /// Format version.
    pub version: u16,
    /// Wrap algorithm identity.
    pub algorithm: String,
    /// One entry per authorized recipient.
    pub wraps: Vec<WrappedKey>,
}

impl RecipientWrapSet {
    /// Canonical CBOR serialization (round-trips via [`Self::from_canonical_cbor`]).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, WrapError> {
        csv_codec::to_canonical_cbor(self).map_err(|e| WrapError::Encoding(e.to_string()))
    }

    /// Deserialize and validate version/algorithm. Unknown values fail closed.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WrapError> {
        let set: RecipientWrapSet = csv_codec::from_canonical_cbor(bytes)
            .map_err(|e| WrapError::Encoding(e.to_string()))?;
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> Result<(), WrapError> {
        if self.version != WRAP_SET_VERSION {
            return Err(WrapError::UnsupportedVersion(self.version));
        }
        if self.algorithm != WRAP_ALGORITHM {
            return Err(WrapError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        for wrap in &self.wraps {
            if wrap.recipient.len() != X25519_LEN
                || wrap.ephemeral_public.len() != X25519_LEN
                || wrap.nonce.len() != XNONCE_LEN
                || wrap.wrapped_dek.len() != DEK_LEN + 16
            {
                return Err(WrapError::MalformedWrap);
            }
        }
        Ok(())
    }
}

/// A payload encrypted under a per-object DEK with a recipient wrap set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedObject {
    /// Content id: SHA-256 of `ciphertext ‖ tag`. Stable object reference used
    /// for supersession linkage.
    pub object_id: Vec<u8>,
    /// AEAD descriptor for the payload (algorithm, nonce, aad).
    pub descriptor: EncryptionDescriptor,
    /// Payload ciphertext.
    pub ciphertext: Vec<u8>,
    /// Payload AEAD tag.
    pub tag: Vec<u8>,
    /// Per-recipient wrap set.
    pub wrap_set: RecipientWrapSet,
    /// When this object was produced by re-encryption, the id of the object it
    /// supersedes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Vec<u8>>,
}

/// Errors from wrapping/unwrapping. All failure modes are closed (no partial
/// success, no plaintext leak).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WrapError {
    /// No recipients were supplied.
    #[error("at least one recipient is required")]
    NoRecipients,
    /// A recipient public key was not 32 bytes.
    #[error("recipient public key must be 32 bytes")]
    BadRecipientKey,
    /// Unknown wrap-set version.
    #[error("unsupported wrap-set version: {0}")]
    UnsupportedVersion(u16),
    /// Unknown wrap algorithm.
    #[error("unsupported wrap algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Unknown payload algorithm.
    #[error("unsupported payload algorithm: {0}")]
    UnsupportedPayloadAlgorithm(String),
    /// A wrap entry has malformed/truncated fields.
    #[error("malformed wrap entry")]
    MalformedWrap,
    /// This recipient has no wrap in the set.
    #[error("no wrap for this recipient")]
    NoWrapForRecipient,
    /// AEAD authentication failed (wrong key, tampering, or truncation).
    #[error("authenticated decryption failed")]
    AeadFailed,
    /// Canonical (de)serialization failed.
    #[error("wrap-set encoding error: {0}")]
    Encoding(String),
}

fn derive_kek(shared: &[u8], ephemeral_public: &[u8], recipient: &[u8]) -> Zeroizing<[u8; 32]> {
    // Bind the KEK to both public keys so a wrap cannot be replayed under a
    // different (ephemeral, recipient) pairing.
    let mut salt = Vec::with_capacity(2 * X25519_LEN);
    salt.extend_from_slice(ephemeral_public);
    salt.extend_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("32 is a valid HKDF-SHA256 output length");
    okm
}

fn wrap_aad(ephemeral_public: &[u8], recipient: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 * X25519_LEN);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient);
    aad
}

fn object_id(ciphertext: &[u8], tag: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.update(tag);
    hasher.finalize().to_vec()
}

fn wrap_dek_for<R: RngCore + CryptoRng>(
    dek: &DataKey,
    recipient: &RecipientPublicKey,
    rng: &mut R,
) -> WrappedKey {
    let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient.0));

    let kek = derive_kek(shared.as_bytes(), ephemeral_public.as_bytes(), &recipient.0);
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());

    let mut nonce_bytes = [0u8; XNONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = wrap_aad(ephemeral_public.as_bytes(), &recipient.0);

    let wrapped_dek = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &dek.0,
                aad: &aad,
            },
        )
        .expect("AEAD encryption of a 32-byte DEK cannot fail");

    WrappedKey {
        recipient: recipient.0.to_vec(),
        ephemeral_public: ephemeral_public.as_bytes().to_vec(),
        nonce: nonce_bytes.to_vec(),
        wrapped_dek,
    }
}

fn build_wraps<R: RngCore + CryptoRng>(
    dek: &DataKey,
    recipients: &[RecipientPublicKey],
    rng: &mut R,
) -> RecipientWrapSet {
    let wraps = recipients
        .iter()
        .map(|recipient| wrap_dek_for(dek, recipient, rng))
        .collect();
    RecipientWrapSet {
        version: WRAP_SET_VERSION,
        algorithm: WRAP_ALGORITHM.to_string(),
        wraps,
    }
}

impl SealedObject {
    /// Encrypt `plaintext` under a fresh DEK and wrap that DEK for each recipient.
    pub fn seal_for_recipients<R: RngCore + CryptoRng>(
        plaintext: &[u8],
        recipients: &[RecipientPublicKey],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<Self, WrapError> {
        if recipients.is_empty() {
            return Err(WrapError::NoRecipients);
        }

        let mut dek_bytes = [0u8; DEK_LEN];
        rng.fill_bytes(&mut dek_bytes);
        let dek = DataKey(dek_bytes);
        dek_bytes.zeroize();

        let mut payload_nonce = [0u8; XNONCE_LEN];
        rng.fill_bytes(&mut payload_nonce);
        let cipher = XChaCha20Poly1305::new((&dek.0).into());
        let mut sealed = cipher
            .encrypt(
                XNonce::from_slice(&payload_nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| WrapError::AeadFailed)?;
        // chacha20poly1305 appends the 16-byte tag; split it out to fit the envelope.
        let tag = sealed.split_off(sealed.len() - 16);
        let ciphertext = sealed;

        let wrap_set = build_wraps(&dek, recipients, rng);

        let mut descriptor = EncryptionDescriptor::new(
            PAYLOAD_ALGORITHM.to_string(),
            hex_id(&object_id(&ciphertext, &tag)),
            payload_nonce.to_vec(),
        );
        if let Some(aad) = aad {
            descriptor = descriptor.with_aad(aad.to_vec());
        }

        Ok(Self {
            object_id: object_id(&ciphertext, &tag),
            descriptor,
            ciphertext,
            tag,
            wrap_set,
            supersedes: None,
        })
    }

    /// Unwrap the DEK with `secret` and decrypt the payload.
    ///
    /// A non-recipient — even holding the whole object — cannot derive the DEK
    /// and receives [`WrapError::NoWrapForRecipient`] or [`WrapError::AeadFailed`].
    pub fn unseal(&self, secret: &RecipientSecretKey) -> Result<Vec<u8>, WrapError> {
        self.wrap_set.validate()?;
        if self.descriptor.algorithm != PAYLOAD_ALGORITHM {
            return Err(WrapError::UnsupportedPayloadAlgorithm(
                self.descriptor.algorithm.clone(),
            ));
        }
        let my_public = secret.public_key().0;
        let wrap = self
            .wrap_set
            .wraps
            .iter()
            .find(|w| w.recipient.as_slice() == my_public.as_slice())
            .ok_or(WrapError::NoWrapForRecipient)?;

        let static_secret = StaticSecret::from(secret.0);
        let mut ephemeral_public = [0u8; X25519_LEN];
        ephemeral_public.copy_from_slice(&wrap.ephemeral_public);
        let shared = static_secret.diffie_hellman(&PublicKey::from(ephemeral_public));

        let kek = derive_kek(shared.as_bytes(), &wrap.ephemeral_public, &wrap.recipient);
        let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
        let aad = wrap_aad(&wrap.ephemeral_public, &wrap.recipient);
        let dek_bytes = cipher
            .decrypt(
                XNonce::from_slice(&wrap.nonce),
                Payload {
                    msg: &wrap.wrapped_dek,
                    aad: &aad,
                },
            )
            .map_err(|_| WrapError::AeadFailed)?;
        let dek = DataKey(
            dek_bytes
                .as_slice()
                .try_into()
                .map_err(|_| WrapError::AeadFailed)?,
        );
        // dek_bytes is a Vec; zeroize it now that the DEK is copied out.
        let mut dek_bytes = dek_bytes;
        dek_bytes.zeroize();

        let payload_cipher = XChaCha20Poly1305::new((&dek.0).into());
        let mut combined = self.ciphertext.clone();
        combined.extend_from_slice(&self.tag);
        payload_cipher
            .decrypt(
                XNonce::from_slice(&self.descriptor.nonce),
                Payload {
                    msg: &combined,
                    aad: self.descriptor.aad.as_deref().unwrap_or(&[]),
                },
            )
            .map_err(|_| WrapError::AeadFailed)
        // `dek` is dropped here and zeroized (ZeroizeOnDrop).
    }

    /// Re-encrypt `plaintext` for a new recipient set, producing a new object
    /// that supersedes this one (a fresh DEK and fresh wraps).
    ///
    /// Removing a recipient from `new_recipients` removes their access to the
    /// **new** object only. See the module docs: prior key holders may retain
    /// access to the object they already have.
    pub fn reseal_for_recipients<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        new_recipients: &[RecipientPublicKey],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<Self, WrapError> {
        let mut next = Self::seal_for_recipients(plaintext, new_recipients, aad, rng)?;
        next.supersedes = Some(self.object_id.clone());
        Ok(next)
    }
}

fn hex_id(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Deterministic test RNG (splitmix64). Test-only; keeps the library and its
    /// wasm build free of any `getrandom`/`OsRng` dependency.
    struct TestRng {
        state: u64,
    }
    impl RngCore for TestRng {
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    /// A fresh, distinctly-seeded RNG per call so generated keys never collide.
    fn rng() -> TestRng {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        TestRng {
            state: COUNTER.fetch_add(0x1234_5678_9ABC_DEF1, Ordering::Relaxed),
        }
    }

    fn recipients(n: usize) -> (Vec<RecipientSecretKey>, Vec<RecipientPublicKey>) {
        let mut secrets = Vec::new();
        let mut publics = Vec::new();
        for _ in 0..n {
            let (s, p) = RecipientSecretKey::generate(&mut rng());
            secrets.push(s);
            publics.push(p);
        }
        (secrets, publics)
    }

    #[test]
    fn recipient_can_unseal_nonrecipient_cannot() {
        let (secrets, publics) = recipients(2);
        let (outsider, _outsider_pub) = RecipientSecretKey::generate(&mut rng());
        let msg = b"private consignment payload";

        let obj = SealedObject::seal_for_recipients(msg, &publics, None, &mut rng()).unwrap();

        assert_eq!(obj.unseal(&secrets[0]).unwrap(), msg);
        assert_eq!(obj.unseal(&secrets[1]).unwrap(), msg);
        // Outsider holds the whole object but has no wrap.
        assert_eq!(obj.unseal(&outsider), Err(WrapError::NoWrapForRecipient));
    }

    #[test]
    fn one_two_and_many_recipients() {
        for n in [1usize, 2, 13] {
            let (secrets, publics) = recipients(n);
            let msg = format!("payload for {n} recipients");
            let obj = SealedObject::seal_for_recipients(msg.as_bytes(), &publics, None, &mut rng())
                .unwrap();
            assert_eq!(obj.wrap_set.wraps.len(), n);
            for secret in &secrets {
                assert_eq!(obj.unseal(secret).unwrap(), msg.as_bytes());
            }
        }
    }

    #[test]
    fn rotation_removes_future_access() {
        let (secrets, publics) = recipients(3);
        let msg = b"rotate me";
        let obj = SealedObject::seal_for_recipients(msg, &publics, None, &mut rng()).unwrap();

        // Remove recipient index 2 by re-encrypting for the first two only.
        let kept = vec![publics[0], publics[1]];
        let rotated = obj
            .reseal_for_recipients(msg, &kept, None, &mut rng())
            .unwrap();

        assert_eq!(rotated.supersedes.as_ref(), Some(&obj.object_id));
        assert_ne!(rotated.object_id, obj.object_id);
        // Kept recipients can open the new object.
        assert_eq!(rotated.unseal(&secrets[0]).unwrap(), msg);
        // The removed recipient cannot open the new object.
        assert_eq!(
            rotated.unseal(&secrets[2]),
            Err(WrapError::NoWrapForRecipient)
        );
        // But (honesty) they can still open the OLD object they already hold.
        assert_eq!(obj.unseal(&secrets[2]).unwrap(), msg);
    }

    #[test]
    fn wrap_set_serialization_is_canonical_and_roundtrips() {
        let (_secrets, publics) = recipients(3);
        let obj = SealedObject::seal_for_recipients(b"x", &publics, None, &mut rng()).unwrap();
        let bytes = obj.wrap_set.to_canonical_cbor().unwrap();
        let bytes2 = obj.wrap_set.to_canonical_cbor().unwrap();
        assert_eq!(bytes, bytes2, "canonical encoding must be deterministic");
        let decoded = RecipientWrapSet::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, obj.wrap_set);
    }

    #[test]
    fn unknown_version_and_algorithm_fail_closed() {
        let (_s, publics) = recipients(1);
        let obj = SealedObject::seal_for_recipients(b"x", &publics, None, &mut rng()).unwrap();

        let mut bad_version = obj.wrap_set.clone();
        bad_version.version = 99;
        let bytes = csv_codec::to_canonical_cbor(&bad_version).unwrap();
        assert_eq!(
            RecipientWrapSet::from_canonical_cbor(&bytes),
            Err(WrapError::UnsupportedVersion(99))
        );

        let mut bad_algo = obj.wrap_set.clone();
        bad_algo.algorithm = "rot13".to_string();
        let bytes = csv_codec::to_canonical_cbor(&bad_algo).unwrap();
        assert!(matches!(
            RecipientWrapSet::from_canonical_cbor(&bytes),
            Err(WrapError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn truncated_wrap_fails_closed() {
        let (secrets, publics) = recipients(1);
        let mut obj = SealedObject::seal_for_recipients(b"x", &publics, None, &mut rng()).unwrap();
        // Truncate the wrapped DEK.
        obj.wrap_set.wraps[0].wrapped_dek.truncate(10);
        assert_eq!(obj.unseal(&secrets[0]), Err(WrapError::MalformedWrap));
    }

    #[test]
    fn tampered_wrapped_dek_fails_closed() {
        let (secrets, publics) = recipients(1);
        let mut obj = SealedObject::seal_for_recipients(b"x", &publics, None, &mut rng()).unwrap();
        let last = obj.wrap_set.wraps[0].wrapped_dek.len() - 1;
        obj.wrap_set.wraps[0].wrapped_dek[last] ^= 0xff;
        assert_eq!(obj.unseal(&secrets[0]), Err(WrapError::AeadFailed));
    }

    #[test]
    fn no_recipients_is_rejected() {
        assert_eq!(
            SealedObject::seal_for_recipients(b"x", &[], None, &mut rng()).unwrap_err(),
            WrapError::NoRecipients
        );
    }

    #[test]
    fn aad_is_bound_to_payload() {
        let (secrets, publics) = recipients(1);
        let obj = SealedObject::seal_for_recipients(b"x", &publics, Some(b"context"), &mut rng())
            .unwrap();
        // Correct recipient with intact AAD succeeds.
        assert_eq!(obj.unseal(&secrets[0]).unwrap(), b"x");
        // Corrupting the bound AAD breaks payload authentication.
        let mut tampered = obj.clone();
        tampered.descriptor.aad = Some(b"different".to_vec());
        assert_eq!(tampered.unseal(&secrets[0]), Err(WrapError::AeadFailed));
    }
}
