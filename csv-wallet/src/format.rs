//! Portable wallet file format — the single normative envelope shared by
//! `csv-cli` and `csv-wallet` (WALLETFMT-SPEC-002).
//!
//! This module owns the one versioned, encrypted, authenticated wallet
//! interchange format. Both the reference CLI and the graphical wallet MUST
//! use this implementation; no presentation layer may define an alternate
//! serialization or crypto path (see the architecture charter,
//! "Wallet interoperability" and "No duplicated ... wallet-format
//! implementation").
//!
//! # Threat model & guarantees
//!
//! The portable file carries mnemonic / seed material. An attacker may supply
//! an arbitrary file. The format therefore:
//!
//! - **Authenticates the header.** The versioned header (magic, format
//!   version, KDF identifier and parameters, cipher identifier, salt, nonce)
//!   is canonically encoded and bound as AEAD associated data. Any bit flip in
//!   the header changes the AAD and fails decryption closed.
//! - **Encodes the protected payload canonically.** The plaintext is
//!   deterministic CBOR (RFC 8949 §4.2) via [`csv_codec`]. On decode the
//!   payload is re-encoded and compared byte-for-byte; a non-canonical payload
//!   is rejected.
//! - **Bounds attacker-controlled resources.** File size, plaintext size, and
//!   the KDF cost parameters (memory / iterations / parallelism) are clamped to
//!   sane ranges *before* the memory-hard KDF runs, so a hostile file cannot
//!   force unbounded memory or CPU use.
//! - **Fails closed.** Wrong password, tampering, truncation, unknown version,
//!   unsupported KDF/cipher, and non-canonical payloads all return an error.
//!   There is no plaintext / legacy fallback (charter: "No silent legacy /
//!   plaintext wallet import fallback").
//! - **Zeroizes plaintext secrets.** Derived keys and decrypted plaintext
//!   buffers are wiped; secret-bearing payload fields zeroize on drop and are
//!   never included in `Debug` output or logs.
//!
//! # Excluded from the portable payload
//!
//! The payload deliberately has no field for runtime authority or caches:
//! runtime leases, replay state, execution journals, in-progress transfer
//! authority, explorer caches, RPC credentials, or UI preferences. Those live
//! only in `csv-runtime` / local UI state and MUST NOT travel in this file
//! (charter: "It must not contain runtime leases, ..."). The exclusion is
//! structural — there is nowhere to put them — and asserted by tests.
//!
//! # Migration policy
//!
//! This is an explicit *export* envelope. The CLI unified state file
//! (`csv-cli/src/encrypt.rs`) is a different, non-portable at-rest format and
//! is **not** silently reinterpreted as a portable wallet. Producing a
//! portable file is an explicit export step; consuming one is an explicit
//! import step. Unknown [`FORMAT_VERSION`] values are rejected rather than
//! best-effort decoded; a future version bump ships an explicit upgrade path.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Magic bytes identifying a portable CSV wallet file (`CSVW`).
pub const MAGIC: [u8; 4] = *b"CSVW";

/// Current normative envelope format version. Unknown versions are rejected.
pub const FORMAT_VERSION: u16 = 1;

/// Current protected-payload schema version.
pub const PAYLOAD_SCHEMA_VERSION: u16 = 1;

/// Salt length in bytes.
pub const SALT_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Derived key length in bytes (AES-256).
pub const KEY_LEN: usize = 32;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Maximum accepted on-disk envelope size. Bounds a hostile file before it is
/// parsed or a KDF is run.
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum accepted decrypted payload size.
pub const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// KDF cost bounds. Values outside these ranges are rejected before the KDF
/// runs, both to refuse attacker-forced resource exhaustion (upper bounds) and
/// to refuse a deliberately weakened KDF (lower bounds).
pub mod kdf_bounds {
    /// Minimum Argon2id memory cost in KiB (32 MiB).
    pub const MIN_MEMORY_KIB: u32 = 32 * 1024;
    /// Maximum Argon2id memory cost in KiB (1 GiB).
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    /// Minimum Argon2id iterations.
    pub const MIN_ITERATIONS: u32 = 1;
    /// Maximum Argon2id iterations.
    pub const MAX_ITERATIONS: u32 = 16;
    /// Minimum Argon2id parallelism (lanes).
    pub const MIN_PARALLELISM: u32 = 1;
    /// Maximum Argon2id parallelism (lanes).
    pub const MAX_PARALLELISM: u32 = 16;
}

/// Default Argon2id parameters used when exporting (64 MiB, 3 passes, 4 lanes).
pub const DEFAULT_KDF: KdfParams = KdfParams {
    algorithm: KdfId::Argon2id,
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 4,
    output_len: KEY_LEN as u32,
};

/// Errors produced by the portable wallet format.
///
/// Error text never contains secret material. Wrong password, tampering, and
/// truncation deliberately collapse into a single [`Decryption`] variant so the
/// format is not a distinguishing oracle.
#[derive(Debug, Error)]
pub enum FormatError {
    /// The envelope byte length exceeds [`MAX_ENVELOPE_BYTES`].
    #[error("wallet file too large: {0} bytes exceeds import limit")]
    EnvelopeTooLarge(usize),

    /// The decrypted payload exceeds [`MAX_PLAINTEXT_BYTES`].
    #[error("decrypted wallet payload too large")]
    PayloadTooLarge,

    /// The envelope could not be parsed as canonical CBOR / had a bad magic.
    #[error("malformed wallet envelope")]
    MalformedEnvelope,

    /// The envelope declares an unsupported [`FORMAT_VERSION`].
    #[error("unsupported wallet format version: {0}")]
    UnknownVersion(u16),

    /// The KDF identifier is not supported.
    #[error("unsupported key-derivation function")]
    UnsupportedKdf,

    /// The cipher identifier is not supported.
    #[error("unsupported cipher")]
    UnsupportedCipher,

    /// A KDF parameter is outside the accepted [`kdf_bounds`].
    #[error("key-derivation parameters out of accepted bounds")]
    KdfParamsOutOfBounds,

    /// Salt or nonce length did not match the declared cipher/KDF.
    #[error("invalid salt or nonce length")]
    InvalidCryptoLengths,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,

    /// Authenticated decryption failed: wrong password, tampering, or
    /// truncation. Intentionally indistinguishable.
    #[error("wallet decryption failed: wrong password or corrupted file")]
    Decryption,

    /// The decrypted payload was not canonical CBOR for the payload schema.
    #[error("wallet payload is not canonically encoded")]
    NoncanonicalPayload,

    /// Encoding / encryption failed while producing an envelope.
    #[error("failed to encode wallet envelope")]
    Encoding,
}

/// Result alias for format operations.
pub type Result<T> = std::result::Result<T, FormatError>;

/// Supported key-derivation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KdfId {
    /// Argon2id (memory-hard), the only accepted KDF.
    Argon2id,
}

/// Supported authenticated ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CipherId {
    /// AES-256-GCM, the only accepted cipher.
    Aes256Gcm,
}

/// KDF identifier and cost parameters. Part of the authenticated header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Key-derivation function.
    pub algorithm: KdfId,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration (time) cost.
    pub iterations: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
    /// Derived key length in bytes.
    pub output_len: u32,
}

impl KdfParams {
    /// Validate the parameters against [`kdf_bounds`]. Called before the KDF
    /// runs so an attacker-supplied file cannot force excessive resources.
    fn validate(&self) -> Result<()> {
        if self.algorithm != KdfId::Argon2id {
            return Err(FormatError::UnsupportedKdf);
        }
        if self.output_len as usize != KEY_LEN {
            return Err(FormatError::KdfParamsOutOfBounds);
        }
        let in_range = self.memory_kib >= kdf_bounds::MIN_MEMORY_KIB
            && self.memory_kib <= kdf_bounds::MAX_MEMORY_KIB
            && self.iterations >= kdf_bounds::MIN_ITERATIONS
            && self.iterations <= kdf_bounds::MAX_ITERATIONS
            && self.parallelism >= kdf_bounds::MIN_PARALLELISM
            && self.parallelism <= kdf_bounds::MAX_PARALLELISM;
        if !in_range {
            return Err(FormatError::KdfParamsOutOfBounds);
        }
        Ok(())
    }
}

/// Versioned, authenticated header. Bound as AEAD associated data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WalletHeader {
    /// Magic bytes ([`MAGIC`]).
    magic: [u8; 4],
    /// Envelope format version.
    format_version: u16,
    /// Key-derivation identifier and parameters.
    kdf: KdfParams,
    /// Authenticated-encryption cipher.
    cipher: CipherId,
    /// KDF salt.
    salt: Vec<u8>,
    /// AEAD nonce.
    nonce: Vec<u8>,
}

/// On-disk envelope: authenticated header plus the sealed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletEnvelope {
    /// Authenticated header.
    header: WalletHeader,
    /// AES-256-GCM ciphertext with appended authentication tag.
    ciphertext: Vec<u8>,
}

/// A single source of key material carried in the portable file.
///
/// The `secret` bytes are wiped on drop and never appear in `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySource {
    /// Stable identifier for this source within the file.
    pub id: String,
    /// The kind of secret material held in `secret`.
    pub kind: KeySourceKind,
    /// The secret material (mnemonic UTF-8 bytes, seed bytes, or key bytes).
    pub secret: Vec<u8>,
}

/// The kind of a [`KeySource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeySourceKind {
    /// A BIP-39 mnemonic phrase (UTF-8 bytes).
    Mnemonic,
    /// A raw derivation seed.
    Seed,
    /// A single raw private key.
    PrivateKey,
}

impl Drop for KeySource {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySource")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// A derivation profile describing how accounts are derived from a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationProfile {
    /// Identifier of the [`KeySource`] this profile derives from.
    pub source_id: String,
    /// BIP-32 style derivation path (e.g. `m/44'/0'/0'`).
    pub path: String,
    /// Human-readable profile name.
    pub name: String,
}

/// A known (public) account and its user label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownAccount {
    /// Chain identifier (e.g. `bitcoin`, `ethereum`).
    pub chain: String,
    /// Public address string.
    pub address: String,
    /// Optional user-assigned label.
    pub label: String,
}

/// The protected (encrypted) portable wallet payload.
///
/// This is the exhaustive list of what a portable file may contain. It has no
/// field for runtime authority or caches (leases, replay state, journals,
/// in-progress transfers, explorer caches, RPC credentials, UI preferences);
/// that exclusion is intentional and enforced structurally.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPayload {
    /// Payload schema version.
    pub schema_version: u16,
    /// Key source material.
    pub key_sources: Vec<KeySource>,
    /// Derivation profiles.
    pub derivation_profiles: Vec<DerivationProfile>,
    /// Known accounts.
    pub accounts: Vec<KnownAccount>,
    /// User labels keyed by an application-defined string. Sorted for
    /// canonical encoding.
    pub labels: std::collections::BTreeMap<String, String>,
}

impl WalletPayload {
    /// Create an empty payload at the current [`PAYLOAD_SCHEMA_VERSION`].
    pub fn new() -> Self {
        Self {
            schema_version: PAYLOAD_SCHEMA_VERSION,
            key_sources: Vec::new(),
            derivation_profiles: Vec::new(),
            accounts: Vec::new(),
            labels: std::collections::BTreeMap::new(),
        }
    }
}

impl Default for WalletPayload {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for WalletPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render secret material. Show shape only.
        f.debug_struct("WalletPayload")
            .field("schema_version", &self.schema_version)
            .field("key_sources", &self.key_sources.len())
            .field("derivation_profiles", &self.derivation_profiles)
            .field("accounts", &self.accounts)
            .field("labels", &self.labels)
            .finish()
    }
}

/// Derive a 32-byte key from `passphrase` using validated Argon2id parameters.
/// The returned key zeroizes on drop.
fn derive_key(
    passphrase: &str,
    params: &KdfParams,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    params.validate()?;
    if salt.len() != SALT_LEN {
        return Err(FormatError::InvalidCryptoLengths);
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| FormatError::KdfParamsOutOfBounds)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| FormatError::KeyDerivation)?;
    Ok(key)
}

/// Fill `buf` with cryptographically secure random bytes.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| FormatError::Encoding)
}

/// Seal `payload` into an on-disk envelope with fixed salt and nonce.
///
/// Separated from [`encrypt`] so golden vectors can pin the randomness. Callers
/// in production MUST use fresh random salt and nonce (see [`encrypt`]); reusing
/// a (key, nonce) pair breaks AES-GCM.
fn seal(
    payload: &WalletPayload,
    passphrase: &str,
    kdf: &KdfParams,
    salt: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(FormatError::InvalidCryptoLengths);
    }

    // Canonical plaintext. Wiped after encryption.
    let mut plaintext =
        Zeroizing::new(csv_codec::to_canonical_cbor(payload).map_err(|_| FormatError::Encoding)?);
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(FormatError::PayloadTooLarge);
    }

    let header = WalletHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        kdf: *kdf,
        cipher: CipherId::Aes256Gcm,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
    };
    let aad = csv_codec::to_canonical_cbor(&header).map_err(|_| FormatError::Encoding)?;

    let key = derive_key(passphrase, kdf, salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| FormatError::Encoding)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| FormatError::Encoding)?;
    plaintext.zeroize();

    let envelope = WalletEnvelope { header, ciphertext };
    let bytes = csv_codec::to_canonical_cbor(&envelope).map_err(|_| FormatError::Encoding)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(FormatError::EnvelopeTooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// Encrypt `payload` into a portable wallet file using [`DEFAULT_KDF`] and a
/// fresh random salt and nonce.
pub fn encrypt(payload: &WalletPayload, passphrase: &str) -> Result<Vec<u8>> {
    encrypt_with_params(payload, passphrase, &DEFAULT_KDF)
}

/// Encrypt `payload` with caller-chosen (validated) KDF parameters.
pub fn encrypt_with_params(
    payload: &WalletPayload,
    passphrase: &str,
    kdf: &KdfParams,
) -> Result<Vec<u8>> {
    kdf.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    seal(payload, passphrase, kdf, &salt, &nonce)
}

/// Decrypt and validate a portable wallet file.
///
/// Fails closed on: oversize input, malformed / non-canonical framing, bad
/// magic, unknown version, unsupported KDF or cipher, out-of-bounds KDF
/// parameters, wrong password, tampering, truncation, oversize plaintext, and a
/// non-canonical protected payload.
pub fn decrypt(envelope_bytes: &[u8], passphrase: &str) -> Result<WalletPayload> {
    // 1. Bound the file before parsing.
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(FormatError::EnvelopeTooLarge(envelope_bytes.len()));
    }

    // 2. Parse the envelope framing.
    let envelope: WalletEnvelope = csv_codec::from_canonical_cbor(envelope_bytes)
        .map_err(|_| FormatError::MalformedEnvelope)?;
    let header = &envelope.header;

    // 3. Identify and version-check before any expensive work.
    if header.magic != MAGIC {
        return Err(FormatError::MalformedEnvelope);
    }
    if header.format_version != FORMAT_VERSION {
        return Err(FormatError::UnknownVersion(header.format_version));
    }
    if header.cipher != CipherId::Aes256Gcm {
        return Err(FormatError::UnsupportedCipher);
    }
    // 4. Bound attacker-controlled KDF cost before running the KDF.
    header.kdf.validate()?;
    if header.salt.len() != SALT_LEN || header.nonce.len() != NONCE_LEN {
        return Err(FormatError::InvalidCryptoLengths);
    }
    // A valid GCM output is at least the tag; reject impossibly short bodies.
    if envelope.ciphertext.len() < TAG_LEN
        || envelope.ciphertext.len() - TAG_LEN > MAX_PLAINTEXT_BYTES
    {
        return Err(FormatError::Decryption);
    }

    // 5. Recompute the authenticated header and decrypt.
    let aad = csv_codec::to_canonical_cbor(header).map_err(|_| FormatError::MalformedEnvelope)?;
    let key = derive_key(passphrase, &header.kdf, &header.salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| FormatError::Decryption)?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&header.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| FormatError::Decryption)?,
    );
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(FormatError::PayloadTooLarge);
    }

    // 6. Decode the payload and enforce canonical encoding.
    let payload: WalletPayload = csv_codec::from_canonical_cbor(plaintext.as_slice())
        .map_err(|_| FormatError::NoncanonicalPayload)?;
    let recoded =
        csv_codec::to_canonical_cbor(&payload).map_err(|_| FormatError::NoncanonicalPayload)?;
    if recoded.as_slice() != plaintext.as_slice() {
        return Err(FormatError::NoncanonicalPayload);
    }
    plaintext.zeroize();

    // Reject unknown payload schema versions rather than best-effort decoding.
    if payload.schema_version != PAYLOAD_SCHEMA_VERSION {
        return Err(FormatError::UnknownVersion(payload.schema_version));
    }

    Ok(payload)
}

/// The normative golden wallet file for [`FORMAT_VERSION`] 1.
///
/// This is the conformance artifact every application that speaks the portable
/// format must be able to import (`csv-cli`, `csv-wallet`). It is checked in as
/// bytes on purpose: an implementation that can still encrypt/decrypt its *own*
/// output has proven nothing about interoperability. Regenerate it only by a
/// deliberate format change — see `regenerate_golden_wallet_v1` in this module's
/// tests, and expect every consumer's golden test to fail until they agree.
pub const GOLDEN_WALLET_V1: &[u8] = include_bytes!("../tests/fixtures/golden-wallet-v1.csvw");

/// Passphrase that opens [`GOLDEN_WALLET_V1`]. Test material only — the golden
/// file carries a well-known BIP-39 test vector, never live funds.
pub const GOLDEN_WALLET_V1_PASSPHRASE: &str = "golden-passphrase";

/// The BIP-39 test mnemonic carried by [`GOLDEN_WALLET_V1`].
pub const GOLDEN_WALLET_V1_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Build the payload that [`GOLDEN_WALLET_V1`] must decrypt to.
///
/// Consumers assert against this so a drifting decoder is caught in *their*
/// test suite, not in production.
pub fn golden_wallet_v1_payload() -> WalletPayload {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("primary".to_string(), "Golden test wallet".to_string());
    WalletPayload {
        schema_version: PAYLOAD_SCHEMA_VERSION,
        key_sources: vec![KeySource {
            id: "primary".to_string(),
            kind: KeySourceKind::Mnemonic,
            secret: GOLDEN_WALLET_V1_MNEMONIC.as_bytes().to_vec(),
        }],
        derivation_profiles: vec![
            DerivationProfile {
                source_id: "primary".to_string(),
                path: "m/86'/0'/0'/0/0".to_string(),
                name: "bitcoin".to_string(),
            },
            DerivationProfile {
                source_id: "primary".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                name: "ethereum".to_string(),
            },
        ],
        accounts: vec![
            KnownAccount {
                chain: "bitcoin".to_string(),
                address: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
                    .to_string(),
                label: "bitcoin Account (golden)".to_string(),
            },
            KnownAccount {
                chain: "ethereum".to_string(),
                address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_string(),
                label: "ethereum Account (golden)".to_string(),
            },
        ],
        labels,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_payload() -> WalletPayload {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("primary".to_string(), "Main savings".to_string());
        labels.insert("cold".to_string(), "Cold storage".to_string());
        WalletPayload {
            schema_version: PAYLOAD_SCHEMA_VERSION,
            key_sources: vec![KeySource {
                id: "src-0".to_string(),
                kind: KeySourceKind::Mnemonic,
                secret: b"abandon abandon abandon abandon abandon about".to_vec(),
            }],
            derivation_profiles: vec![DerivationProfile {
                source_id: "src-0".to_string(),
                path: "m/44'/0'/0'".to_string(),
                name: "Bitcoin account 0".to_string(),
            }],
            accounts: vec![KnownAccount {
                chain: "bitcoin".to_string(),
                address: "bc1qexampleaddress".to_string(),
                label: "receive".to_string(),
            }],
            labels,
        }
    }

    // Fast KDF for tests so the suite stays quick while remaining in-bounds.
    fn test_kdf() -> KdfParams {
        KdfParams {
            algorithm: KdfId::Argon2id,
            memory_kib: kdf_bounds::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
            output_len: KEY_LEN as u32,
        }
    }

    #[test]
    fn round_trip_recovers_payload() {
        let payload = sample_payload();
        let bytes =
            encrypt_with_params(&payload, "correct horse battery staple", &test_kdf()).unwrap();
        let decoded = decrypt(&bytes, "correct horse battery staple").unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn default_kdf_round_trip() {
        let payload = sample_payload();
        let bytes = encrypt(&payload, "pw").unwrap();
        assert_eq!(decrypt(&bytes, "pw").unwrap(), payload);
    }

    #[test]
    fn wrong_password_fails_closed() {
        let bytes = encrypt_with_params(&sample_payload(), "right", &test_kdf()).unwrap();
        assert!(matches!(
            decrypt(&bytes, "wrong"),
            Err(FormatError::Decryption)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let mut bytes = encrypt_with_params(&sample_payload(), "pw", &test_kdf()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(decrypt(&bytes, "pw").is_err());
    }

    #[test]
    fn tampered_header_fails_closed() {
        // Flip a byte inside the header region (near the front, past the CBOR
        // map opener) and confirm AAD binding rejects it.
        let bytes = encrypt_with_params(&sample_payload(), "pw", &test_kdf()).unwrap();
        // Find and corrupt the salt/nonce/kdf area by flipping several early
        // bytes until decode fails; header is bound as AAD so any accepted
        // parse must fail authentication.
        let mut any_tamper_rejected = true;
        for i in 4..24.min(bytes.len()) {
            let mut c = bytes.clone();
            c[i] ^= 0xFF;
            if decrypt(&c, "pw").is_ok() {
                any_tamper_rejected = false;
                break;
            }
        }
        assert!(any_tamper_rejected, "header tampering must fail closed");
    }

    #[test]
    fn truncation_fails_closed() {
        let bytes = encrypt_with_params(&sample_payload(), "pw", &test_kdf()).unwrap();
        let truncated = &bytes[..bytes.len() - 4];
        assert!(decrypt(truncated, "pw").is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let bytes = seal(&sample_payload(), "pw", &test_kdf(), &salt, &nonce).unwrap();
        let mut envelope: WalletEnvelope = csv_codec::from_canonical_cbor(&bytes).unwrap();
        envelope.header.format_version = 999;
        let bad = csv_codec::to_canonical_cbor(&envelope).unwrap();
        assert!(matches!(
            decrypt(&bad, "pw"),
            Err(FormatError::UnknownVersion(999))
        ));
    }

    #[test]
    fn out_of_bounds_kdf_rejected_before_derivation() {
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];
        let bytes = seal(&sample_payload(), "pw", &test_kdf(), &salt, &nonce).unwrap();
        let mut envelope: WalletEnvelope = csv_codec::from_canonical_cbor(&bytes).unwrap();
        // Absurd memory cost an attacker might use to exhaust the importer.
        envelope.header.kdf.memory_kib = kdf_bounds::MAX_MEMORY_KIB + 1;
        let bad = csv_codec::to_canonical_cbor(&envelope).unwrap();
        assert!(matches!(
            decrypt(&bad, "pw"),
            Err(FormatError::KdfParamsOutOfBounds)
        ));
    }

    #[test]
    fn unknown_payload_schema_version_rejected() {
        // A payload that authenticates and decodes canonically but carries an
        // unrecognized schema version must be rejected, not best-effort read.
        let salt = [5u8; SALT_LEN];
        let nonce = [6u8; NONCE_LEN];
        let kdf = test_kdf();
        let mut payload = sample_payload();
        payload.schema_version = 2;
        let bytes = seal(&payload, "pw", &kdf, &salt, &nonce).unwrap();
        assert!(matches!(
            decrypt(&bytes, "pw"),
            Err(FormatError::UnknownVersion(2))
        ));
    }

    #[test]
    fn oversize_envelope_rejected() {
        let big = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            decrypt(&big, "pw"),
            Err(FormatError::EnvelopeTooLarge(_))
        ));
    }

    #[test]
    fn garbage_input_rejected() {
        assert!(matches!(
            decrypt(b"not a wallet file at all", "pw"),
            Err(FormatError::MalformedEnvelope)
        ));
    }

    #[test]
    fn noncanonical_payload_rejected() {
        // Hand-build an envelope whose plaintext is valid-but-non-canonical
        // CBOR for WalletPayload, then confirm decrypt rejects it.
        use ciborium::value::Value;

        let salt = [3u8; SALT_LEN];
        let nonce = [4u8; NONCE_LEN];
        let kdf = test_kdf();

        // Non-canonical map: keys in non-sorted order and an extra unknown key
        // is not allowed, so instead we perturb by encoding with unsorted keys.
        // ciborium `Value` map preserves insertion order and is NOT sorted.
        let payload = sample_payload();
        let canonical = csv_codec::to_canonical_cbor(&payload).unwrap();
        // Decode to a Value then re-encode WITHOUT canonical normalization,
        // reversing map key order to guarantee a non-canonical byte string.
        let mut value: Value = ciborium::from_reader(canonical.as_slice()).unwrap();
        fn reverse_maps(v: &mut Value) {
            match v {
                Value::Map(entries) => {
                    for (_, val) in entries.iter_mut() {
                        reverse_maps(val);
                    }
                    entries.reverse();
                }
                Value::Array(items) => {
                    for it in items {
                        reverse_maps(it);
                    }
                }
                _ => {}
            }
        }
        reverse_maps(&mut value);
        let mut noncanonical = Vec::new();
        ciborium::into_writer(&value, &mut noncanonical).unwrap();
        // Sanity: it must differ from canonical, else the test proves nothing.
        assert_ne!(noncanonical, canonical);

        // Seal this raw plaintext under a matching header.
        let header = WalletHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            kdf,
            cipher: CipherId::Aes256Gcm,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
        };
        let aad = csv_codec::to_canonical_cbor(&header).unwrap();
        let key = derive_key("pw", &kdf, &salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &noncanonical,
                    aad: &aad,
                },
            )
            .unwrap();
        let envelope = WalletEnvelope {
            header,
            ciphertext: ct,
        };
        let bytes = csv_codec::to_canonical_cbor(&envelope).unwrap();

        assert!(matches!(
            decrypt(&bytes, "pw"),
            Err(FormatError::NoncanonicalPayload)
        ));
    }

    #[test]
    fn golden_vector_is_stable_and_decodes() {
        // Pinned inputs → deterministic Argon2id → deterministic envelope.
        let salt = [0x11u8; SALT_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let kdf = test_kdf();
        let payload = sample_payload();
        let bytes = seal(&payload, "golden-passphrase", &kdf, &salt, &nonce).unwrap();

        // Regression guard: the on-disk bytes must not drift silently. If the
        // format intentionally changes, regenerate this vector deliberately.
        let hex = hex::encode(&bytes);
        assert_eq!(hex, GOLDEN_VECTOR_HEX, "golden vector drift detected");

        // And it must decode back to the original payload.
        let decoded = decrypt(&bytes, "golden-passphrase").unwrap();
        assert_eq!(decoded, payload);
    }

    // Regenerate deliberately if the format changes (see test above).
    const GOLDEN_VECTOR_HEX: &str = "a266686561646572a6636b6466a569616c676f726974686d684172676f6e3269646a697465726174696f6e73016a6d656d6f72795f6b69621980006a6f75747075745f6c656e18206b706172616c6c656c69736d016473616c7498201111111111111111111111111111111111111111111111111111111111111111656d61676963841843185318561857656e6f6e63658c182218221822182218221822182218221822182218221822666369706865726941657332353647636d6e666f726d61745f76657273696f6e016a63697068657274657874990168183a18841879183d18f218c318df0d0b18b4182318ce18ac18cd0a189a18f418e1182f18b718f618c418e8188c18b818a4186918c9185718c6183518b91118fb18bd0c188318b4187618ce189f1854181818e90d182c188318f318591862183c18a1189518e51871186b18e6186018f6184e188b18fa183e18ba18a01852187f18a318ef189f18b5182918a7186718bd18c0186d18e118a618211845188d18c218251618f518a6189b18871862186c09181c18d20b181b18da18e518ae185406187c0a18fe070818d918e5187118f0188218f6185e187a1618cd18260c188b183618fa187c18ad1871186b18a21853182518e518cc18fb1862189c18e90618ad184118f71866181f101831183b184818fc189218cf184218f01850188f18ce1893181918f1181918480f1894187d0d183d18d3188f182e185118fe188b18a5187418cb188b185a18c002185c187118421835187b18de18a8187c1838181918fe18fa13187c07188d18ab186818b4187418f0184a18ad183a183118ab0b18520b18e4187018e9187d181b182d18bd184a181c186018361862183d18bb188818af1846182e18cc18581879185f187f18d618b00a18ad18321869182d185b189318b718d00b18181871186f18cc188c182b187718861890185b18f5189a18e4189218d4185918ce1839189d18fd13184e18581871185018af185d1896182a189618a918c0182b18f218ef183418610705184718f118f0189618ff188b188218bc0718ef186f184f18f218c2187e1850182a18f018b318f109184a181b184618ff18f418d9184a188b189618a318ee187618b5183c18e918ed186718a2186418e7181e1418fd18b618781850184718f2189c185d18a9187818420e18c4182318d818d618a91860189f18ea18ad18a318e4001823185818f4181a18ec18b418dd18a818201318b418c818ea18a11871";

    #[test]
    fn payload_debug_never_leaks_secret() {
        let payload = sample_payload();
        let rendered = format!("{:?}", payload);
        assert!(!rendered.contains("abandon"));
        assert!(!rendered.contains("about"));
    }

    #[test]
    fn keysource_debug_redacts_secret() {
        let src = KeySource {
            id: "x".to_string(),
            kind: KeySourceKind::Seed,
            secret: b"supersecretseed".to_vec(),
        };
        let rendered = format!("{:?}", src);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("supersecretseed"));
    }

    #[test]
    fn payload_has_no_runtime_authority_fields() {
        // Structural guard: the canonical field set is exactly these. Adding a
        // lease/replay/journal/cache/RPC/UI field must break this test and
        // force a charter review.
        let payload = WalletPayload::new();
        let value: ciborium::value::Value = {
            let bytes = csv_codec::to_canonical_cbor(&payload).unwrap();
            ciborium::from_reader(bytes.as_slice()).unwrap()
        };
        let keys: Vec<String> = match value {
            ciborium::value::Value::Map(entries) => entries
                .into_iter()
                .filter_map(|(k, _)| match k {
                    ciborium::value::Value::Text(t) => Some(t),
                    _ => None,
                })
                .collect(),
            _ => panic!("payload must encode as a map"),
        };
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "accounts".to_string(),
                "derivation_profiles".to_string(),
                "key_sources".to_string(),
                "labels".to_string(),
                "schema_version".to_string(),
            ]
        );
    }

    /// Fixed inputs for the checked-in golden file, so regeneration is
    /// byte-reproducible. Cost is the accepted minimum: the file exists to be
    /// imported by every consumer's test suite, not to protect real funds.
    fn golden_kdf() -> KdfParams {
        KdfParams {
            algorithm: KdfId::Argon2id,
            memory_kib: kdf_bounds::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
            output_len: KEY_LEN as u32,
        }
    }
    const GOLDEN_SALT: [u8; SALT_LEN] = [0x11; SALT_LEN];
    const GOLDEN_NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

    #[test]
    fn golden_wallet_v1_imports() {
        let payload = decrypt(GOLDEN_WALLET_V1, GOLDEN_WALLET_V1_PASSPHRASE).unwrap();
        assert_eq!(payload, golden_wallet_v1_payload());
    }

    #[test]
    fn golden_wallet_v1_rejects_wrong_passphrase() {
        assert!(matches!(
            decrypt(GOLDEN_WALLET_V1, "not-the-passphrase"),
            Err(FormatError::Decryption)
        ));
    }

    /// Regenerate the checked-in golden file. Deliberately `#[ignore]`d: run it
    /// only when the format changes on purpose, with
    /// `cargo test -p csv-wallet regenerate_golden_wallet_v1 -- --ignored`, and
    /// then re-run every consumer's golden test.
    #[test]
    #[ignore = "regenerates a checked-in conformance artifact; run deliberately"]
    fn regenerate_golden_wallet_v1() {
        let bytes = seal(
            &golden_wallet_v1_payload(),
            GOLDEN_WALLET_V1_PASSPHRASE,
            &golden_kdf(),
            &GOLDEN_SALT,
            &GOLDEN_NONCE,
        )
        .unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/golden-wallet-v1.csvw");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, &bytes).unwrap();
    }
}
