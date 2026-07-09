//! Production mint-verifier signer resolution (MINT-KEYS-001).
//!
//! The RFC-0012 thin-registry mint path authorizes destination-chain
//! materialization with **verifier signatures** over the §9.2 attestation
//! digest. The private half of each verifier key is a process secret: it is
//! never a chain-config field, never serialized, and never logged.
//!
//! This module replaces the single process-wide `CSV_MINT_VERIFIER_KEY` with a
//! destination-chain-scoped, multi-signer resolution layer:
//!
//! - `CSV_MINT_VERIFIER_KEY` remains the legacy/default single-key path used for
//!   local testnet and single-destination runs.
//! - `CSV_MINT_VERIFIER_KEY_APTOS` / `_SUI` / `_SOLANA` / `_ETHEREUM` override the
//!   default **for that destination chain only**. A chain-scoped key is never
//!   silently reused for a different destination chain.
//! - Each variable may hold a comma-separated list of 32-byte hex secrets, so an
//!   operator can attach multiple local signers to one destination chain for
//!   threshold (M-of-N) registries. The adapter emits one verifier signature per
//!   configured key; the destination registry adjudicates the threshold.
//!
//! Production operators should prefer a provider-backed signer (KMS/HSM) over raw
//! env keys. The [`MintAttestationSigner`] trait is that seam; [`EnvSecpSigner`]
//! is the concrete env-backed provider, and [`KmsSigner`] is a fail-closed
//! scaffold that returns a clear error until an operator wires a real provider.
//! See `csv-docs/runbooks/MINT_VERIFIER_OPERATIONS.md`.

use secp256k1::SecretKey;

/// Legacy/default env var: one secp256k1 verifier secret (32-byte hex, optional
/// `0x`). Used for every destination chain that has no chain-scoped override.
pub const MINT_VERIFIER_KEY_ENV: &str = "CSV_MINT_VERIFIER_KEY";

/// Error surface for [`MintAttestationSigner`] providers.
///
/// Variants never carry key material; a `Display` of any variant is safe to log
/// or surface to an operator.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// No signer is configured for the requested destination chain.
    #[error("no mint verifier signer configured for destination chain '{0}'")]
    NoSignerConfigured(String),
    /// The provider is a scaffold that has not been wired to a real backend.
    #[error("mint verifier signer provider '{0}' is not configured: {1}")]
    ProviderUnavailable(String, String),
    /// The signing operation failed inside the provider.
    #[error("mint verifier signer '{0}' failed to sign: {1}")]
    SigningFailed(String, String),
}

/// A source of RFC-0012 §9.2 mint-attestation signatures.
///
/// This is the production seam between the runtime/adapters (which compute the
/// §9.2 digest) and the key custody backend (raw env key, KMS, or HSM). A
/// provider must never expose raw private material through its API surface; it
/// exposes only its identity, its 33-byte compressed secp256k1 public key, and a
/// digest-signing operation.
pub trait MintAttestationSigner: Send + Sync {
    /// Stable, non-secret identifier for logs and audit (never key material).
    fn signer_id(&self) -> String;

    /// 33-byte compressed secp256k1 public key registered in the destination
    /// registry's verifier set.
    fn public_key(&self) -> Result<[u8; 33], SignerError>;

    /// Sign a 32-byte §9.2 attestation digest, returning a 65-byte recoverable
    /// signature (`r(32) || s(32) || v(1)`, `v` the raw recovery id 0/1).
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError>;
}

/// Env-backed secp256k1 signer holding a raw secret in process memory.
///
/// Acceptable for local testnet and single-destination CLI runs. The secret is
/// held in a `SecretKey` (which zeroizes on drop and never `Debug`-prints its
/// bytes) and is never logged.
pub struct EnvSecpSigner {
    id: String,
    secret: SecretKey,
}

impl EnvSecpSigner {
    /// Wrap a resolved secret with a non-secret identity label.
    pub fn new(id: impl Into<String>, secret: SecretKey) -> Self {
        Self {
            id: id.into(),
            secret,
        }
    }
}

impl MintAttestationSigner for EnvSecpSigner {
    fn signer_id(&self) -> String {
        self.id.clone()
    }

    fn public_key(&self) -> Result<[u8; 33], SignerError> {
        let secp = secp256k1::Secp256k1::signing_only();
        Ok(secp256k1::PublicKey::from_secret_key(&secp, &self.secret).serialize())
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        let msg = secp256k1::Message::from_digest(*digest);
        let secp = secp256k1::Secp256k1::signing_only();
        let sig = secp.sign_ecdsa_recoverable(&msg, &self.secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&compact);
        out.push(recovery_id.to_i32() as u8);
        Ok(out)
    }
}

/// Fail-closed KMS/HSM provider scaffold.
///
/// A production deployment stores verifier keys in a KMS/HSM rather than process
/// env. This type documents the provider seam and **fails closed** on every
/// operation with a clear, key-material-free error until an operator supplies a
/// real backend. It is intentionally never selected by [`resolve_signers`]; it
/// exists so the interface has a non-env implementation and so wiring a KMS is a
/// localized change rather than a redesign.
pub struct KmsSigner {
    /// Operator-supplied non-secret key handle/URI (e.g. `aws-kms://<key-arn>`).
    pub key_ref: String,
}

impl KmsSigner {
    /// Construct a scaffold bound to a non-secret KMS key reference.
    pub fn new(key_ref: impl Into<String>) -> Self {
        Self {
            key_ref: key_ref.into(),
        }
    }

    fn unavailable(&self) -> SignerError {
        SignerError::ProviderUnavailable(
            "kms".to_string(),
            format!(
                "KMS-backed mint verifier signing is not wired for key '{}'; \
                 configure a KMS provider or use a chain-scoped env key",
                self.key_ref
            ),
        )
    }
}

impl MintAttestationSigner for KmsSigner {
    fn signer_id(&self) -> String {
        format!("kms:{}", self.key_ref)
    }

    fn public_key(&self) -> Result<[u8; 33], SignerError> {
        Err(self.unavailable())
    }

    fn sign_digest(&self, _digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        Err(self.unavailable())
    }
}

/// Chain-scoped override env var for a destination chain tag (`"aptos"` etc.).
///
/// Returns `None` for chains that do not use the verifier-attested mint path.
fn chain_scoped_env(chain_tag: &str) -> Option<&'static str> {
    match chain_tag {
        "aptos" => Some("CSV_MINT_VERIFIER_KEY_APTOS"),
        "sui" => Some("CSV_MINT_VERIFIER_KEY_SUI"),
        "solana" => Some("CSV_MINT_VERIFIER_KEY_SOLANA"),
        "ethereum" => Some("CSV_MINT_VERIFIER_KEY_ETHEREUM"),
        _ => None,
    }
}

/// Parse a comma-separated list of 32-byte hex secp256k1 secrets.
///
/// Whitespace and an optional `0x` prefix per entry are tolerated. Empty entries
/// are skipped. A malformed entry (bad hex, wrong length, invalid scalar) is
/// dropped with a warning that never contains the entry value, preserving
/// fail-closed behavior (fewer or zero signers) rather than panicking.
fn parse_secret_list(raw: &str, source: &str) -> Vec<SecretKey> {
    let mut keys = Vec::new();
    for (idx, part) in raw.split(',').enumerate() {
        let trimmed = part.trim().trim_start_matches("0x");
        if trimmed.is_empty() {
            continue;
        }
        let bytes = match hex::decode(trimmed) {
            Ok(b) => b,
            Err(_) => {
                log::warn!(
                    "{source}: entry #{idx} is not valid hex; skipping (mint may fail closed)"
                );
                continue;
            }
        };
        match SecretKey::from_slice(&bytes) {
            Ok(k) => keys.push(k),
            Err(_) => {
                log::warn!(
                    "{source}: entry #{idx} is not a valid 32-byte secp256k1 secret; \
                     skipping (mint may fail closed)"
                );
            }
        }
    }
    keys
}

/// Resolve the ordered list of local secp256k1 verifier secrets for a
/// destination chain.
///
/// Resolution order:
/// 1. If the chain-scoped var (e.g. `CSV_MINT_VERIFIER_KEY_APTOS`) is set and
///    non-empty, its entries are used **exclusively** — the legacy default is not
///    appended, so a chain-scoped configuration is never silently mixed with an
///    unrelated default key.
/// 2. Otherwise the legacy/default `CSV_MINT_VERIFIER_KEY` entries are used.
///
/// Returns an empty vector when nothing is configured (or everything configured
/// was malformed); callers must fail closed on empty. Key material never appears
/// in logs.
pub fn resolve_mint_verifier_keys(chain_tag: &str) -> Vec<SecretKey> {
    if let Some(scoped_var) = chain_scoped_env(chain_tag)
        && let Ok(raw) = std::env::var(scoped_var)
        && !raw.trim().is_empty()
    {
        let keys = parse_secret_list(&raw, scoped_var);
        if !keys.is_empty() {
            log::info!(
                "Factory: loaded {} mint verifier signer(s) for '{chain_tag}' from {scoped_var}",
                keys.len()
            );
        }
        // Chain-scoped var is authoritative for this chain even if every entry
        // was malformed: do NOT fall back to the default key, which could belong
        // to a different verifier set.
        return keys;
    }

    match std::env::var(MINT_VERIFIER_KEY_ENV) {
        Ok(raw) if !raw.trim().is_empty() => {
            let keys = parse_secret_list(&raw, MINT_VERIFIER_KEY_ENV);
            if !keys.is_empty() {
                log::info!(
                    "Factory: loaded {} mint verifier signer(s) for '{chain_tag}' from {MINT_VERIFIER_KEY_ENV} (default)",
                    keys.len()
                );
            }
            keys
        }
        _ => Vec::new(),
    }
}

/// Resolve verifier signers as [`MintAttestationSigner`] providers.
///
/// Convenience over [`resolve_mint_verifier_keys`] for callers that want the
/// provider abstraction (public keys, signer ids) rather than raw secrets.
pub fn resolve_signers(chain_tag: &str) -> Vec<EnvSecpSigner> {
    resolve_mint_verifier_keys(chain_tag)
        .into_iter()
        .enumerate()
        .map(|(i, secret)| EnvSecpSigner::new(format!("env:{chain_tag}:{i}"), secret))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests mutate shared process env vars; serialize them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // 32-byte valid secp256k1 secrets.
    const K1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const K2: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn clear() {
        for v in [
            MINT_VERIFIER_KEY_ENV,
            "CSV_MINT_VERIFIER_KEY_APTOS",
            "CSV_MINT_VERIFIER_KEY_SUI",
            "CSV_MINT_VERIFIER_KEY_SOLANA",
            "CSV_MINT_VERIFIER_KEY_ETHEREUM",
        ] {
            // SAFETY: guarded by ENV_LOCK; single-threaded within the test body.
            unsafe { std::env::remove_var(v) };
        }
    }

    #[test]
    fn legacy_default_applies_to_all_chains() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe { std::env::set_var(MINT_VERIFIER_KEY_ENV, K1) };
        assert_eq!(resolve_mint_verifier_keys("aptos").len(), 1);
        assert_eq!(resolve_mint_verifier_keys("sui").len(), 1);
        assert_eq!(resolve_mint_verifier_keys("solana").len(), 1);
        clear();
    }

    #[test]
    fn chain_scoped_overrides_default_for_that_chain_only() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            std::env::set_var(MINT_VERIFIER_KEY_ENV, K1);
            std::env::set_var("CSV_MINT_VERIFIER_KEY_APTOS", format!("{K1},{K2}"));
        }
        // Aptos gets its two chain-scoped keys.
        assert_eq!(resolve_mint_verifier_keys("aptos").len(), 2);
        // Sui, with no scoped override, still gets the single default.
        assert_eq!(resolve_mint_verifier_keys("sui").len(), 1);
        clear();
    }

    #[test]
    fn chain_scoped_does_not_fall_back_to_default_when_malformed() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe {
            std::env::set_var(MINT_VERIFIER_KEY_ENV, K1);
            std::env::set_var("CSV_MINT_VERIFIER_KEY_SUI", "not-a-key");
        }
        // Scoped var present but malformed: must NOT silently reuse the default
        // key (which could be a different verifier set). Fails closed (empty).
        assert!(resolve_mint_verifier_keys("sui").is_empty());
        clear();
    }

    #[test]
    fn missing_config_fails_closed_empty() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        assert!(resolve_mint_verifier_keys("aptos").is_empty());
        clear();
    }

    #[test]
    fn multiple_local_signers_parse_from_comma_list() {
        let _g = ENV_LOCK.lock().unwrap();
        clear();
        unsafe { std::env::set_var("CSV_MINT_VERIFIER_KEY_SOLANA", format!("{K1}, 0x{K2} ")) };
        let signers = resolve_signers("solana");
        assert_eq!(signers.len(), 2);
        // Providers expose distinct public keys without leaking secrets.
        let pk0 = signers[0].public_key().unwrap();
        let pk1 = signers[1].public_key().unwrap();
        assert_ne!(pk0, pk1);
        clear();
    }

    #[test]
    fn env_signer_produces_65_byte_recoverable_signature() {
        let secret = SecretKey::from_slice(&hex::decode(K1).unwrap()).unwrap();
        let signer = EnvSecpSigner::new("env:test:0", secret);
        let sig = signer.sign_digest(&[7u8; 32]).unwrap();
        assert_eq!(sig.len(), 65);
        assert!(sig[64] <= 1, "raw recovery id must be 0/1");
    }

    #[test]
    fn kms_scaffold_fails_closed() {
        let signer = KmsSigner::new("aws-kms://example");
        assert!(signer.public_key().is_err());
        assert!(signer.sign_digest(&[0u8; 32]).is_err());
    }
}
