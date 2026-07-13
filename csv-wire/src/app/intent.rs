//! Typed, expiring signing intents.
//!
//! Opaque-byte signing is forbidden: a signer must never be asked to sign bytes
//! whose meaning it cannot state back to the user. A [`SigningIntent`] carries
//! every security field the operation turns on — chain, network, operation,
//! recipient, value, sanad, seal, nonce and replay data — plus the sentence the
//! user is actually agreeing to, and the digest of the transaction the resulting
//! signature will authorize.
//!
//! [`SigningIntent::binding_digest`] provides a canonical commitment to all of
//! the fields above for signers and transports that support signing a typed
//! intent. The legacy proof-bundle signature format currently signs the
//! transition-DAG root directly, so callers using that format must validate that
//! `payload_digest` equals the root immediately before signing. They must not
//! claim that the other intent fields are carried by that legacy signature.
//!
//! An intent is valid only inside its window. An expired or incomplete intent is
//! not a warning to be clicked through — [`SigningIntent::validate_at`] returns
//! an error and the operation does not proceed.

use csv_codec::canonical_hash;
use serde::{Deserialize, Serialize};

use super::{ArtifactKind, ContractArtifact, ContractError, ContractHeader, require_nonempty};
use crate::primitives::{HashWire, SanadIdWire};
use crate::seal::SealPointWire;

/// Domain tag for the intent binding digest.
const INTENT_BINDING_DOMAIN: &str = "csv.wire.app.signing-intent.v1";

/// Longest validity window an intent may declare, in seconds.
///
/// An intent is a user's answer to a question they were just shown. A long-lived
/// intent is a bearer authorization sitting in a queue, so the window is short and
/// the bound is enforced at validation, not merely recommended.
pub const MAX_INTENT_TTL_SECS: u64 = 300;

/// The operation a signature will authorize.
///
/// Naming the operation is what lets a signer refuse a request whose meaning does
/// not match what the user was shown. There is deliberately no "other" or "raw"
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentOperation {
    /// Sign the send transition: assign the sanad to the recipient's invoice seal
    /// and close the single-use source seal. This is the off-chain send's
    /// commitment, and the signature the recipient authenticates on `accept`.
    SendTransition,
    /// Lock the sanad on the source chain for an on-chain materialization.
    LockSanad,
    /// Mint the sanad on the destination chain against a verified proof.
    MintSanad,
    /// Release a source-chain escrow against a verifier-signed settlement receipt.
    ReleaseEscrow,
}

/// The value a signature puts at stake.
///
/// Held as a decimal string plus its unit rather than a scalar: chains disagree on
/// precision, and a rounded number shown to a user is a lie about what they signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentValue {
    /// Amount, as an exact decimal string in `unit` (e.g. `"0.00042"`).
    pub amount: String,
    /// The unit `amount` is denominated in (e.g. `"BTC"`, `"SUI"`).
    pub unit: String,
}

/// A typed, expiring request for a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningIntent {
    /// Versioned contract header.
    pub header: ContractHeader,
    /// Chain the transaction will be submitted to (e.g. `"bitcoin"`).
    pub chain: String,
    /// Network within that chain (e.g. `"mainnet"`, `"testnet"`). Bound explicitly:
    /// a mainnet transaction must never be signable under a testnet confirmation.
    pub network: String,
    /// The operation the signature authorizes.
    pub operation: IntentOperation,
    /// The sanad the operation acts on.
    pub sanad_id: SanadIdWire,
    /// The seal the operation consumes or creates.
    pub seal: SealPointWire,
    /// Beneficiary of the operation, in the chain's address encoding.
    pub recipient: String,
    /// The value at stake.
    pub value: IntentValue,
    /// Anti-replay nonce for this intent.
    pub nonce: u64,
    /// The runtime replay ID this operation is guarded by, when the runtime has
    /// assigned one.
    pub replay_id: Option<HashWire>,
    /// The sentence the user is agreeing to. This is the user-visible meaning of the
    /// signature, and it is bound into [`SigningIntent::binding_digest`] along with
    /// everything else — it cannot be shown for one transaction and used for another.
    pub summary: String,
    /// Digest of the chain transaction the signature will authorize (32 bytes).
    #[serde(with = "crate::hexbytes")]
    pub payload_digest: Vec<u8>,
    /// Unix seconds when the intent was created.
    pub created_at: u64,
    /// Unix seconds when the intent stops being valid (exclusive).
    pub expires_at: u64,
}

impl SigningIntent {
    /// Build an intent at the current contract version.
    ///
    /// The result is *not* trusted merely because it was constructed here — call
    /// [`SigningIntent::validate_at`] before acting on it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: String,
        network: String,
        operation: IntentOperation,
        sanad_id: SanadIdWire,
        seal: SealPointWire,
        recipient: String,
        value: IntentValue,
        nonce: u64,
        replay_id: Option<HashWire>,
        summary: String,
        payload_digest: Vec<u8>,
        created_at: u64,
        ttl_secs: u64,
    ) -> Self {
        Self {
            header: ContractHeader::current(ArtifactKind::SigningIntent),
            chain,
            network,
            operation,
            sanad_id,
            seal,
            recipient,
            value,
            nonce,
            replay_id,
            summary,
            payload_digest,
            created_at,
            expires_at: created_at.saturating_add(ttl_secs),
        }
    }

    /// The canonical commitment a typed-intent signer signs.
    ///
    /// Domain-separated over the intent's canonical CBOR encoding, so it commits to
    /// every field above — including `summary`, `network`, and `payload_digest`.
    /// The legacy proof-bundle signature format does not yet carry this digest;
    /// see the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Codec`] if the intent cannot be canonically encoded.
    pub fn binding_digest(&self) -> Result<Vec<u8>, ContractError> {
        Ok(canonical_hash(INTENT_BINDING_DOMAIN, self)?)
    }

    /// Whether the intent's window has passed (or has not begun) at `now`.
    pub fn is_expired_at(&self, now: u64) -> bool {
        now < self.created_at || now >= self.expires_at
    }

    /// Validate the intent for use at `now`.
    ///
    /// This is the gate an application calls before signing. It fails closed: an
    /// intent that is incomplete, over-long, or outside its window yields an error,
    /// and there is no variant of the result that means "sign it anyway".
    ///
    /// # Errors
    ///
    /// - [`ContractError::MissingField`] / [`ContractError::InvalidField`] if any
    ///   security field is absent, empty, or malformed — see
    ///   [`ContractArtifact::validate`].
    /// - [`ContractError::IntentExpired`] if `now` is outside `[created_at, expires_at)`.
    pub fn validate_at(&self, now: u64) -> Result<(), ContractError> {
        self.header.validate(ArtifactKind::SigningIntent)?;
        ContractArtifact::validate(self)?;
        if self.is_expired_at(now) {
            return Err(ContractError::IntentExpired {
                now,
                created_at: self.created_at,
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

impl ContractArtifact for SigningIntent {
    const KIND: ArtifactKind = ArtifactKind::SigningIntent;

    fn header(&self) -> &ContractHeader {
        &self.header
    }

    /// Enforce completeness. Every field here is one a user would have to read to
    /// understand what they are authorizing, so an absent one makes the intent
    /// unsignable rather than merely incomplete.
    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "signing intent";
        require_nonempty(ARTIFACT, "chain", &self.chain)?;
        require_nonempty(ARTIFACT, "network", &self.network)?;
        require_nonempty(ARTIFACT, "sanad_id", &self.sanad_id.bytes)?;
        require_nonempty(ARTIFACT, "seal.id", &self.seal.id)?;
        require_nonempty(ARTIFACT, "recipient", &self.recipient)?;
        require_nonempty(ARTIFACT, "value.amount", &self.value.amount)?;
        require_nonempty(ARTIFACT, "value.unit", &self.value.unit)?;
        require_nonempty(ARTIFACT, "summary", &self.summary)?;

        if self.payload_digest.len() != 32 {
            return Err(ContractError::InvalidField {
                artifact: ARTIFACT,
                reason: format!(
                    "payload_digest must be a 32-byte digest, got {} bytes",
                    self.payload_digest.len()
                ),
            });
        }
        if self.payload_digest.iter().all(|b| *b == 0) {
            return Err(ContractError::InvalidField {
                artifact: ARTIFACT,
                reason: "payload_digest is all zeroes: the intent is not bound to any transaction"
                    .to_string(),
            });
        }
        if self.expires_at <= self.created_at {
            return Err(ContractError::InvalidField {
                artifact: ARTIFACT,
                reason: format!(
                    "expires_at {} does not follow created_at {}: the intent has no validity window",
                    self.expires_at, self.created_at
                ),
            });
        }
        let ttl = self.expires_at.saturating_sub(self.created_at);
        if ttl > MAX_INTENT_TTL_SECS {
            return Err(ContractError::InvalidField {
                artifact: ARTIFACT,
                reason: format!(
                    "validity window of {ttl}s exceeds the maximum of {MAX_INTENT_TTL_SECS}s"
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{decode, encode};

    const NOW: u64 = 1_700_000_000;

    fn intent() -> SigningIntent {
        SigningIntent::new(
            "bitcoin".to_string(),
            "mainnet".to_string(),
            IntentOperation::LockSanad,
            SanadIdWire {
                bytes: hex::encode([0x11u8; 32]),
            },
            SealPointWire {
                id: hex::encode([0xAAu8; 32]),
                nonce: Some(7),
                version: Some(1),
            },
            "bc1qexampleexampleexample".to_string(),
            IntentValue {
                amount: "0.00042".to_string(),
                unit: "BTC".to_string(),
            },
            42,
            Some(HashWire {
                bytes: hex::encode([0x22u8; 32]),
            }),
            "Lock sanad 1111…1111 on bitcoin mainnet for transfer to sui".to_string(),
            vec![0x33; 32],
            NOW,
            120,
        )
    }

    #[test]
    fn complete_intent_validates_inside_its_window() {
        let i = intent();
        assert!(i.validate_at(NOW).is_ok());
        assert!(i.validate_at(NOW + 119).is_ok());

        let bytes = encode(&i).expect("valid intent encodes");
        assert_eq!(decode::<SigningIntent>(&bytes).expect("decodes"), i);
    }

    #[test]
    fn expired_intent_fails_closed() {
        let i = intent();
        let err = i
            .validate_at(NOW + 120)
            .expect_err("an intent must not be valid at its expiry instant");
        assert!(matches!(err, ContractError::IntentExpired { .. }));

        assert!(i.validate_at(NOW + 10_000).is_err());
    }

    #[test]
    fn intent_from_the_future_fails_closed() {
        // A clock-skewed or back-dated intent must not become valid early.
        let i = intent();
        assert!(matches!(
            i.validate_at(NOW - 1),
            Err(ContractError::IntentExpired { .. })
        ));
    }

    #[test]
    fn over_long_window_is_rejected() {
        let mut i = intent();
        i.expires_at = i.created_at + MAX_INTENT_TTL_SECS + 1;
        assert!(
            i.validate_at(NOW).is_err(),
            "a long-lived intent is a bearer authorization; the bound must be enforced"
        );
    }

    #[test]
    fn zero_length_window_is_rejected() {
        let mut i = intent();
        i.expires_at = i.created_at;
        assert!(i.validate_at(NOW).is_err());
    }

    #[test]
    fn every_security_field_is_required() {
        // Each of these is something the user must read to know what they authorize.
        let cases: Vec<(&str, Box<dyn Fn(&mut SigningIntent)>)> = vec![
            ("chain", Box::new(|i: &mut SigningIntent| i.chain.clear())),
            (
                "network",
                Box::new(|i: &mut SigningIntent| i.network.clear()),
            ),
            (
                "sanad_id",
                Box::new(|i: &mut SigningIntent| i.sanad_id.bytes.clear()),
            ),
            ("seal", Box::new(|i: &mut SigningIntent| i.seal.id.clear())),
            (
                "recipient",
                Box::new(|i: &mut SigningIntent| i.recipient.clear()),
            ),
            (
                "amount",
                Box::new(|i: &mut SigningIntent| i.value.amount.clear()),
            ),
            (
                "unit",
                Box::new(|i: &mut SigningIntent| i.value.unit.clear()),
            ),
            (
                "summary",
                Box::new(|i: &mut SigningIntent| i.summary.clear()),
            ),
            (
                "payload_digest",
                Box::new(|i: &mut SigningIntent| i.payload_digest.clear()),
            ),
        ];

        for (field, break_it) in cases {
            let mut i = intent();
            break_it(&mut i);
            assert!(
                i.validate_at(NOW).is_err(),
                "an intent missing `{field}` must not be signable"
            );
            assert!(
                encode(&i).is_err(),
                "an intent missing `{field}` must not even encode"
            );
        }
    }

    #[test]
    fn unbound_payload_digest_is_rejected() {
        let mut i = intent();
        i.payload_digest = vec![0u8; 32];
        assert!(
            i.validate_at(NOW).is_err(),
            "an all-zero digest binds the intent to no transaction at all"
        );
    }

    #[test]
    fn binding_digest_covers_every_user_visible_field() {
        let base = intent();
        let baseline = base.binding_digest().expect("digest");

        let mutations: Vec<Box<dyn Fn(&mut SigningIntent)>> = vec![
            Box::new(|i: &mut SigningIntent| i.chain = "ethereum".to_string()),
            Box::new(|i: &mut SigningIntent| i.network = "testnet".to_string()),
            Box::new(|i: &mut SigningIntent| i.operation = IntentOperation::MintSanad),
            Box::new(|i: &mut SigningIntent| i.recipient = "bc1qattacker".to_string()),
            Box::new(|i: &mut SigningIntent| i.value.amount = "9.99".to_string()),
            Box::new(|i: &mut SigningIntent| i.value.unit = "ETH".to_string()),
            Box::new(|i: &mut SigningIntent| i.nonce += 1),
            Box::new(|i: &mut SigningIntent| i.summary = "Something else entirely".to_string()),
            Box::new(|i: &mut SigningIntent| i.payload_digest = vec![0x44; 32]),
            Box::new(|i: &mut SigningIntent| i.expires_at += 1),
            Box::new(|i: &mut SigningIntent| i.seal.id = hex::encode([0xBBu8; 32])),
            Box::new(|i: &mut SigningIntent| i.sanad_id.bytes = hex::encode([0x99u8; 32])),
        ];

        for (index, mutate) in mutations.iter().enumerate() {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                mutated.binding_digest().expect("digest"),
                baseline,
                "mutation {index} left the binding digest unchanged: that field is not bound"
            );
        }
    }

    #[test]
    fn binding_digest_is_deterministic() {
        let i = intent();
        assert_eq!(i.binding_digest().unwrap(), i.binding_digest().unwrap());
    }

    #[test]
    fn tampered_intent_bytes_fail_closed_on_decode() {
        let mut i = intent();
        i.summary.clear();
        // Model a peer that skipped its own producer-side guard.
        let bytes = csv_codec::to_canonical_cbor(&i).unwrap();
        assert!(matches!(
            decode::<SigningIntent>(&bytes),
            Err(ContractError::MissingField { .. })
        ));
    }
}
