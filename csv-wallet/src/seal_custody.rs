//! Seal custody: tracking which key controls each single-use `SealPoint`.
//!
//! Interactive (send-mode) transfers assign a Sanad to a recipient-controlled
//! destination `SealPoint` and close a sender-controlled source `SealPoint`.
//! Getting custody wrong — signing a close with the wrong key, or losing track
//! of which key controls a seal — risks lost or double-spent sanads. This
//! module records, per `SealPoint`, the controlling key so the wallet knows
//! which signer to use and can refuse to reuse a seal it has already spent.
//!
//! Custody is wallet-local bookkeeping: it never grants authority on its own
//! (the on-chain seal and the runtime's replay database remain authoritative).
//! It exists so the wallet can select the right signer and enforce single-use
//! locally before a transfer is ever handed to `csv-runtime`.

use crate::error::{Result, WalletError};
use csv_hash::seal::SealPoint;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The controlling key recorded for a single-use `SealPoint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCustodyRecord {
    /// Chain the seal lives on (e.g. `"bitcoin"`).
    pub chain: String,
    /// Keystore/signer identifier for the controlling key (e.g. `"bitcoin:0:0"`).
    pub key_id: String,
    /// Public key of the controlling key.
    pub public_key: Vec<u8>,
    /// Whether the seal has been consumed (source seal closed / spent).
    ///
    /// A consumed seal must never be closed again — this is the wallet-local
    /// half of the single-use guarantee (the runtime enforces the other half
    /// via its replay database).
    pub consumed: bool,
}

/// A thread-safe registry mapping each single-use `SealPoint` to the key that
/// controls it.
///
/// Cloning a `SealCustody` shares the same underlying registry (it is an
/// `Arc`-backed handle), so a custody handle can be shared between a
/// `WalletManager` and callers that need to consult it.
#[derive(Clone, Default)]
pub struct SealCustody {
    inner: Arc<RwLock<HashMap<SealPoint, SealCustodyRecord>>>,
}

impl SealCustody {
    /// Create an empty custody registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the controlling key for `seal`.
    ///
    /// Idempotent when the same controlling key is recorded again. Rejects an
    /// attempt to re-assign custody of a seal to a *different* controlling key
    /// (chain / key id / public key) — silently overwriting custody would be a
    /// way to redirect or lose a seal.
    pub fn record(&self, seal: SealPoint, record: SealCustodyRecord) -> Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| WalletError::SealCustody(format!("custody lock poisoned: {e}")))?;
        match guard.get(&seal) {
            Some(existing) => {
                if existing.chain != record.chain
                    || existing.key_id != record.key_id
                    || existing.public_key != record.public_key
                {
                    return Err(WalletError::SealCustody(
                        "seal already under a different controlling key".to_string(),
                    ));
                }
                // Same controlling key: keep the existing record (preserving a
                // `consumed` flag already set) rather than resurrecting a spent
                // seal by overwriting it.
                Ok(())
            }
            None => {
                guard.insert(seal, record);
                Ok(())
            }
        }
    }

    /// Return the custody record for `seal`, if tracked.
    pub fn custody_of(&self, seal: &SealPoint) -> Option<SealCustodyRecord> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(seal).cloned()
    }

    /// True if the wallet controls `seal` and it has not yet been consumed.
    pub fn controls(&self, seal: &SealPoint) -> bool {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(seal).is_some_and(|r| !r.consumed)
    }

    /// True if `seal` is tracked and already consumed.
    pub fn is_consumed(&self, seal: &SealPoint) -> bool {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(seal).is_some_and(|r| r.consumed)
    }

    /// Mark `seal` consumed after its single-use close.
    ///
    /// Rejects an untracked seal (the wallet does not control it) and a
    /// double-consume (the seal was already spent — closing it again would
    /// double-spend the Sanad).
    pub fn mark_consumed(&self, seal: &SealPoint) -> Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| WalletError::SealCustody(format!("custody lock poisoned: {e}")))?;
        match guard.get_mut(seal) {
            None => Err(WalletError::SealCustody(
                "cannot consume a seal the wallet does not control".to_string(),
            )),
            Some(record) if record.consumed => Err(WalletError::SealCustody(
                "seal already consumed (double-spend prevented)".to_string(),
            )),
            Some(record) => {
                record.consumed = true;
                Ok(())
            }
        }
    }

    /// Number of tracked seals.
    pub fn len(&self) -> usize {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }

    /// True if no seals are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(byte: u8) -> SealPoint {
        SealPoint::new(vec![byte; 36], Some(0), None).unwrap()
    }

    fn record(chain: &str, key_id: &str, pk: u8) -> SealCustodyRecord {
        SealCustodyRecord {
            chain: chain.to_string(),
            key_id: key_id.to_string(),
            public_key: vec![pk; 33],
            consumed: false,
        }
    }

    #[test]
    fn records_and_reads_custody() {
        let custody = SealCustody::new();
        let s = seal(0x01);
        custody
            .record(s.clone(), record("bitcoin", "bitcoin:0:0", 0x02))
            .unwrap();

        assert!(custody.controls(&s));
        let got = custody.custody_of(&s).unwrap();
        assert_eq!(got.chain, "bitcoin");
        assert_eq!(got.key_id, "bitcoin:0:0");
        assert!(!got.consumed);
        assert_eq!(custody.len(), 1);
    }

    #[test]
    fn recording_same_key_is_idempotent() {
        let custody = SealCustody::new();
        let s = seal(0x03);
        let r = record("sui", "sui:0:0", 0x04);
        custody.record(s.clone(), r.clone()).unwrap();
        custody.record(s.clone(), r).unwrap();
        assert_eq!(custody.len(), 1);
    }

    #[test]
    fn rejects_reassigning_custody_to_a_different_key() {
        let custody = SealCustody::new();
        let s = seal(0x05);
        custody
            .record(s.clone(), record("ethereum", "ethereum:0:0", 0x06))
            .unwrap();
        let err = custody
            .record(s.clone(), record("ethereum", "ethereum:9:9", 0x07))
            .unwrap_err();
        assert!(matches!(err, WalletError::SealCustody(_)));
    }

    #[test]
    fn consume_marks_and_prevents_double_spend() {
        let custody = SealCustody::new();
        let s = seal(0x08);
        custody
            .record(s.clone(), record("bitcoin", "bitcoin:0:0", 0x09))
            .unwrap();

        custody.mark_consumed(&s).unwrap();
        assert!(custody.is_consumed(&s));
        assert!(
            !custody.controls(&s),
            "a consumed seal is no longer controllable"
        );

        let err = custody.mark_consumed(&s).unwrap_err();
        assert!(matches!(err, WalletError::SealCustody(_)));
    }

    #[test]
    fn consuming_untracked_seal_is_rejected() {
        let custody = SealCustody::new();
        let err = custody.mark_consumed(&seal(0x0A)).unwrap_err();
        assert!(matches!(err, WalletError::SealCustody(_)));
    }

    #[test]
    fn re_recording_a_consumed_seal_does_not_resurrect_it() {
        let custody = SealCustody::new();
        let s = seal(0x0B);
        let r = record("aptos", "aptos:0:0", 0x0C);
        custody.record(s.clone(), r.clone()).unwrap();
        custody.mark_consumed(&s).unwrap();
        // Same controlling key re-recorded: must not clear the consumed flag.
        custody.record(s.clone(), r).unwrap();
        assert!(custody.is_consumed(&s));
    }
}
