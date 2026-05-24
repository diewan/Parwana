//! Stealth Addresses for Privacy-Preserving Seal Creation
//!
//! Implements a dual-key stealth address scheme where payments to a recipient
//! cannot be linked to their public address without their scan key.
//!
//! # Architecture
//!
//! ```text
//! Recipient keys:
//!   (scan_sk, scan_pk)  — scan key pair for detecting incoming payments
//!   (spend_sk, spend_pk) — spend key pair for controlling funds
//!
//! Sender flow (creates stealth address):
//!   1. Generate nonce n ← Z_p
//!   2. R = n * G (ephemeral public point)
//!   3. P' = H(R || scan_pk) * spend_pk (stealth address)
//!   4. Publish R in the transaction; only recipient can derive P'
//!
//! Recipient scanning flow:
//!   1. For each tx with ephemeral point R:
//!      P' = H(R || scan_pk) * spend_sk
//!   2. Check if P' matches any known spending key
//! ```
//!
//! # Security Properties
//!
//! 1. **Sender Privacy**: Observers cannot link multiple payments to the same recipient
//! 2. **Recipient Privacy**: Only the recipient with scan_sk can detect their payments
//! 3. **Spending Control**: Only the recipient with spend_sk can spend from stealth addresses

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::csv_tagged_hash;

/// Maximum size for key material in bytes.
pub const MAX_KEY_SIZE: usize = 64;

/// The scan public key used by senders to generate stealth addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPublicKey(pub [u8; 32]);

impl ScanPublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Display for ScanPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ScanPub(0x{})", self.to_hex())
    }
}

/// The spend public key — the actual address visible on-chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendPublicKey(pub [u8; 32]);

impl SpendPublicKey {
    #[allow(missing_docs)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    #[allow(missing_docs)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    #[allow(missing_docs)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Display for SpendPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SpendPub(0x{})", self.to_hex())
    }
}

/// The stealth address derived from a sender's nonce and the recipient's scan key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress(pub [u8; 32]);

impl StealthAddress {
    #[allow(missing_docs)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    #[allow(missing_docs)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    #[allow(missing_docs)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Display for StealthAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Stealth(0x{})", self.to_hex())
    }
}

/// An ephemeral point shared by the sender during stealth address derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralPoint(pub [u8; 32]);

impl EphemeralPoint {
    #[allow(missing_docs)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    #[allow(missing_docs)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Full stealth address key pair for a recipient.
#[derive(Clone, Debug)]
pub struct StealthAddressPair {
    /// Scan public key (shared with senders).
    pub scan_pk: ScanPublicKey,
    /// Spend public key (the on-chain address).
    pub spend_pk: SpendPublicKey,
}

/// Complete stealth wallet for scanning and spending.
pub struct StealthWallet {
    scan_pk: ScanPublicKey,
    spend_pk: SpendPublicKey,
    // Note: private keys would be stored in the keystore (csv-keys), not here.
    // This struct only holds public information.
}

impl StealthWallet {
    /// Create a new stealth wallet from public keys.
    pub fn new(scan_pk: ScanPublicKey, spend_pk: SpendPublicKey) -> Self {
        Self { scan_pk, spend_pk }
    }

    /// Generate a stealth address for a payment from the given ephemeral point.
    ///
    /// This is what a sender calls to create a stealth address for a recipient.
    ///
    /// # Arguments
    /// * `ephemeral` — The sender's ephemeral point R = n*G
    /// * `scan_pk` — Recipient's scan public key
    /// * `spend_pk` — Recipient's spend public key
    pub fn generate(
        recipient_scan_pk: &ScanPublicKey,
        _recipient_spend_pk: &SpendPublicKey,
        ephemeral: &EphemeralPoint,
    ) -> StealthAddress {
        // P' = csv_tagged_hash(R || scan_pk) * spend_pk (simplified: direct hash-based derivation)
        use csv_codec::to_canonical_cbor;
        let data = to_canonical_cbor(&(ephemeral, recipient_scan_pk))
            .expect("Canonical serialization should not fail for stealth address");
        let hash = csv_tagged_hash("csv.stealth.addr.v1", &data);

        // Use hash as seed for stealth address (in a real elliptic curve implementation,
        // this would be scalar multiplication: P' = H(R||scan_pk) * spend_pk)
        StealthAddress::from_bytes(hash.into())
    }

    /// Scan for stealth addresses belonging to this wallet.
    ///
    /// Given a list of ephemeral points from transactions, checks if any of them
    /// produce a stealth address that matches this wallet's spending key.
    ///
    /// In a full elliptic curve implementation, this would:
    /// 1. For each R, compute P' = H(R || scan_pk) * spend_sk
    /// 2. Check if the resulting point's x-coordinate matches any known address
    ///
    /// This simplified version returns all ephemeral points that could produce
    /// a match (in practice, the wallet would compare against stored keys).
    pub fn scan<'a>(
        &self,
        ephemeral_points: &'a [EphemeralPoint],
    ) -> Vec<(StealthAddress, &'a EphemeralPoint)> {
        let mut matches = Vec::new();
        for ep in ephemeral_points {
            let stealth = Self::generate(&self.scan_pk, &self.spend_pk, ep);
            // In a real implementation, we'd check if this stealth address
            // corresponds to a key we control. Here we return all derived addresses.
            matches.push((stealth, ep));
        }
        matches
    }

    /// Derive the scan public key from scan bytes (for reconstruction).
    pub fn scan_pk(&self) -> &ScanPublicKey {
        &self.scan_pk
    }

    /// Derive the spend public key.
    pub fn spend_pk(&self) -> &SpendPublicKey {
        &self.spend_pk
    }
}

/// Hash a nonce and recipient scan key to derive the shared secret for stealth address using canonical serialization.
pub fn derive_stealth_base(nonce: &[u8], scan_pk: &ScanPublicKey) -> [u8; 32] {
    use csv_codec::to_canonical_cbor;
    let data = to_canonical_cbor(&(nonce, scan_pk))
        .expect("Canonical serialization should not fail for stealth base");
    csv_tagged_hash("csv.stealth.nonce.v1", &data)
}

/// Compute an ephemeral point from a nonce (simplified: hash to bytes).
///
/// In a real elliptic curve implementation, this would be R = nonce * G.
pub fn compute_ephemeral_point(nonce: &[u8]) -> EphemeralPoint {
    let hash = csv_tagged_hash("csv.ephemeral.point.v1", nonce);
    EphemeralPoint::from_bytes(hash.into())
}

/// A stealth address entry for monitoring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthScanEntry {
    /// The derived stealth address.
    pub stealth_address: StealthAddress,
    /// The ephemeral point from the transaction.
    pub ephemeral: EphemeralPoint,
    /// The block height where this was found.
    pub block_height: u64,
    /// Transaction identifier.
    pub tx_id: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scan_pk() -> ScanPublicKey {
        ScanPublicKey::from_bytes([0x01; 32])
    }

    fn test_spend_pk() -> SpendPublicKey {
        SpendPublicKey::from_bytes([0x02; 32])
    }

    fn test_ephemeral() -> EphemeralPoint {
        EphemeralPoint::from_bytes([0x03; 32])
    }

    #[test]
    fn test_stealth_address_generation() {
        let scan_pk = test_scan_pk();
        let spend_pk = test_spend_pk();
        let ephemeral = test_ephemeral();

        let stealth = StealthWallet::generate(&scan_pk, &spend_pk, &ephemeral);
        assert_ne!(stealth.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_stealth_address_deterministic() {
        let scan_pk = test_scan_pk();
        let spend_pk = test_spend_pk();
        let ephemeral = test_ephemeral();

        let s1 = StealthWallet::generate(&scan_pk, &spend_pk, &ephemeral);
        let s2 = StealthWallet::generate(&scan_pk, &spend_pk, &ephemeral);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_different_ephemeral_produces_different_stealth() {
        let scan_pk = test_scan_pk();
        let spend_pk = test_spend_pk();
        let ep1 = EphemeralPoint::from_bytes([0x03; 32]);
        let ep2 = EphemeralPoint::from_bytes([0x04; 32]);

        let s1 = StealthWallet::generate(&scan_pk, &spend_pk, &ep1);
        let s2 = StealthWallet::generate(&scan_pk, &spend_pk, &ep2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_different_scan_key_produces_different_stealth() {
        let scan_pk1 = ScanPublicKey::from_bytes([0x01; 32]);
        let scan_pk2 = ScanPublicKey::from_bytes([0x11; 32]);
        let spend_pk = test_spend_pk();
        let ephemeral = test_ephemeral();

        let s1 = StealthWallet::generate(&scan_pk1, &spend_pk, &ephemeral);
        let s2 = StealthWallet::generate(&scan_pk2, &spend_pk, &ephemeral);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_wallet_scan() {
        let wallet = StealthWallet::new(test_scan_pk(), test_spend_pk());
        let ep1 = EphemeralPoint::from_bytes([0x03; 32]);
        let ep2 = EphemeralPoint::from_bytes([0x04; 32]);
        let points = [ep1, ep2];
        let matches = wallet.scan(&points);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_empty_scan() {
        let wallet = StealthWallet::new(test_scan_pk(), test_spend_pk());
        let matches = wallet.scan(&[]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_derive_stealth_base() {
        let scan_pk = test_scan_pk();
        let b1 = derive_stealth_base(b"nonce-1", &scan_pk);
        let b2 = derive_stealth_base(b"nonce-2", &scan_pk);
        assert_ne!(b1, b2);

        // Same nonce produces same base
        let b3 = derive_stealth_base(b"nonce-1", &scan_pk);
        assert_eq!(b1, b3);
    }

    #[test]
    fn test_compute_ephemeral_point() {
        let ep1 = compute_ephemeral_point(b"nonce-1");
        let ep2 = compute_ephemeral_point(b"nonce-2");
        assert_ne!(ep1, ep2);
        assert_ne!(ep1.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_stealth_address_display() {
        let stealth = StealthAddress::from_bytes([0xAB; 32]);
        let display = format!("{}", stealth);
        assert!(display.starts_with("Stealth(0x"));
        assert_eq!(display.len(), 75);
    }

    #[test]
    fn test_scan_public_key_display() {
        let pk = ScanPublicKey::from_bytes([0xAB; 32]);
        let display = format!("{}", pk);
        assert!(display.starts_with("ScanPub(0x"));
    }

    #[test]
    fn test_spend_public_key_display() {
        let pk = SpendPublicKey::from_bytes([0xAB; 32]);
        let display = format!("{}", pk);
        assert!(display.starts_with("SpendPub(0x"));
    }

    #[test]
    fn test_wallet_keys() {
        let scan_pk = test_scan_pk();
        let spend_pk = test_spend_pk();
        let wallet = StealthWallet::new(scan_pk.clone(), spend_pk.clone());
        assert_eq!(*wallet.scan_pk(), scan_pk);
        assert_eq!(*wallet.spend_pk(), spend_pk);
    }

    #[test]
    fn test_stealth_scan_entry() {
        let entry = StealthScanEntry {
            stealth_address: StealthAddress::from_bytes([0x01; 32]),
            ephemeral: EphemeralPoint::from_bytes([0x02; 32]),
            block_height: 100,
            tx_id: Hash::new([0x03; 32]),
        };
        assert_eq!(entry.block_height, 100);
    }
}
