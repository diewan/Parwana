//! Sanad identifier domain
//!
//! Domain tag: `csv.sanad.id.v1`
//!
//! Used for: SanadId derivation via `H(domain || descriptor_hash || commitment || salt)`
//!
//! This domain ensures that Sanad IDs are cryptographically separated from
//! all other protocol hashes (commitments, nullifiers, proof leaves, etc.).

use crate::Domain;

/// Domain for Sanad ID derivation.
///
/// All Sanad IDs are computed as:
/// ```text
/// SanadId = tagged_hash("urn:lnp-bp:csv:csv.sanad.id.v1", descriptor_hash || commitment || salt)
/// ```
///
/// This ensures:
/// - Salt affects the ID (prevents collision when same commitment used with different salts)
/// - Descriptor hash binds content metadata to the ID
/// - Domain separation prevents cross-protocol replay
pub struct SanadIdDomain;

impl Domain for SanadIdDomain {
    const DOMAIN: &'static [u8] = b"csv.sanad.id.v1";
}
