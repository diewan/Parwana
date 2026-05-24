//! Wallet capability separation and signing provider abstraction.
//!
//! The wallet architecture must isolate viewing keys from signing keys from
//! transfer authorization. This module provides the capability types and
//! provider traits needed for production-grade wallet implementations.

use serde::{Deserialize, Serialize};

/// Wallet capabilities that separate security domains.
///
/// These MUST be enforced at the wallet UI and service layer. No single
/// wallet component should have all capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCapabilities {
    /// Can sign transactions.
    pub can_sign: bool,
    /// Can verify proofs locally.
    pub can_verify: bool,
    /// Can authorize mint operations.
    pub can_mint: bool,
    /// Can export keys.
    pub can_export_keys: bool,
}

impl WalletCapabilities {
    /// Default capabilities (view-only).
    pub fn view_only() -> Self {
        Self {
            can_sign: false,
            can_verify: true,
            can_mint: false,
            can_export_keys: false,
        }
    }

    /// Full capabilities (sign, verify, mint, export).
    pub fn full() -> Self {
        Self {
            can_sign: true,
            can_verify: true,
            can_mint: true,
            can_export_keys: true,
        }
    }

    /// Signing-only capabilities (hardware wallet).
    pub fn signing_only() -> Self {
        Self {
            can_sign: true,
            can_verify: false,
            can_mint: false,
            can_export_keys: false,
        }
    }
}

/// A signing provider — never let runtime depend on local private key material.
///
/// Supported implementations:
/// - Local software signer (keyring)
/// - Hardware wallet (Ledger, Trezor)
/// - HSM (Hardware Security Module)
/// - Remote signer (web wallet, KMS)
#[async_trait::async_trait]
pub trait SigningProvider: Send + Sync {
    /// Sign the given message with the given key identifier.
    ///
    /// The implementation decides where the private key material lives.
    /// The runtime never receives private key bytes.
    async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, String>;
}
