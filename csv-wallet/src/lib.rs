//! CSV Wallet - Unified wallet abstraction with Signer trait
//!
//! This crate provides a unified wallet interface that consolidates wallet logic
//! from csv-keys, csv-coordinator, csv-sdk, and chain adapters into a single
//! canonical wallet abstraction.
//!
//! # Architecture
//!
//! - **Signer trait**: Unified signing interface for all chains
//! - **WalletManager**: Centralized wallet state management
//! - **KeyStore**: Secure key storage with zeroization
//! - **Chain-specific adapters**: Per-chain signing implementations
//!
//! # Security
//!
//! - All secret material uses secrecy types with zeroize-on-drop
//! - No raw private key strings in public APIs
//! - Typed secret handles throughout

#![warn(missing_docs)]
#![allow(unused_variables)]
#![allow(unused_imports)]

pub mod error;
pub mod format;
pub mod keystore;
pub mod seal_custody;
pub mod signer;
pub mod wallet;
pub mod wallet_traits;

// Re-export commonly used types
pub use error::{Result, WalletError};
pub use format::{
    DerivationProfile, FormatError, KdfId, KdfParams, KeySource, KeySourceKind, KnownAccount,
    WalletPayload,
};
pub use keystore::{KeyPurpose, KeyStore};
pub use seal_custody::{SealCustody, SealCustodyRecord};
pub use signer::{Signature, Signer, SignerRef};
pub use wallet::address; // Static address derivation functions
pub use wallet::{Wallet, WalletConfig, WalletManager};
// Re-export canonical secret types from csv-protocol
pub use csv_protocol::secret::{SecretHandle, SharedSecretHandle};
pub use csv_protocol::signature::SignatureScheme;
pub use wallet_traits::{WalletFactory, WalletOperations};
