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
pub mod signer;
pub mod wallet;
pub mod keystore;

// Re-export commonly used types
pub use error::{WalletError, Result};
pub use signer::{Signer, SignerRef, Signature};
pub use wallet::{Wallet, WalletManager, WalletConfig};
pub use keystore::{KeyStore, SecretHandle, KeyPurpose};
pub use csv_protocol::signature::SignatureScheme;
