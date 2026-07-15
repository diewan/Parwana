//! Pure accountability protocol semantics.
//!
//! This crate defines canonical accountability objects and validation rules.
//! It owns no storage, network, runtime, chain, UI, or application authority.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod assurance;
pub mod dispute;
pub mod evidence;
pub mod execution;
pub mod id;
pub mod intent;
pub mod mandate;
pub mod verification;

pub use id::{
    AssuranceProfileId, AttemptId, BundleId, EvidenceNodeId, GateProfileId, IntentId, MandateId,
    ObjectVersion, ProtocolVersion, ReceiptId, VerificationContextId, VersionError,
};
