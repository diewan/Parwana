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
pub mod identifiers;
pub mod intent;
pub mod mandate;
pub mod verification;
