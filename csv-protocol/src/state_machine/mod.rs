//! State machine
//!
//! This module preserves the state-machine import path while delegating to the
//! canonical transition algebra.

pub use super::transition::{State, Transition, is_legal_transition};
