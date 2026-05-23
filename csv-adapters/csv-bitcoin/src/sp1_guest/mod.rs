//! SP1 Guest Program for Bitcoin SPV Verification
//!
//! This module provides the SP1 zkVM guest program for proving Bitcoin
//! seal consumption. The guest program runs inside the SP1 zkVM and
//! produces a zero-knowledge proof that a specific UTXO was spent.
//!
//! # Architecture
//!
//! ```text
//! Host (csv-adapter-bitcoin):
//!   - Collects: transaction data, Merkle branch, block header
//!   - Calls: SP1 prover with guest program ELF
//!
//! Guest (SP1 zkVM - this module):
//!   - Input: Sp1BtcSpvInput { tx_data, merkle_branch, block_header, ... }
//!   - Computation:
//!     1. Compute txid from tx_data (double SHA256)
//!     2. Verify Merkle branch (connect txid to block header's merkle root)
//!     3. Verify block header hash matches claimed block_hash
//!   - Output: ZkPublicInputs { seal_ref, block_hash, commitment, ... }
//!
//! Verifier (anyone):
//!   - Receives: ZkSealProof
//!   - Verifies: SNARK proof without Bitcoin RPC
//! ```
//!
//! # Security Properties
//!
//! - Zero-knowledge: Verifier learns only that seal was consumed, not which UTXO
//! - Succinct: Proof size is constant (~1MB for SP1) regardless of block height
//! - Verifiable: Anyone can verify without trusting Bitcoin RPC

pub mod spv;

pub use spv::{Sp1BtcSpvInput, Sp1BtcSpvOutput, verify_bitcoin_spv};

/// SP1 guest program entry point for Bitcoin SPV verification.
///
/// This function is called by the SP1 zkVM when executing the guest program.
/// It takes the input, performs the verification, and returns the output.
///
/// # Arguments
/// * `input` - The SP1 input containing transaction data, Merkle branch, etc.
///
/// # Returns
/// * `Ok(output)` - Verification succeeded, returns public inputs
/// * `Err(error_code)` - Verification failed with specific error code
#[cfg(feature = "sp1-guest")]
pub fn sp1_main(input: &Sp1BtcSpvInput) -> Result<Sp1BtcSpvOutput, u32> {
    // This function is only compiled when building for SP1 guest
    // It uses SP1's zkvm::io::read/write for input/output

    match verify_bitcoin_spv(input) {
        true => Ok(Sp1BtcSpvOutput::from_input(input)),
        false => Err(1), // Error code 1: Verification failed
    }
}

/// Error codes for SP1 guest program
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Sp1ErrorCode {
    /// Success
    Success = 0,
    /// Invalid transaction data
    InvalidTxData = 1,
    /// Invalid Merkle branch
    InvalidMerkleBranch = 2,
    /// Invalid block header
    InvalidBlockHeader = 3,
    /// Verification failed
    VerificationFailed = 4,
    /// Unknown error
    Unknown = 255,
}

impl From<u32> for Sp1ErrorCode {
    fn from(code: u32) -> Self {
        match code {
            0 => Sp1ErrorCode::Success,
            1 => Sp1ErrorCode::InvalidTxData,
            2 => Sp1ErrorCode::InvalidMerkleBranch,
            3 => Sp1ErrorCode::InvalidBlockHeader,
            4 => Sp1ErrorCode::VerificationFailed,
            _ => Sp1ErrorCode::Unknown,
        }
    }
}
