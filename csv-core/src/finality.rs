//! Finality abstraction for CSV protocol
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::finality::{
    FinalityType, FinalityProof, FinalityError, FinalityVerifier,
    BitcoinFinalityVerifier, EthereumFinalityVerifier, SolanaFinalityVerifier,
    SuiFinalityVerifier, AptosFinalityVerifier, FinalityConfig,
};
