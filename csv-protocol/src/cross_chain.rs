//! Cross-chain transfer types

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

/// Entry in the cross-chain seal registry recording a completed transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashEntry {
    /// The Hash's unique ID (preserved across chains)
    pub sanad_id: Hash,
    /// Source chain identifier
    pub source_chain: ChainId,
    /// Source chain's seal reference
    pub source_seal: SealPoint,
    /// Destination chain identifier
    pub destination_chain: ChainId,
    /// Destination chain's seal reference
    pub destination_seal: SealPoint,
    /// Lock transaction hash on source chain
    pub lock_tx_hash: Hash,
    /// Mint transaction hash on destination chain
    pub mint_tx_hash: Hash,
    /// Unix timestamp of the transfer
    pub timestamp: u64,
}
