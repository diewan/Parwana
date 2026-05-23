//! Constants for CSV Seal program

/// Refund timeout in seconds (24 hours)
pub const REFUND_TIMEOUT: u32 = 86400;

/// Chain IDs for cross-chain transfers
/// These match the chain IDs used in other CSV contracts
pub const CHAIN_BITCOIN: u8 = 0;
pub const CHAIN_SUI: u8 = 1;
pub const CHAIN_APTOS: u8 = 2;
pub const CHAIN_ETHEREUM: u8 = 3;
pub const CHAIN_SOLANA: u8 = 4;

/// Seed prefixes for PDA derivation
pub const SEED_SANAD: &[u8] = b"sanad";
pub const SEED_LOCK_REGISTRY: &[u8] = b"lock_registry";
pub const SEED_REFUND: &[u8] = b"refund";

/// Domain separator for CSV commitments on Solana
/// This matches the separator used in the Rust adapter
pub const SOLANA_DOMAIN_SEPARATOR: [u8; 32] = [
    0x53, 0x4f, 0x4c, 0x61, 0x6e, 0x61, 0x43, 0x53, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
