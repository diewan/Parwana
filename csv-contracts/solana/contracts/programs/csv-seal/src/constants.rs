//! Constants for CSV Seal program

/// Refund timeout in seconds (24 hours)
pub const REFUND_TIMEOUT: u32 = 86400;

/// Legacy 1-byte chain IDs (retained for the lock-event field / event compatibility).
/// The mint attestation digest uses the `keccak256("csv.chain.<name>")` bytes32 identity
/// (RFC-0012 §6 / §9.2), NOT these 1-byte ids.
pub const CHAIN_BITCOIN: u8 = 0;
pub const CHAIN_SUI: u8 = 1;
pub const CHAIN_APTOS: u8 = 2;
pub const CHAIN_ETHEREUM: u8 = 3;
pub const CHAIN_SOLANA: u8 = 4;

/// Seed prefixes for PDA derivation
pub const SEED_SANAD: &[u8] = b"sanad";
pub const SEED_LOCK_REGISTRY: &[u8] = b"lock_registry";
pub const SEED_REFUND: &[u8] = b"refund";
pub const SEED_VERIFIER_REGISTRY: &[u8] = b"verifier_registry";
pub const SEED_MINTED: &[u8] = b"minted";
pub const SEED_NULLIFIER: &[u8] = b"nullifier";
pub const SEED_LOCK_EVENT: &[u8] = b"lock_event";
pub const SEED_SETTLEMENT: &[u8] = b"settlement";

/// This chain's ABI identity name (RFC-0012 §6). `keccak256(CHAIN_NAME_SOLANA)` is the
/// bytes32 `destinationChainId` bound into the §9.2 mint attestation digest.
pub const CHAIN_NAME_SOLANA: &[u8] = b"csv.chain.solana";

/// Domain tag for the §9.2 mint attestation digest (23 bytes, ASCII, no NUL).
pub const MINT_ATTESTATION_DOMAIN: &[u8] = b"csv.mint.attestation.v1";

/// Domain tag for the §10 settlement-receipt digest (25 bytes, ASCII, no NUL).
pub const SETTLEMENT_RECEIPT_DOMAIN: &[u8] = b"csv.settlement.receipt.v1";

/// secp256k1 low-s malleability guard: half the curve order (n/2), big-endian.
/// A signature whose `s` exceeds this is rejected (EIP-2-style canonicalization),
/// so a single (r,s) cannot be re-encoded into a second valid signature.
pub const SECP256K1_HALF_ORDER_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];
