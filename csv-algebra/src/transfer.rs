/// Pure transfer types.
/// 
/// These are the algebraic types for cross-chain transfers.
/// No serde, no IO, no infrastructure dependencies.

/// Unique identifier for a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId(pub [u8; 32]);

/// Unique identifier for a seal (commitment) on the source chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealId(pub [u8; 32]);

/// Chain identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainId(pub u32);

/// The point in a transfer where a seal is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealPoint {
    pub seal_id: SealId,
    pub block_height: u64,
    pub block_hash: [u8; 32],
}

impl TransferId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SealId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ChainId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}
