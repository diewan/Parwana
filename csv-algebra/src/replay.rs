/// Pure replay detection types.
///
/// Replay identifiers and nonce types.
/// No serde, no IO, no infrastructure dependencies.
///
/// Unique identifier for replay detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayId(pub [u8; 32]);

/// Replay nonce for preventing replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayNonce(pub u64);

impl ReplayId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl ReplayNonce {
    pub fn new(nonce: u64) -> Self {
        Self(nonce)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn increment(&self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}
