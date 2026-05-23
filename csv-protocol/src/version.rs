//! Protocol versioning

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Protocol version components
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
}

impl Version {
    /// Create a new version
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Get the current protocol version
    pub const fn current() -> Self {
        Self { major: 1, minor: 0, patch: 0 }
    }
}
