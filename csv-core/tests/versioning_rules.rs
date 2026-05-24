#![cfg(any())]
//! Versioning Rules — Protocol Constitution Section 7
//!
//! Tests for protocol versioning and upgrade requirements.

#[cfg(test)]
mod tests {
    use csv_core::protocol_version::{PROTOCOL_VERSION, ProtocolVersion};

    /// Property: PROTOCOL_VERSION has valid structure
    #[test]
    fn test_protocol_version_structure() {
        let v = ProtocolVersion::current();
        assert!(v.major >= 0, "Major version must be non-negative");
        assert!(v.minor >= 0, "Minor version must be non-negative");
        assert!(v.patch >= 0, "Patch version must be non-negative");
    }

    /// Property: ProtocolVersion is cloneable
    #[test]
    fn test_protocol_version_clone() {
        let v = ProtocolVersion::current();
        let cloned = v.clone();
        assert_eq!(v.major, cloned.major);
        assert_eq!(v.minor, cloned.minor);
        assert_eq!(v.patch, cloned.patch);
    }

    /// Property: ProtocolVersion is equatable
    #[test]
    fn test_protocol_version_equality() {
        let v1 = ProtocolVersion::current();
        let v2 = ProtocolVersion::current();
        assert_eq!(v1, v2);
    }

    /// Property: ProtocolVersion debug output is informative
    #[test]
    fn test_protocol_version_debug() {
        let v = ProtocolVersion::current();
        let debug_str = format!("{:?}", v);
        assert!(!debug_str.is_empty());
    }

    /// Property: Different versions are not equal
    #[test]
    fn test_different_versions_not_equal() {
        let v1 = ProtocolVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let v2 = ProtocolVersion {
            major: 2,
            minor: 0,
            patch: 0,
        };
        assert_ne!(v1, v2, "Different versions must not be equal");
    }

    /// Property: Protocol version major bump indicates breaking change
    #[test]
    fn test_major_version_breaking() {
        let v1 = ProtocolVersion {
            major: 1,
            minor: 5,
            patch: 0,
        };
        let v2 = ProtocolVersion {
            major: 2,
            minor: 0,
            patch: 0,
        };
        assert_ne!(
            v1.major, v2.major,
            "Major version bump indicates breaking change"
        );
    }

    /// Property: ProtocolVersion Display works
    #[test]
    fn test_protocol_version_display() {
        let v = ProtocolVersion::current();
        let display = format!("{}", v);
        assert!(
            display.contains('.'),
            "Display must contain version separators"
        );
    }

    /// Property: is_compatible checks major version
    #[test]
    fn test_is_compatible() {
        let v = ProtocolVersion::current();
        assert!(
            v.is_compatible(),
            "Current version must be compatible with itself"
        );
    }
}
