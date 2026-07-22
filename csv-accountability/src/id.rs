//! Stable accountability identifiers and explicit versions.

use core::fmt;

/// Number of bytes in every content-derived accountability identifier.
pub const ID_BYTES: usize = 32;

/// Experimental Accountability Profile protocol version.
pub const ACCOUNTABILITY_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1);

/// First object-schema version for the Accountability Profile.
pub const ACCOUNTABILITY_OBJECT_VERSION: ObjectVersion = ObjectVersion(1);

/// A protocol compatibility version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Creates a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the compatibility-breaking major component.
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the additive minor component.
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Returns whether `other` is readable by this implementation.
    pub const fn supports(self, other: Self) -> bool {
        self.major == other.major && other.minor <= self.minor
    }
}

/// A nonzero schema version for one accountability object type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectVersion(u16);

impl ObjectVersion {
    /// Validates an object version received from an external boundary.
    pub const fn try_new(version: u16) -> Result<Self, VersionError> {
        if version == 0 {
            Err(VersionError::ReservedZero)
        } else {
            Ok(Self(version))
        }
    }

    /// Returns the numeric schema version.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A version-validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// Version zero is reserved and never identifies a schema.
    ReservedZero,
}

macro_rules! content_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Creates an identifier from a domain-separated content digest.
            pub const fn from_digest(digest: [u8; ID_BYTES]) -> Self {
                Self(digest)
            }

            /// Borrows the identifier bytes.
            pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }

            /// Returns the identifier bytes.
            pub const fn into_bytes(self) -> [u8; ID_BYTES] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "("))?;
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str(")")
            }
        }

        impl From<[u8; ID_BYTES]> for $name {
            fn from(digest: [u8; ID_BYTES]) -> Self {
                Self::from_digest(digest)
            }
        }
    };
}

content_id!(IntentId, "Content-derived identifier of an action intent.");
content_id!(
    MandateId,
    "Content-derived identifier of an action mandate."
);
content_id!(
    AttemptId,
    "Content-derived identifier of an execution attempt."
);
content_id!(
    ReceiptId,
    "Content-derived identifier of an execution receipt."
);
content_id!(
    EvidenceNodeId,
    "Content-derived identifier of an evidence node."
);
content_id!(BundleId, "Content-derived identifier of a dispute bundle.");
content_id!(
    VerificationContextId,
    "Content-derived identifier of a verification context."
);
content_id!(
    AssuranceProfileId,
    "Content-derived identifier of an assurance profile."
);
content_id!(
    GateProfileId,
    "Content-derived identifier of a gate profile."
);
content_id!(
    AuthorityReconstructionId,
    "Content-derived identifier of a historical authority reconstruction."
);

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn identifiers_are_type_distinct_and_byte_stable() {
        let digest = [0xa5; ID_BYTES];
        let intent = IntentId::from_digest(digest);
        let mandate = MandateId::from_digest(digest);
        assert_eq!(intent.into_bytes(), digest);
        assert_eq!(mandate.into_bytes(), digest);
        assert!(format!("{intent:?}").starts_with("IntentId(a5a5"));
        assert!(format!("{mandate:?}").starts_with("MandateId(a5a5"));
    }

    #[test]
    fn version_zero_fails_closed() {
        assert_eq!(ObjectVersion::try_new(0), Err(VersionError::ReservedZero));
        assert_eq!(ObjectVersion::try_new(1), Ok(ACCOUNTABILITY_OBJECT_VERSION));
    }

    #[test]
    fn protocol_compatibility_rejects_newer_or_different_major() {
        assert!(ACCOUNTABILITY_PROTOCOL_VERSION.supports(ProtocolVersion::new(0, 1)));
        assert!(!ACCOUNTABILITY_PROTOCOL_VERSION.supports(ProtocolVersion::new(0, 2)));
        assert!(!ACCOUNTABILITY_PROTOCOL_VERSION.supports(ProtocolVersion::new(1, 0)));
    }
}
