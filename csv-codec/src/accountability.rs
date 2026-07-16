//! Canonical accountability byte boundary.
//!
//! Accountability semantic crates produce their own specified canonical bytes.
//! This module only preserves and bounds those bytes; it never re-serializes an
//! accountability object.

use crate::CodecError;

/// Maximum supported canonical accountability artifact size.
pub const MAX_ACCOUNTABILITY_CANONICAL_BYTES: usize = 64 * 1024 * 1024;

/// Validates an exact canonical accountability byte sequence for transport.
pub fn preserve_accountability_bytes(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    if bytes.is_empty() || bytes.len() > MAX_ACCOUNTABILITY_CANONICAL_BYTES {
        return Err(CodecError::IntegrityError(
            "accountability canonical bytes are empty or exceed the transport bound".into(),
        ));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_preserved_exactly_and_empty_input_fails_closed() {
        let bytes = [0, 1, 2, 255];
        assert_eq!(preserve_accountability_bytes(&bytes).unwrap(), bytes);
        assert!(preserve_accountability_bytes(&[]).is_err());
    }
}
