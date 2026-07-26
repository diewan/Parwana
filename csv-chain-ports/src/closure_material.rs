//! Canonical framing for chain-native closure proof material.
//!
//! [`crate::ClosureProofVerifier`] receives `proof_material` as opaque bytes:
//! `csv-protocol` deliberately does not interpret them. Every chain adapter
//! nevertheless needs the same three guarantees from whatever framing it picks,
//! so the framing lives here once instead of four times:
//!
//! 1. **Deterministic.** The same logical proof encodes to the same bytes, so
//!    [`csv_protocol::ClosureProof::commitment`] is stable and a recipient can
//!    re-derive it.
//! 2. **Unambiguous.** Every variable-length field is length-prefixed, so no two
//!    distinct field sequences share an encoding. Without this, a verifier can
//!    be fed a re-split payload that reads as a different proof.
//! 3. **Bounded.** Decoding never trusts a length prefix it cannot satisfy from
//!    the remaining input, so a truncated or hostile payload fails closed rather
//!    than panicking or allocating on an attacker-chosen length.
//!
//! This is framing, not protocol semantics: it decides where fields begin and
//! end, never whether a proof is valid. It is also **not** a second canonical
//! serializer — protocol objects keep using `csv-codec`'s canonical CBOR. These
//! bytes are the adapter-private interior of a field the protocol treats as
//! opaque.
//!
//! Every adapter's material begins with a `u16` version so an old verifier
//! rejects a newer encoding instead of misreading it.

/// Failure while decoding chain-native proof material.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClosureMaterialError {
    /// Input ended in the middle of a field.
    #[error("closure material ended after {read} of {needed} required bytes")]
    UnexpectedEnd {
        /// Bytes still available when the read was attempted.
        read: usize,
        /// Bytes the read required.
        needed: usize,
    },
    /// A length prefix exceeded the bytes actually present.
    #[error("closure material declares a {declared}-byte field but only {available} bytes remain")]
    LengthOverrun {
        /// Length the encoding claimed.
        declared: usize,
        /// Bytes actually remaining.
        available: usize,
    },
    /// Bytes remained after the final field.
    #[error("closure material has {trailing} unconsumed trailing bytes")]
    TrailingBytes {
        /// Number of unconsumed bytes.
        trailing: usize,
    },
    /// The encoding version is not one this verifier implements.
    #[error("closure material version {found} is not supported (expected {expected})")]
    UnsupportedVersion {
        /// Version read from the payload.
        found: u16,
        /// Version this verifier implements.
        expected: u16,
    },
}

/// Append-only writer producing canonical closure material.
#[derive(Clone, Debug, Default)]
pub struct ClosureMaterialWriter {
    buffer: Vec<u8>,
}

impl ClosureMaterialWriter {
    /// Start a payload declaring its encoding version.
    pub fn new(version: u16) -> Self {
        let mut writer = Self {
            buffer: Vec::with_capacity(256),
        };
        writer.buffer.extend_from_slice(&version.to_le_bytes());
        writer
    }

    /// Append a fixed-width field. Not length-prefixed: the width is known to
    /// both sides from the field's position in the layout.
    pub fn put_fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// Append a `u64` in little-endian form.
    pub fn put_u64(&mut self, value: u64) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a length-prefixed variable-width field.
    pub fn put_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// Append a length-prefixed sequence of variable-width fields.
    pub fn put_byte_vectors<'a>(
        &mut self,
        items: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> &mut Self {
        self.buffer
            .extend_from_slice(&(items.len() as u32).to_le_bytes());
        for item in items {
            self.put_bytes(item);
        }
        self
    }

    /// Finish and return the canonical bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

/// Bounds-checked reader for canonical closure material.
///
/// Every read is checked against the remaining input, so malformed material
/// produces a typed error rather than a panic or an over-allocation.
#[derive(Clone, Debug)]
pub struct ClosureMaterialReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ClosureMaterialReader<'a> {
    /// Begin reading, requiring the payload to declare `expected_version`.
    pub fn new(input: &'a [u8], expected_version: u16) -> Result<Self, ClosureMaterialError> {
        let mut reader = Self { input, offset: 0 };
        let version = u16::from_le_bytes(reader.take_fixed::<2>()?);
        if version != expected_version {
            return Err(ClosureMaterialError::UnsupportedVersion {
                found: version,
                expected: expected_version,
            });
        }
        Ok(reader)
    }

    /// Read a fixed-width field.
    pub fn take_fixed<const N: usize>(&mut self) -> Result<[u8; N], ClosureMaterialError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Read a little-endian `u64`.
    pub fn take_u64(&mut self) -> Result<u64, ClosureMaterialError> {
        Ok(u64::from_le_bytes(self.take_fixed::<8>()?))
    }

    /// Read a length-prefixed variable-width field.
    pub fn take_bytes(&mut self) -> Result<&'a [u8], ClosureMaterialError> {
        let len = u32::from_le_bytes(self.take_fixed::<4>()?) as usize;
        let available = self.input.len() - self.offset;
        if len > available {
            return Err(ClosureMaterialError::LengthOverrun {
                declared: len,
                available,
            });
        }
        self.take(len)
    }

    /// Read a length-prefixed sequence of variable-width fields.
    ///
    /// The element count is validated against the bytes that remain before any
    /// allocation, so a hostile count cannot cause a large reservation.
    pub fn take_byte_vectors(&mut self) -> Result<Vec<&'a [u8]>, ClosureMaterialError> {
        let count = u32::from_le_bytes(self.take_fixed::<4>()?) as usize;
        let available = self.input.len() - self.offset;
        // Each element costs at least its own 4-byte length prefix.
        if count.saturating_mul(4) > available {
            return Err(ClosureMaterialError::LengthOverrun {
                declared: count.saturating_mul(4),
                available,
            });
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(self.take_bytes()?);
        }
        Ok(items)
    }

    /// Assert the payload is fully consumed.
    ///
    /// Trailing bytes are rejected so two different payloads cannot both verify
    /// as the same proof.
    pub fn finish(self) -> Result<(), ClosureMaterialError> {
        let trailing = self.input.len() - self.offset;
        if trailing != 0 {
            return Err(ClosureMaterialError::TrailingBytes { trailing });
        }
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ClosureMaterialError> {
        let available = self.input.len() - self.offset;
        if len > available {
            return Err(ClosureMaterialError::UnexpectedEnd {
                read: available,
                needed: len,
            });
        }
        let slice = &self.input[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION: u16 = 1;

    fn sample() -> Vec<u8> {
        let mut writer = ClosureMaterialWriter::new(VERSION);
        writer.put_fixed(&[1u8; 32]);
        writer.put_u64(42);
        writer.put_bytes(b"header");
        let nodes: Vec<&[u8]> = vec![b"a", b"bb"];
        writer.put_byte_vectors(nodes.into_iter());
        writer.finish()
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let encoded = sample();
        let mut reader = ClosureMaterialReader::new(&encoded, VERSION).unwrap();
        assert_eq!(reader.take_fixed::<32>().unwrap(), [1u8; 32]);
        assert_eq!(reader.take_u64().unwrap(), 42);
        assert_eq!(reader.take_bytes().unwrap(), b"header");
        assert_eq!(
            reader.take_byte_vectors().unwrap(),
            vec![&b"a"[..], &b"bb"[..]]
        );
        reader.finish().unwrap();
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn a_different_version_is_rejected_not_reinterpreted() {
        let encoded = sample();
        assert_eq!(
            ClosureMaterialReader::new(&encoded, VERSION + 1).unwrap_err(),
            ClosureMaterialError::UnsupportedVersion {
                found: VERSION,
                expected: VERSION + 1,
            }
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // "a" + "bb" must not encode the same as "ab" + "b".
        let mut first = ClosureMaterialWriter::new(VERSION);
        first.put_bytes(b"a").put_bytes(b"bb");
        let mut second = ClosureMaterialWriter::new(VERSION);
        second.put_bytes(b"ab").put_bytes(b"b");
        assert_ne!(first.finish(), second.finish());
    }

    #[test]
    fn truncated_material_fails_closed() {
        let encoded = sample();
        for cut in 2..encoded.len() {
            let truncated = &encoded[..cut];
            let result = (|| {
                let mut reader = ClosureMaterialReader::new(truncated, VERSION)?;
                reader.take_fixed::<32>()?;
                reader.take_u64()?;
                reader.take_bytes()?;
                reader.take_byte_vectors()?;
                reader.finish()
            })();
            assert!(result.is_err(), "truncation at {cut} must not verify");
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = sample();
        encoded.push(0xFF);
        let mut reader = ClosureMaterialReader::new(&encoded, VERSION).unwrap();
        reader.take_fixed::<32>().unwrap();
        reader.take_u64().unwrap();
        reader.take_bytes().unwrap();
        reader.take_byte_vectors().unwrap();
        assert_eq!(
            reader.finish().unwrap_err(),
            ClosureMaterialError::TrailingBytes { trailing: 1 }
        );
    }

    #[test]
    fn hostile_length_prefix_does_not_over_allocate() {
        // A 4 GiB length claim over a tiny payload must fail on the bound, not
        // on an allocation.
        let mut encoded = VERSION.to_le_bytes().to_vec();
        encoded.extend_from_slice(&u32::MAX.to_le_bytes());
        encoded.extend_from_slice(b"short");
        let mut reader = ClosureMaterialReader::new(&encoded, VERSION).unwrap();
        assert!(matches!(
            reader.take_bytes().unwrap_err(),
            ClosureMaterialError::LengthOverrun { .. }
        ));
    }

    #[test]
    fn hostile_element_count_does_not_over_allocate() {
        let mut encoded = VERSION.to_le_bytes().to_vec();
        encoded.extend_from_slice(&u32::MAX.to_le_bytes());
        encoded.extend_from_slice(b"short");
        let mut reader = ClosureMaterialReader::new(&encoded, VERSION).unwrap();
        assert!(matches!(
            reader.take_byte_vectors().unwrap_err(),
            ClosureMaterialError::LengthOverrun { .. }
        ));
    }
}
