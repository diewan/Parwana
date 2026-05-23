# Golden Test Corpus

This directory contains canonical CBOR fixtures for testing the CSV protocol.

## Files

- `valid_proof_bundle_v1.cbor` — A valid proof bundle with all required fields
- `valid_sanad_envelope_v1.cbor` — A valid sanad envelope structure
- `replay_attempt_v1.cbor` — A proof bundle that has already been replay-checked
- `malformed_proof_missing_finality.cbor` — A proof bundle with empty finality data
- `malformed_proof_wrong_domain.cbor` — A proof bundle with an invalid domain hash

## Usage

These fixtures are loaded by `csv-core/tests/golden/mod.rs` using `include_bytes!()`
and validated against the canonical deserialization and proof pipeline.

## Generation

Regenerate with: `cargo run --bin generate_golden_fixtures`

## Signing

These fixtures are signed with a release key. Signature verification is performed
in CI to ensure fixture integrity.
