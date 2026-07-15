# csv-testkit

Test fixtures and adversarial testing utilities for Parwana.

## Overview

`csv-testkit` provides testing utilities, fixtures, and adversarial testing tools for the Parwana to ensure robustness and security.

## Key Features

- **Test fixtures**: Pre-built test data and scenarios
- **Adversarial testing**: Tools for testing against adversarial inputs
- **Property-based testing**: Proptest integration
- **Golden fixtures**: Canonical test data for regression testing
- **Mock implementations**: Mock chain adapters and storage backends

## Modules

- **fixtures**: Test fixtures and golden data
- **adversarial**: Adversarial testing utilities
- **mocks**: Mock implementations for testing

## Architecture Role

`csv-testkit` provides:

- Shared testing utilities across all crates
- Adversarial testing for security validation
- Regression testing through golden fixtures
- Mock implementations for unit testing

## Dependencies

- `csv-protocol`: Protocol types
- `csv-hash`: Hash types
- `csv-codec`: Serialization
- `csv-proof`: Proof types
- `csv-verifier**: Verification
- `csv-storage`: Storage types
- `csv-runtime`: Runtime types
- `proptest`: Property-based testing
- `serde`: Serialization
- `serde_json`: JSON serialization

## Usage Example

```rust
use csv_testkit::fixtures::create_test_proof_bundle;
use csv_testkit::adversarial::truncate_hex;

let proof = create_test_proof_bundle();
let truncated = truncate_hex(&proof, 10);
```

## Adversarial Testing

The testkit includes:

- **Hex truncation**: Test handling of truncated data
- **Stale height injection**: Test handling of stale blockchain data
- **Selective censorship**: Test handling of censored responses
- **Malformed proofs**: Test handling of invalid proof structures

## Design Principles

- **Reusable**: Shared across all protocol crates
- **Adversarial**: Tests against malicious inputs
- **Deterministic**: Golden fixtures for regression testing
- **Comprehensive**: Covers edge cases and failure modes

## License

MIT OR Apache-2.0
