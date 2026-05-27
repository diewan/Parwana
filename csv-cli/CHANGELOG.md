# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Chain management**: `chain list`, `chain status`, `chain set-rpc`, `chain set-contract`, `chain set-network`
- **Wallet operations**: `wallet init`, `wallet import`, `wallet export`, `wallet generate`, `wallet balance`, `wallet list`, `wallet private-key`
- **Sanad operations**: `sanad create`, `sanad show`, `sanad list`, `sanad transfer`, `sanad consume`
- **Proof operations**: `proof generate`, `proof verify`, `proof verify-cross-chain`
- **Cross-chain transfers**: `cross-chain transfer`, `cross-chain status`, `cross-chain list`, `cross-chain retry`
- **Seal operations**: `seal create`, `seal consume`, `seal verify`, `seal list`
- **Content management**: `content create`, `content prove`, `content verify`, `content encrypt`, `content disclose`, `content attach`, `content participants`, `content claims`
- **Trust management**: `trust status`, `trust export`, `trust import`, `trust verify`, `trust rotate`
- **Runtime monitoring**: `runtime status`, `runtime health`, `runtime admission`, `runtime events`
- **Validation & inspection**: `validate consignment`, `validate proof`, `validate seal`, `validate offline`, `inspect replay`, `inspect merkle`
- **Schema tooling**: `schema validate`, `schema compile`, `schema diff`
- **End-to-end testing**: `test run`, `test run-all`, `test scenario`, `test results`
- **Global flags**: `--verbose`, `--canonical`, `--proof-tree`, `--config`
- **Celestia support**: Added to all CLI commands and chain configuration

### Changed
- Migrated from csv-core to csv-protocol/csv-algebra/csv-wire
- Updated to use csv-runtime for all protocol authority delegation
- Integrated csv-observability for runtime health monitoring
- Integrated csv-admission for admission control
- Integrated csv-content for content tree operations

### Fixed
- (nothing yet)
