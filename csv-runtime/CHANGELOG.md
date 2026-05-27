# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **PostgreSQL execution journal**: `PostgresExecutionJournal` in `postgres_store.rs` with async operations via `spawn_blocking`
- **Health monitoring**: Integrated `RuntimeHealth` from csv-observability, replaced `HealthMonitor`
- **Health status**: Added `HealthStatus` enum as backward-compatible alias mapping to `RuntimeHealth`
- **Module declarations**: Added `postgres_store` and `replay_record` module exports
- **Lease configuration**: Added `LeaseConfig` with configurable defaults

### Changed
- **Lease durations**: Aligned `LeaseConfig` defaults with lease module constants (30s default, 300s max)
- **Dependency updates**: Now depends on csv-protocol, csv-coordinator, csv-admission, csv-observability (no csv-core)
- **Runtime mode**: Added `HealthStatus` enum with `From<RuntimeHealth>` impl

### Fixed
- **Recovery lease authority**: Aligned lease configuration with production and development configs
